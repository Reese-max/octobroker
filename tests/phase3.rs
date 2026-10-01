//! Issue #18 Phase-3 e2e tests — run against the real `octobroker` binary
//! (CARGO_BIN_EXE) with in-process mock upstream MCP + STS endpoints.
//!
//! Covered contracts:
//! - SigV4 `sts:GetCallerIdentity` proof exchange (`POST /mcp/iam-auth`):
//!   strict Vault-style validation (method, allowlisted STS endpoint, signed
//!   `x-octobroker-server-id`, ≤60s freshness, exact body) then a short-lived
//!   `X-Octobroker-Iam-Token` bearer authenticates `/mcp`.
//! - Per-agent rate quota → 429 + `Retry-After`.
//! - Upstream circuit breaker → fail-fast 503 + `Retry-After` without
//!   touching upstream; upstream `Retry-After` is propagated downstream.
//! - `GET /metrics` Prometheus exposition (per-agent requests/denials,
//!   upstream latency, breaker state, IAM exchanges).
//! - Upstream contract probes: POST timeout → clean JSON-RPC 502; mid-stream
//!   disconnect → truncated stream, no hang; session idle expiry → 404 so
//!   clients re-initialize (the documented single-replica failure mode).

use std::collections::HashMap;
use std::io::Write;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, Method},
    response::Response,
    routing::any,
    Router,
};
use futures_util::StreamExt as _;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// spawn helpers
// ---------------------------------------------------------------------------

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct ServerProc {
    port: u16,
    child: Child,
    _dir: String,
}

impl Drop for ServerProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn the real octobroker binary with the given config TOML + env vars and
/// wait for /healthz.
async fn spawn_octobroker(config: &str, envs: &[(&str, &str)]) -> ServerProc {
    let dir = std::env::temp_dir()
        .join(format!("obk-phase3-{}-{}", std::process::id(), free_port()))
        .to_str()
        .unwrap()
        .to_string();
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = format!("{}/config.toml", dir);
    std::fs::File::create(&cfg_path)
        .unwrap()
        .write_all(config.as_bytes())
        .unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_octobroker"));
    cmd.env("OCTOBROKER_CONFIG", &cfg_path)
        .env("RUST_LOG", "error")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let child = cmd.spawn().unwrap();
    let port = config_port(config);
    let proc = ServerProc {
        port,
        child,
        _dir: dir,
    };

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match reqwest::get(format!("http://127.0.0.1:{}/healthz", proc.port)).await {
            Ok(r) if r.status().is_success() => return proc,
            _ if Instant::now() < deadline => tokio::time::sleep(Duration::from_millis(50)).await,
            _ => panic!("octobroker did not become healthy on port {}", proc.port),
        }
    }
}

fn config_port(config: &str) -> u16 {
    for line in config.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("port") {
            if let Some(v) = rest.trim_start_matches(['=', ' ']).split([' ', '#']).next() {
                if let Ok(p) = v.parse::<u16>() {
                    return p;
                }
            }
        }
    }
    panic!("config missing port");
}

async fn spawn_mock(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{}", addr)
}

// ---------------------------------------------------------------------------
// mock upstream MCP server: behavior driven by body markers
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct UpLog {
    requests: Arc<Mutex<Vec<String>>>,
}

async fn mock_upstream(
    State(log): State<UpLog>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let body_str = String::from_utf8_lossy(&body).to_string();
    log.requests.lock().unwrap().push(format!(
        "{} auth={} sid={} body={}",
        method,
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        headers
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        body_str
    ));
    if body_str.contains("m_marker_500") {
        return Response::builder()
            .status(500)
            .body(Body::from("upstream broke"))
            .unwrap();
    }
    if body_str.contains("m_marker_429") {
        return Response::builder()
            .status(429)
            .header("retry-after", "7")
            .body(Body::from("slow down"))
            .unwrap();
    }
    if body_str.contains("m_marker_slow") {
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    if body_str.contains("m_marker_disconnect") {
        // Emit a partial SSE frame, then error mid-body AFTER headers and the
        // first chunk have flushed — a real mid-stream disconnect.
        let stream = futures_util::stream::once(async {
            Ok::<Bytes, std::io::Error>(Bytes::from(
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"partial\":",
            ))
        })
        .chain(futures_util::stream::once(async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Err::<Bytes, std::io::Error>(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "gone",
            ))
        }));
        return Response::builder()
            .status(200)
            .header("content-type", "text/event-stream")
            .body(Body::from_stream(stream))
            .unwrap();
    }
    if body_str.contains("\"initialize\"") {
        return Response::builder()
            .status(200)
            .header("content-type", "text/event-stream")
            .header("mcp-session-id", "e2e-sess-1")
            .body(Body::from(
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{}}\n\n",
            ))
            .unwrap();
    }
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#))
        .unwrap()
}

async fn spawn_upstream() -> (String, UpLog) {
    let log = UpLog {
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let app = Router::new()
        .route("/", any(mock_upstream))
        .with_state(log.clone());
    (spawn_mock(app).await, log)
}

// ---------------------------------------------------------------------------
// mock STS: returns GetCallerIdentity XML, records what it received
// ---------------------------------------------------------------------------

type CapturedRequest = (HashMap<String, String>, String);

#[derive(Clone)]
struct StsLog {
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    arn: String,
}

async fn mock_sts(State(log): State<StsLog>, headers: HeaderMap, body: Bytes) -> Response {
    let mut captured = HashMap::new();
    for (k, v) in headers.iter() {
        if let Ok(s) = v.to_str() {
            captured.insert(k.as_str().to_string(), s.to_string());
        }
    }
    let body_s = String::from_utf8_lossy(&body).to_string();
    // Act like real STS: recompute the SigV4 over the FORWARDED request and
    // reject a signature that doesn't match — this proves octobroker relays
    // the proof faithfully, not merely its shape.
    if !verify_forwarded_sigv4(&captured, &body_s) {
        log.requests.lock().unwrap().push((captured, body_s));
        return Response::builder()
            .status(403)
            .header("content-type", "text/xml")
            .body(Body::from(
                "<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>",
            ))
            .unwrap();
    }
    captured.remove("host");
    log.requests.lock().unwrap().push((captured, body_s));
    let xml = format!(
        "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\
         <GetCallerIdentityResult><Arn>{}</Arn><UserId>AROA:session</UserId>\
         <Account>123456789012</Account></GetCallerIdentityResult>\
         <ResponseMetadata><RequestId>req</RequestId></ResponseMetadata>\
         </GetCallerIdentityResponse>",
        log.arn
    );
    Response::builder()
        .status(200)
        .header("content-type", "text/xml")
        .body(Body::from(xml))
        .unwrap()
}

/// Recompute AWS SigV4 over the request octobroker actually forwarded
/// (headers as received on the wire + body), using the test secret key.
fn verify_forwarded_sigv4(headers: &HashMap<String, String>, body: &str) -> bool {
    let Some(authz) = headers.get("authorization") else {
        return false;
    };
    let Some(cred_start) = authz.find("Credential=") else {
        return false;
    };
    let cred = &authz[cred_start + 11..];
    let cred = cred.split(',').next().unwrap_or("");
    let scope: Vec<&str> = cred.split('/').collect();
    if scope.len() != 5 {
        return false;
    }
    let (date, region) = (scope[1], scope[2]);
    // StringToSign carries the credential scope WITHOUT the access key.
    let cred_scope = scope[1..].join("/");
    let Some(sh_start) = authz.find("SignedHeaders=") else {
        return false;
    };
    let signed_headers = authz[sh_start + 14..]
        .split(',')
        .next()
        .unwrap_or("")
        .to_string();
    let Some(sig_start) = authz.find("Signature=") else {
        return false;
    };
    let expected_sig = &authz[sig_start + 10..];

    // Canonical request over ONLY the signed headers, values as received.
    let mut canonical_headers = String::new();
    for name in signed_headers.split(';') {
        let Some(v) = headers.get(name) else {
            return false;
        };
        canonical_headers.push_str(&format!("{}:{}\n", name, v.trim()));
    }
    let payload_hash = hex_lower(&Sha256::digest(body.as_bytes()));
    let canonical = format!(
        "POST\n/\n\n{}\n{}\n{}",
        canonical_headers, signed_headers, payload_hash
    );
    let sts = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        headers.get("x-amz-date").map(String::as_str).unwrap_or(""),
        cred_scope,
        hex_lower(&Sha256::digest(canonical.as_bytes()))
    );
    let k_date = hmac_sha256(format!("AWS4{}", TEST_SK).as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"sts");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let actual = hex_lower(&hmac_sha256(&k_signing, sts.as_bytes()));
    actual == *expected_sig
}

async fn spawn_sts(arn: &str) -> (String, StsLog) {
    let log = StsLog {
        requests: Arc::new(Mutex::new(Vec::new())),
        arn: arn.to_string(),
    };
    let app = Router::new()
        .route("/", any(mock_sts))
        .with_state(log.clone());
    (spawn_mock(app).await, log)
}

// ---------------------------------------------------------------------------
// SigV4 signer (test-side): signs a fixed GetCallerIdentity POST
// ---------------------------------------------------------------------------

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let h = Sha256::digest(key);
        k[..32].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let ih = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(ih);
    outer.finalize().to_vec()
}

fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn amz_date(when: std::time::SystemTime) -> (String, String) {
    let ts = when
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let dt = time::OffsetDateTime::from_unix_timestamp(ts).unwrap();
    let fmt =
        time::format_description::parse("[year][month][day]T[hour][minute][second]Z").unwrap();
    let date_fmt = time::format_description::parse("[year][month][day]").unwrap();
    (dt.format(&fmt).unwrap(), dt.format(&date_fmt).unwrap())
}

const TEST_AK: &str = "TESTACCESSKEY0000001";
const TEST_SK: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const STS_BODY: &str = "Action=GetCallerIdentity&Version=2011-06-15";

/// Sign GetCallerIdentity. If `sign_server_id` is false the header value is
/// still sent but kept OUT of SignedHeaders (must be rejected).
fn sign_proof(
    authority: &str,
    region: &str,
    server_id: &str,
    when: std::time::SystemTime,
    sign_server_id: bool,
) -> HashMap<String, String> {
    let (amz, date) = amz_date(when);
    let mut headers: Vec<(String, String)> = vec![
        (
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        ),
        ("host".into(), authority.to_string()),
        ("x-amz-date".into(), amz.clone()),
    ];
    if sign_server_id {
        headers.push(("x-octobroker-server-id".into(), server_id.to_string()));
    }
    headers.sort();
    let canonical_headers: String = headers
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v))
        .collect();
    let signed_headers: String = headers
        .iter()
        .map(|(k, _)| k.clone())
        .collect::<Vec<_>>()
        .join(";");
    let payload_hash = hex_lower(&Sha256::digest(STS_BODY.as_bytes()));
    let canonical = format!(
        "POST\n/\n\n{}\n{}\n{}",
        canonical_headers, signed_headers, payload_hash
    );
    let scope = format!("{}/{}/sts/aws4_request", date, region);
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz,
        scope,
        hex_lower(&Sha256::digest(canonical.as_bytes()))
    );
    let k_date = hmac_sha256(format!("AWS4{}", TEST_SK).as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"sts");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex_lower(&hmac_sha256(&k_signing, to_sign.as_bytes()));
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        TEST_AK, scope, signed_headers, signature
    );

    let mut out = HashMap::new();
    out.insert("host".into(), authority.to_string());
    out.insert("x-amz-date".into(), amz);
    out.insert(
        "content-type".into(),
        "application/x-www-form-urlencoded".into(),
    );
    out.insert("x-octobroker-server-id".into(), server_id.to_string());
    out.insert("authorization".into(), authorization);
    out
}

fn iam_request(
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: &str,
) -> serde_json::Value {
    serde_json::json!({
        "iam_request_method": method,
        "iam_request_url": url,
        "iam_request_headers": headers,
        "iam_request_body": body,
    })
}

fn iam_config(port: u16, upstream: &str, sts: &str, extra_agents: &str, extra_mcp: &str) -> String {
    format!(
        r#"
port = {port}
[[identities]]
id = "pool1"
token = "ghp_pool_fake"
allowed_owners = ["openabdev"]

[mcp]
enabled = true
upstream = "{upstream}"
{extra_mcp}

[mcp.iam]
enabled = true
server_id = "test-server-1"
token_ttl_secs = 300
sts_endpoints = ["{sts}"]

[[mcp.agents]]
id = "arn-agent"
iam_arns = ["arn:aws:sts::123456789012:assumed-role/agent-role/*"]
tools = ["issue_read"]

[[mcp.agents]]
id = "key-agent"
key = "secret-key-1"
tools = ["issue_read"]
{extra_agents}
"#,
        port = port,
        upstream = upstream,
        sts = sts,
        extra_mcp = extra_mcp,
        extra_agents = extra_agents
    )
}

fn authority(url: &str) -> &str {
    url.split("://").nth(1).unwrap().trim_end_matches('/')
}

// ---------------------------------------------------------------------------
// IAM proof exchange
// ---------------------------------------------------------------------------

async fn iam_exchange(port: u16, payload: serde_json::Value) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/mcp/iam-auth", port))
        .json(&payload)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn iam_exchange_happy_path_and_mcp_access() {
    let (up, _log) = spawn_upstream().await;
    let (sts, sts_log) =
        spawn_sts("arn:aws:sts::123456789012:assumed-role/agent-role/task-9").await;
    let port = free_port();
    let srv = spawn_octobroker(&iam_config(port, &up, &sts, "", ""), &[]).await;

    let headers = sign_proof(
        authority(&sts),
        "us-east-1",
        "test-server-1",
        std::time::SystemTime::now(),
        true,
    );
    let resp = iam_exchange(
        srv.port,
        iam_request("POST", &format!("{}/", sts), &headers, STS_BODY),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    let token = v["token"].as_str().expect("token returned");
    assert_eq!(v["agent"], "arn-agent");
    assert!(v["expires_at"].as_u64().unwrap() > 0);

    // STS saw the signed request verbatim (signed headers forwarded).
    {
        let log = sts_log.requests.lock().unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].1, STS_BODY);
        assert!(log[0].0["authorization"].starts_with("AWS4-HMAC-SHA256"));
        assert_eq!(log[0].0["x-octobroker-server-id"], "test-server-1");
    }

    // The exchanged token authenticates /mcp as the mapped agent.
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/mcp", srv.port))
        .header("content-type", "application/json")
        .header("x-octobroker-iam-token", token)
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Deny rules still apply: the agent's allowlist only has issue_read.
    let resp = client
        .post(format!("http://127.0.0.1:{}/mcp", srv.port))
        .header("content-type", "application/json")
        .header("x-octobroker-iam-token", token)
        .body(r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"create_issue","arguments":{"owner":"openabdev","repo":"octobroker"}}}"#)
        .send()
        .await
        .unwrap();
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["result"]["isError"], true);
}

#[tokio::test]
async fn iam_rejects_wrong_server_id() {
    let (sts, sts_log) =
        spawn_sts("arn:aws:sts::123456789012:assumed-role/agent-role/task-9").await;
    let (up, _) = spawn_upstream().await;
    let port = free_port();
    let srv = spawn_octobroker(&iam_config(port, &up, &sts, "", ""), &[]).await;

    let headers = sign_proof(
        authority(&sts),
        "us-east-1",
        "other-env",
        std::time::SystemTime::now(),
        true,
    );
    let resp = iam_exchange(
        srv.port,
        iam_request("POST", &format!("{}/", sts), &headers, STS_BODY),
    )
    .await;
    assert_eq!(resp.status(), 401);
    assert!(
        sts_log.requests.lock().unwrap().is_empty(),
        "STS must not be contacted"
    );
}

#[tokio::test]
async fn iam_rejects_unsigned_server_id() {
    let (sts, sts_log) =
        spawn_sts("arn:aws:sts::123456789012:assumed-role/agent-role/task-9").await;
    let (up, _) = spawn_upstream().await;
    let port = free_port();
    let srv = spawn_octobroker(&iam_config(port, &up, &sts, "", ""), &[]).await;

    // header value correct but not covered by the signature → replay-able → reject
    let headers = sign_proof(
        authority(&sts),
        "us-east-1",
        "test-server-1",
        std::time::SystemTime::now(),
        false,
    );
    let resp = iam_exchange(
        srv.port,
        iam_request("POST", &format!("{}/", sts), &headers, STS_BODY),
    )
    .await;
    assert_eq!(resp.status(), 401);
    assert!(sts_log.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn iam_rejects_stale_proof_and_bad_method() {
    let (sts, _) = spawn_sts("arn:aws:sts::123456789012:assumed-role/agent-role/task-9").await;
    let (up, _) = spawn_upstream().await;
    let port = free_port();
    let srv = spawn_octobroker(&iam_config(port, &up, &sts, "", ""), &[]).await;

    // 10-minute-old proof exceeds the 60s validity window
    let stale = std::time::SystemTime::now() - Duration::from_secs(600);
    let headers = sign_proof(authority(&sts), "us-east-1", "test-server-1", stale, true);
    let resp = iam_exchange(
        srv.port,
        iam_request("POST", &format!("{}/", sts), &headers, STS_BODY),
    )
    .await;
    assert_eq!(resp.status(), 401);

    let headers = sign_proof(
        authority(&sts),
        "us-east-1",
        "test-server-1",
        std::time::SystemTime::now(),
        true,
    );
    let resp = iam_exchange(
        srv.port,
        iam_request("GET", &format!("{}/", sts), &headers, STS_BODY),
    )
    .await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn iam_rejects_disallowed_endpoint_and_unmapped_arn() {
    let (sts, _) = spawn_sts("arn:aws:sts::999:assumed-role/unknown-role/x").await;
    let (up, _) = spawn_upstream().await;
    let port = free_port();
    let srv = spawn_octobroker(&iam_config(port, &up, &sts, "", ""), &[]).await;

    // endpoint outside the allowlist is rejected before any I/O
    let headers = sign_proof(
        "sts.example-evil.com",
        "us-east-1",
        "test-server-1",
        std::time::SystemTime::now(),
        true,
    );
    let resp = iam_exchange(
        srv.port,
        iam_request("POST", "https://sts.example-evil.com/", &headers, STS_BODY),
    )
    .await;
    assert!(resp.status() == 400 || resp.status() == 403);

    // well-formed proof, unmapped ARN → authenticated identity is still refused
    let headers = sign_proof(
        authority(&sts),
        "us-east-1",
        "test-server-1",
        std::time::SystemTime::now(),
        true,
    );
    let resp = iam_exchange(
        srv.port,
        iam_request("POST", &format!("{}/", sts), &headers, STS_BODY),
    )
    .await;
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn iam_rejects_replayed_proof_and_presigned_url() {
    let (sts, _) = spawn_sts("arn:aws:sts::123456789012:assumed-role/agent-role/task-9").await;
    let (up, _) = spawn_upstream().await;
    let port = free_port();
    let srv = spawn_octobroker(&iam_config(port, &up, &sts, "", ""), &[]).await;

    // A completed proof cannot mint a second token (the signature is the
    // single-use fingerprint — deterministic SigV4 means a capture is
    // permanently spent, even inside the freshness window).
    let payload = iam_request(
        "POST",
        &format!("{}/", sts),
        &sign_proof(
            authority(&sts),
            "us-east-1",
            "test-server-1",
            std::time::SystemTime::now(),
            true,
        ),
        STS_BODY,
    );
    let resp = iam_exchange(srv.port, payload.clone()).await;
    assert_eq!(resp.status(), 200);
    let resp = iam_exchange(srv.port, payload).await;
    assert_eq!(resp.status(), 401);

    // Presigned-URL style proofs (X-Amz-Signature query params) are rejected.
    let resp = iam_exchange(
        srv.port,
        iam_request(
            "GET",
            &format!("{}/?X-Amz-Signature=abc", sts),
            &HashMap::new(),
            STS_BODY,
        ),
    )
    .await;
    assert!(resp.status() == 400 || resp.status() == 403);
}

#[tokio::test]
async fn iam_token_expiry_denies() {
    let (sts, _) = spawn_sts("arn:aws:sts::123456789012:assumed-role/agent-role/task-9").await;
    let (up, _) = spawn_upstream().await;
    let port = free_port();
    // token_ttl_secs = 1
    let cfg =
        iam_config(port, &up, &sts, "", "").replace("token_ttl_secs = 300", "token_ttl_secs = 1");
    let srv = spawn_octobroker(&cfg, &[]).await;

    let headers = sign_proof(
        authority(&sts),
        "us-east-1",
        "test-server-1",
        std::time::SystemTime::now(),
        true,
    );
    let resp = iam_exchange(
        srv.port,
        iam_request("POST", &format!("{}/", sts), &headers, STS_BODY),
    )
    .await;
    let v: serde_json::Value = resp.json().await.unwrap();
    let token = v["token"].as_str().unwrap().to_string();

    tokio::time::sleep(Duration::from_secs(2)).await;
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/mcp", srv.port))
        .header("content-type", "application/json")
        .header("x-octobroker-iam-token", &token)
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn iam_disabled_route_is_not_registered() {
    let (up, _) = spawn_upstream().await;
    let port = free_port();
    let cfg = format!(
        r#"
port = {port}
allowed_owners = ["openabdev"]
[mcp]
enabled = true
upstream = "{up}"
"#,
        port = port,
        up = up
    );
    let srv = spawn_octobroker(&cfg, &[]).await;
    let resp = iam_exchange(srv.port, serde_json::json!({"iam_request_method":"POST"})).await;
    // No /mcp/iam-auth route and POST /{*path} isn't registered either.
    assert!(resp.status() == 404 || resp.status() == 405);
}

// ---------------------------------------------------------------------------
// quota + circuit breaker + Retry-After
// ---------------------------------------------------------------------------

#[tokio::test]
async fn per_agent_quota_returns_429_with_retry_after() {
    let (up, _) = spawn_upstream().await;
    let port = free_port();
    let cfg = format!(
        r#"
port = {port}
[[identities]]
id = "pool1"
token = "ghp_pool_fake"
allowed_owners = ["openabdev"]
[mcp]
enabled = true
upstream = "{up}"
[[mcp.agents]]
id = "limited"
key = "k1"
tools = ["issue_read"]
requests_per_minute = 1
"#,
        port = port,
        up = up
    );
    let srv = spawn_octobroker(&cfg, &[]).await;
    let client = reqwest::Client::new();
    let call = || {
        client
            .post(format!("http://127.0.0.1:{}/mcp", srv.port))
            .header("content-type", "application/json")
            .header("x-octobroker-key", "k1")
            .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
    };
    assert_eq!(call().send().await.unwrap().status(), 200);
    let resp = call().send().await.unwrap();
    assert_eq!(resp.status(), 429);
    assert!(
        resp.headers().get("retry-after").is_some(),
        "Retry-After required"
    );
}

#[tokio::test]
async fn circuit_breaker_fails_fast_and_recovers() {
    let (up, log) = spawn_upstream().await;
    let port = free_port();
    let cfg = format!(
        r#"
port = {port}
[[identities]]
id = "pool1"
token = "ghp_pool_fake"
allowed_owners = ["openabdev"]
[mcp]
enabled = true
upstream = "{up}"
upstream_breaker_failures = 2
upstream_breaker_cooldown_secs = 2
[[mcp.agents]]
id = "a1"
key = "k1"
tools = ["issue_read"]
"#,
        port = port,
        up = up
    );
    let srv = spawn_octobroker(&cfg, &[]).await;
    let client = reqwest::Client::new();
    let boom = || {
        client
            .post(format!("http://127.0.0.1:{}/mcp", srv.port))
            .header("content-type", "application/json")
            .header("x-octobroker-key", "k1")
            .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_read","arguments":{"marker":"m_marker_500"}}}"#)
    };
    assert_eq!(boom().send().await.unwrap().status(), 500);
    assert_eq!(boom().send().await.unwrap().status(), 500);
    // breaker now open: request is refused locally
    let resp = boom().send().await.unwrap();
    assert_eq!(resp.status(), 503);
    assert!(resp.headers().get("retry-after").is_some());
    assert_eq!(
        log.requests.lock().unwrap().len(),
        2,
        "open breaker must not touch upstream"
    );

    // cooldown elapsed → half-open probe succeeds and closes the breaker
    tokio::time::sleep(Duration::from_millis(2200)).await;
    let ok = client
        .post(format!("http://127.0.0.1:{}/mcp", srv.port))
        .header("content-type", "application/json")
        .header("x-octobroker-key", "k1")
        .body(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
}

#[tokio::test]
async fn upstream_retry_after_is_propagated() {
    let (up, _) = spawn_upstream().await;
    let port = free_port();
    let cfg = format!(
        r#"
port = {port}
[[identities]]
id = "pool1"
token = "ghp_pool_fake"
allowed_owners = ["openabdev"]
[mcp]
enabled = true
upstream = "{up}"
[[mcp.agents]]
id = "a1"
key = "k1"
tools = ["issue_read"]
"#,
        port = port,
        up = up
    );
    let srv = spawn_octobroker(&cfg, &[]).await;
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/mcp", srv.port))
        .header("content-type", "application/json")
        .header("x-octobroker-key", "k1")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_read","arguments":{"marker":"m_marker_429"}}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);
    assert_eq!(resp.headers().get("retry-after").unwrap(), "7");
}

// ---------------------------------------------------------------------------
// observability
// ---------------------------------------------------------------------------

#[tokio::test]
async fn metrics_endpoint_exposes_mcp_counters() {
    let (up, _) = spawn_upstream().await;
    let port = free_port();
    let cfg = format!(
        r#"
port = {port}
[[identities]]
id = "pool1"
token = "ghp_pool_fake"
allowed_owners = ["openabdev"]
[mcp]
enabled = true
upstream = "{up}"
[[mcp.agents]]
id = "a1"
key = "k1"
tools = ["issue_read"]
"#,
        port = port,
        up = up
    );
    let srv = spawn_octobroker(&cfg, &[]).await;
    let client = reqwest::Client::new();
    let _ = client
        .post(format!("http://127.0.0.1:{}/mcp", srv.port))
        .header("content-type", "application/json")
        .header("x-octobroker-key", "k1")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
        .send()
        .await
        .unwrap();
    // policy denial (create_issue not allowlisted → also a write → denied)
    let _ = client
        .post(format!("http://127.0.0.1:{}/mcp", srv.port))
        .header("content-type", "application/json")
        .header("x-octobroker-key", "k1")
        .body(r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"create_issue","arguments":{}}}"#)
        .send()
        .await
        .unwrap();

    let body = reqwest::get(format!("http://127.0.0.1:{}/metrics", srv.port))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        body.contains("octobroker_mcp_requests_total{agent=\"a1\",kind=\"tools_list\"} 1"),
        "{}",
        body
    );
    assert!(
        body.contains("octobroker_mcp_denied_total{agent=\"a1\",reason=\"policy\"} 1"),
        "{}",
        body
    );
    assert!(
        body.contains("octobroker_mcp_upstream_requests_total 1"),
        "{}",
        body
    );
    assert!(
        body.contains("octobroker_mcp_upstream_latency_ms_count"),
        "{}",
        body
    );
    assert!(body.contains("octobroker_mcp_circuit_open 0"), "{}", body);
}

// ---------------------------------------------------------------------------
// upstream contract probes (timeouts, mid-stream disconnect, session expiry)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn upstream_post_timeout_returns_clean_502() {
    let (up, _) = spawn_upstream().await;
    let port = free_port();
    let cfg = format!(
        r#"
port = {port}
[[identities]]
id = "pool1"
token = "ghp_pool_fake"
allowed_owners = ["openabdev"]
[mcp]
enabled = true
upstream = "{up}"
post_timeout_secs = 1
[[mcp.agents]]
id = "a1"
key = "k1"
tools = ["issue_read"]
"#,
        port = port,
        up = up
    );
    let srv = spawn_octobroker(&cfg, &[]).await;
    let start = Instant::now();
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/mcp", srv.port))
        .header("content-type", "application/json")
        .header("x-octobroker-key", "k1")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_read","arguments":{"marker":"m_marker_slow"}}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 502);
    assert!(
        start.elapsed() < Duration::from_secs(8),
        "timeout must bound the call"
    );
    let v: serde_json::Value = resp.json().await.unwrap();
    assert!(v["error"]["message"].as_str().unwrap().contains("upstream"));
}

#[tokio::test]
async fn mid_stream_disconnect_propagates_truncated_body() {
    let (up, _) = spawn_upstream().await;
    let port = free_port();
    let cfg = format!(
        r#"
port = {port}
[[identities]]
id = "pool1"
token = "ghp_pool_fake"
allowed_owners = ["openabdev"]
[mcp]
enabled = true
upstream = "{up}"
[[mcp.agents]]
id = "a1"
key = "k1"
tools = ["issue_read"]
"#,
        port = port,
        up = up
    );
    let srv = spawn_octobroker(&cfg, &[]).await;
    let start = Instant::now();
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/mcp", srv.port))
        .header("content-type", "application/json")
        .header("x-octobroker-key", "k1")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_read","arguments":{"marker":"m_marker_disconnect"}}}"#)
        .send()
        .await
        .unwrap();
    // A mid-stream disconnect must surface as a client-visible transport
    // failure (truncated/aborted body) — never a silent clean EOF on a
    // partial frame, never a retry, never a hang.
    let body = resp.bytes().await;
    assert!(start.elapsed() < Duration::from_secs(8));
    assert!(
        body.is_err(),
        "mid-stream abort must surface as an error, got {:?}",
        body
    );

    // …and it is counted for dashboards/alerting.
    let metrics = reqwest::get(format!("http://127.0.0.1:{}/metrics", srv.port))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains("octobroker_mcp_upstream_stream_errors_total 1"),
        "stream abort must be counted: {}",
        metrics
    );
}

#[tokio::test]
async fn idle_session_expiry_forces_reinitialize() {
    let (up, _) = spawn_upstream().await;
    let port = free_port();
    let cfg = format!(
        r#"
port = {port}
[[identities]]
id = "pool1"
token = "ghp_pool_fake"
allowed_owners = ["openabdev"]
[mcp]
enabled = true
upstream = "{up}"
session_ttl_secs = 1
[[mcp.agents]]
id = "a1"
key = "k1"
tools = ["issue_read"]
"#,
        port = port,
        up = up
    );
    let srv = spawn_octobroker(&cfg, &[]).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/mcp", srv.port))
        .header("content-type", "application/json")
        .header("x-octobroker-key", "k1")
        .body(r#"{"jsonrpc":"2.0","id":0,"method":"initialize"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.headers().get("mcp-session-id").unwrap(), "e2e-sess-1");

    tokio::time::sleep(Duration::from_secs(3)).await;
    // The pin is gone (single-replica replica-loss equivalent): the client
    // gets a clean 404 and must re-initialize — never silent re-binding.
    let resp = client
        .post(format!("http://127.0.0.1:{}/mcp", srv.port))
        .header("content-type", "application/json")
        .header("x-octobroker-key", "k1")
        .header("mcp-session-id", "e2e-sess-1")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}
