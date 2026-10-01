//! `obk mcp` — MCP stdio shim (Phase 3, octobroker#18).
//!
//! Runs inside the agent container as a stdio MCP server: newline-delimited
//! JSON-RPC frames on stdin are piped to octobroker `POST /mcp` over HTTPS;
//! each response frame (JSON or SSE `data:` payloads) is written as one line
//! on stdout. The `mcp-session-id` handshake is tracked and re-sent on every
//! request; stdin EOF sends a session `DELETE` before exit.
//!
//! Authentication (checked in this order):
//! - `OCTOBROKER_KEY` → static `X-Octobroker-Key` (existing mode).
//! - Otherwise IAM mode (secretless): ambient AWS credentials — ECS task
//!   role / EKS IRSA / instance profile via `aws-config` — sign a fixed
//!   `sts:GetCallerIdentity` POST which is exchanged at
//!   `POST /mcp/iam-auth` for a short-lived `X-Octobroker-Iam-Token`.
//!   Requires `OCTOBROKER_IAM_SERVER_ID` (the value signed into the
//!   `x-octobroker-server-id` header) and TLS (https) unless the octobroker
//!   host is loopback. The agent never holds a GitHub credential.
//!
//! Resilience: idempotent MCP methods are retried with bounded exponential
//! backoff honoring `Retry-After`; `tools/call`, notifications and DELETE
//! are NEVER auto-retried (a write's outcome is undeterminable once sent).

use aws_credential_types::provider::ProvideCredentials;
use std::io::{BufRead, Write};

/// Methods safe to auto-retry — they mint no upstream side effect.
const IDEMPOTENT_METHODS: &[&str] = &[
    "initialize",
    "ping",
    "tools/list",
    "resources/list",
    "resources/templates/list",
    "prompts/list",
    "completion/complete",
    "logging/setLevel",
];

const MAX_ATTEMPTS: u32 = 3;
const BACKOFF_BASE_MS: u64 = 500;
const BACKOFF_CAP_MS: u64 = 8000;
/// Hard ceiling for a server-provided Retry-After hint.
const RETRY_AFTER_CAP_MS: u64 = 60_000;
/// POST timeout must exceed octobroker's default upstream POST timeout (120s).
const POST_TIMEOUT_SECS: u64 = 130;

pub fn run(base: &str) -> i32 {
    let base = base.trim_end_matches('/');
    if base.is_empty() {
        eprintln!("obk mcp: OCTOBROKER_URL is not set");
        return 2;
    }
    let mut auth = match Auth::detect(base) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("obk mcp: {}", e);
            return 2;
        }
    };
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(POST_TIMEOUT_SECS))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("obk mcp: http client: {}", e);
            return 1;
        }
    };

    let stdin = std::io::stdin();
    let mut session_id: Option<String> = None;
    for line in stdin.lock().lines() {
        let Ok(frame) = line else { break };
        let frame = frame.trim();
        if frame.is_empty() {
            continue;
        }
        let (method, has_id) = frame_method(frame);
        let retryable = method.as_deref().map(is_idempotent).unwrap_or(false);
        let resp = post_frame(
            &client,
            base,
            frame,
            &mut auth,
            session_id.as_deref(),
            retryable,
        );
        let Some(resp) = resp else {
            // Transport failure past retries — surface as a JSON-RPC error.
            if has_id {
                if let Some(id) = frame_id(frame) {
                    write_frame(&serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {"code": -32000, "message": "octobroker unreachable"}
                    }));
                }
            }
            continue;
        };
        if let Some(sid) = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
        {
            session_id = Some(sid.to_string());
        }
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        emit_response(status.as_u16(), &body, has_id, frame);
    }

    // stdin closed → clean up the upstream session.
    if let Some(sid) = &session_id {
        let mut req = client
            .delete(format!("{}/mcp", base))
            .timeout(std::time::Duration::from_secs(30))
            .header("mcp-session-id", sid.as_str());
        if let Ok(hdrs) = auth.headers() {
            for (k, v) in hdrs {
                req = req.header(k, v);
            }
        }
        let _ = req.send();
    }
    0
}

/// `true` for request frames that may be retried on transient failures.
fn is_idempotent(method: &str) -> bool {
    IDEMPOTENT_METHODS.contains(&method)
}

fn frame_method(frame: &str) -> (Option<String>, bool) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(frame) else {
        return (None, false);
    };
    (
        v.get("method").and_then(|m| m.as_str()).map(String::from),
        v.get("id").is_some() && !v.get("id").unwrap().is_null(),
    )
}

fn frame_id(frame: &str) -> Option<serde_json::Value> {
    serde_json::from_str::<serde_json::Value>(frame)
        .ok()
        .and_then(|v| v.get("id").cloned())
}

/// Write one JSON-RPC frame as a single line (MCP stdio framing).
fn write_frame(v: &serde_json::Value) {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let _ = writeln!(out, "{}", v);
    let _ = out.flush();
}

/// Translate one upstream response into stdout frames.
fn emit_response(status: u16, body: &str, has_id: bool, req_frame: &str) {
    if status == 202 || body.trim().is_empty() {
        return;
    }
    let trimmed = body.trim();
    if trimmed.starts_with("event:") || trimmed.starts_with("data:") {
        // SSE: emit each data payload that parses as JSON-RPC.
        for payload in sse_data_payloads(trimmed) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&payload) {
                write_frame(&v);
            }
        }
        return;
    }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if v.get("error").is_some() && !status_is_success(status) {
            write_frame(&v);
            return;
        }
        if status_is_success(status) {
            write_frame(&v);
            return;
        }
    }
    // Non-2xx without a JSON-RPC body — synthesize one.
    if has_id {
        if let Some(id) = frame_id(req_frame) {
            write_frame(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32000, "message": format!("octobroker HTTP {}", status)}
            }));
        }
    }
}

fn status_is_success(s: u16) -> bool {
    (200..300).contains(&s)
}

/// Extract `data:` payload text from an SSE response body.
fn sse_data_payloads(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    for line in body.lines() {
        if line.is_empty() {
            if !buf.is_empty() {
                out.push(std::mem::take(&mut buf));
            }
            continue;
        }
        if let Some(d) = line.strip_prefix("data:") {
            if !buf.is_empty() {
                buf.push('\n');
            }
            buf.push_str(d.strip_prefix(' ').unwrap_or(d));
        }
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    out
}

/// POST one frame, retrying transient failures with bounded exponential
/// backoff (honoring `Retry-After`) — ONLY for idempotent methods.
fn post_frame(
    client: &reqwest::blocking::Client,
    base: &str,
    frame: &str,
    auth: &mut Auth,
    session_id: Option<&str>,
    retryable: bool,
) -> Option<reqwest::blocking::Response> {
    for attempt in 0..MAX_ATTEMPTS {
        let hdrs = match auth.headers() {
            Ok(h) => h,
            Err(e) => {
                eprintln!("obk mcp: auth: {}", e);
                return None;
            }
        };
        let mut req = client
            .post(format!("{}/mcp", base))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(frame.to_string());
        if let Some(sid) = session_id {
            req = req.header("mcp-session-id", sid);
        }
        for (k, v) in &hdrs {
            req = req.header(k.as_str(), v.as_str());
        }
        match req.send() {
            Ok(resp) => {
                let transient = resp.status().as_u16() == 429 || resp.status().is_server_error();
                if transient && retryable && attempt + 1 < MAX_ATTEMPTS {
                    // Retry-After is honored but capped — a malicious/large
                    // value must not hang the stdio session for an hour.
                    let wait = retry_after_ms(resp.headers())
                        .map(|ms| ms.min(RETRY_AFTER_CAP_MS))
                        .unwrap_or_else(|| backoff_ms(attempt));
                    eprintln!(
                        "obk mcp: upstream {} — retrying in {}ms",
                        resp.status(),
                        wait
                    );
                    std::thread::sleep(std::time::Duration::from_millis(wait));
                    continue;
                }
                return Some(resp);
            }
            Err(e) => {
                if retryable && attempt + 1 < MAX_ATTEMPTS && (e.is_connect() || e.is_timeout()) {
                    let wait = backoff_ms(attempt);
                    eprintln!("obk mcp: transport error — retrying in {}ms", wait);
                    std::thread::sleep(std::time::Duration::from_millis(wait));
                    continue;
                }
                eprintln!("obk mcp: request failed: {}", e);
                return None;
            }
        }
    }
    None
}

/// `Retry-After` header → delay in ms (integer-seconds form only).
fn retry_after_ms(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|s| s * 1000)
}

fn backoff_ms(attempt: u32) -> u64 {
    (BACKOFF_BASE_MS << attempt).min(BACKOFF_CAP_MS)
}

// ---------------------------------------------------------------------------
// auth
// ---------------------------------------------------------------------------

enum Auth {
    /// Static octobroker key (OCTOBROKER_KEY).
    Key(String),
    /// SigV4-exchanged short-lived token.
    Iam(IamState),
}

struct IamState {
    token: String,
    /// unix seconds when the current token was issued — lets the refresh
    /// margin scale to sub-60s TTLs.
    issued_at: u64,
    expires_at: u64,
    /// Ambient AWS credentials snapshot (refreshed per exchange so rotated
    /// task-role credentials are picked up).
    aws: AwsCreds,
    region: String,
    sts_url: String,
    server_id: String,
    base: String,
}

impl Auth {
    fn detect(base: &str) -> Result<Auth, String> {
        if let Ok(key) = std::env::var("OCTOBROKER_KEY") {
            if !key.is_empty() {
                return Ok(Auth::Key(key));
            }
        }
        // IAM mode requires TLS except loopback dev endpoints.
        let loopback = base
            .split_once("://")
            .map(|(_, a)| {
                let auth = a.split('/').next().unwrap_or("");
                let host = if let Some(b) = auth.strip_prefix('[') {
                    b.split(']').next().unwrap_or("")
                } else {
                    auth.split(':').next().unwrap_or("")
                };
                matches!(host, "127.0.0.1" | "localhost" | "::1")
            })
            .unwrap_or(false);
        if !base.starts_with("https://") && !loopback {
            return Err(format!(
                "OCTOBROKER_URL '{}' must be https:// for IAM auth (the SigV4 proof must not travel cleartext)",
                base
            ));
        }
        let server_id = std::env::var("OCTOBROKER_IAM_SERVER_ID")
            .map_err(|_| "OCTOBROKER_IAM_SERVER_ID is required for IAM auth".to_string())?;
        let (aws, region) = ambient_aws_credentials()?;
        let sts_url = std::env::var("OCTOBROKER_STS_URL")
            .unwrap_or_else(|_| format!("https://sts.{}.amazonaws.com", region));
        let mut state = IamState {
            token: String::new(),
            issued_at: 0,
            expires_at: 0,
            aws,
            region,
            sts_url,
            server_id,
            base: base.to_string(),
        };
        refresh_iam_token(&mut state)?;
        Ok(Auth::Iam(state))
    }

    /// Auth header(s) to attach to an /mcp request, refreshing the IAM token
    /// when it is within 60s of expiry.
    fn headers(&mut self) -> Result<Vec<(String, String)>, String> {
        match self {
            Auth::Key(k) => Ok(vec![("x-octobroker-key".to_string(), k.clone())]),
            Auth::Iam(st) => {
                let now = unix_now();
                // Refresh inside a margin of min(60s, half the issued TTL) —
                // a TTL under ~2min would otherwise re-exchange every frame.
                let margin = 60u64.min((st.expires_at.saturating_sub(st.issued_at) / 2).max(1));
                if st.expires_at <= now + margin {
                    // Also re-pull ambient creds — task-role credentials rotate.
                    if let Ok((aws, region)) = ambient_aws_credentials() {
                        st.aws = aws;
                        st.region = region;
                    }
                    if let Err(e) = refresh_iam_token(st) {
                        if st.expires_at > now {
                            // Ride the still-valid token; refresh again next frame.
                            eprintln!("obk mcp: IAM refresh failed ({}) — reusing token", e);
                        } else {
                            return Err(e);
                        }
                    }
                }
                Ok(vec![(
                    "x-octobroker-iam-token".to_string(),
                    st.token.clone(),
                )])
            }
        }
    }
}

/// POST the signed proof to /mcp/iam-auth and store the issued token.
fn refresh_iam_token(st: &mut IamState) -> Result<(), String> {
    let proof = sign_get_caller_identity(&st.aws, &st.region, &st.sts_url, &st.server_id);
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .post(format!("{}/mcp/iam-auth", st.base))
        .json(&proof)
        .send()
        .map_err(|e| format!("iam-auth request failed: {}", e))?;
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .map_err(|e| format!("iam-auth response unreadable: {}", e))?;
    if !status.is_success() {
        return Err(format!(
            "iam-auth rejected ({}): {}",
            status,
            body["error"]["message"].as_str().unwrap_or("unknown")
        ));
    }
    let token = body["token"]
        .as_str()
        .ok_or("iam-auth: no token")?
        .to_string();
    let expires_at = body["expires_at"]
        .as_u64()
        .ok_or("iam-auth: no expires_at")?;
    st.token = token;
    st.issued_at = unix_now();
    st.expires_at = expires_at;
    eprintln!(
        "obk mcp: IAM token refreshed (agent={})",
        body["agent"].as_str().unwrap_or("?")
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// AWS SigV4 — sign the fixed GetCallerIdentity POST by hand (hmac+sha2 only)
// ---------------------------------------------------------------------------

pub struct AwsCreds {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
}

/// Fetch ambient credentials + region via aws-config (env vars, shared
/// config, ECS task-role endpoint, EKS IRSA web identity).
fn ambient_aws_credentials() -> Result<(AwsCreds, String), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(async {
        let cfg = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let provider = cfg
            .credentials_provider()
            .ok_or("no AWS credential provider (set task role / IRSA / env creds)")?;
        let creds = provider
            .provide_credentials()
            .await
            .map_err(|e| format!("AWS credential resolution failed: {}", e))?;
        let region = cfg
            .region()
            .map(|r| r.to_string())
            .unwrap_or_else(|| "us-east-1".to_string());
        Ok((
            AwsCreds {
                access_key: creds.access_key_id().to_string(),
                secret_key: creds.secret_access_key().to_string(),
                session_token: creds.session_token().map(|t| t.to_string()),
            },
            region,
        ))
    })
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `YYYYMMDD'T'HHMMSS'Z'` + `YYYYMMDD` for SigV4. Fixed-width format —
/// hand-rolled civil-from-days math (Howard Hinnant) so no time crate is
/// needed.
fn amz_now() -> (String, String) {
    let secs = unix_now() as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // days → civil y/m/d
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (
        format!("{:04}{:02}{:02}T{:02}{:02}{:02}Z", y, m, d, h, mi, s),
        format!("{:04}{:02}{:02}", y, m, d),
    )
}

/// Sign `Action=GetCallerIdentity&Version=2011-06-15` POST to `endpoint`
/// and return the /mcp/iam-auth request body.
fn sign_get_caller_identity(
    creds: &AwsCreds,
    region: &str,
    endpoint: &str,
    server_id: &str,
) -> serde_json::Value {
    let body = "Action=GetCallerIdentity&Version=2011-06-15";
    let authority = endpoint
        .trim_end_matches('/')
        .split_once("://")
        .map(|(_, a)| a)
        .unwrap_or("");
    let (amz_date, date) = amz_now();

    // Canonical headers — sorted, lowercase; x-amz-security-token is signed
    // whenever session creds are used (ECS task role / IRSA always are).
    let mut headers: Vec<(String, String)> = vec![
        (
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        ),
        ("host".into(), authority.to_string()),
        ("x-amz-date".into(), amz_date.clone()),
        ("x-octobroker-server-id".into(), server_id.to_string()),
    ];
    if let Some(tok) = &creds.session_token {
        headers.push(("x-amz-security-token".into(), tok.clone()));
    }
    headers.sort();
    let canonical_headers: String = headers
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
        .collect();
    let signed_headers: String = headers
        .iter()
        .map(|(k, _)| k.clone())
        .collect::<Vec<_>>()
        .join(";");
    let payload_hash = hex(&sha256(body.as_bytes()));
    let canonical = format!(
        "POST\n/\n\n{}\n{}\n{}",
        canonical_headers, signed_headers, payload_hash
    );
    let scope = format!("{}/{}/sts/aws4_request", date, region);
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        scope,
        hex(&sha256(canonical.as_bytes()))
    );
    let k_date = hmac(
        format!("AWS4{}", creds.secret_key).as_bytes(),
        date.as_bytes(),
    );
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, b"sts");
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex(&hmac(&k_signing, to_sign.as_bytes()));
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        creds.access_key, scope, signed_headers, signature
    );

    let mut header_map = serde_json::Map::new();
    for (k, v) in headers {
        header_map.insert(k, serde_json::Value::String(v));
    }
    header_map.insert(
        "authorization".to_string(),
        serde_json::Value::String(authorization),
    );
    serde_json::json!({
        "iam_request_method": "POST",
        "iam_request_url": endpoint.trim_end_matches('/') .to_string() + "/",
        "iam_request_headers": header_map,
        "iam_request_body": body,
    })
}

fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).to_vec()
}

fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
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

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> AwsCreds {
        AwsCreds {
            access_key: "TESTACCESSKEY0000001".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: Some("sessiontok".into()),
        }
    }

    #[test]
    fn sigv4_proof_is_well_formed() {
        let proof = sign_get_caller_identity(
            &creds(),
            "us-east-1",
            "https://sts.us-east-1.amazonaws.com",
            "prod-1",
        );
        assert_eq!(proof["iam_request_method"], "POST");
        assert_eq!(
            proof["iam_request_url"],
            "https://sts.us-east-1.amazonaws.com/"
        );
        assert_eq!(
            proof["iam_request_body"],
            "Action=GetCallerIdentity&Version=2011-06-15"
        );
        let h = &proof["iam_request_headers"];
        let authz = h["authorization"].as_str().unwrap();
        assert!(authz.starts_with("AWS4-HMAC-SHA256 Credential=TESTACCESSKEY0000001/"));
        assert!(authz.contains("/us-east-1/sts/aws4_request"));
        assert!(authz.contains("x-octobroker-server-id"));
        assert!(authz.contains("x-amz-security-token"));
        assert_eq!(h["host"], "sts.us-east-1.amazonaws.com");
        assert_eq!(h["x-octobroker-server-id"], "prod-1");
    }

    #[test]
    fn idempotent_methods_are_retryable_writes_are_not() {
        assert!(is_idempotent("initialize"));
        assert!(is_idempotent("tools/list"));
        assert!(!is_idempotent("tools/call"));
        assert!(!is_idempotent("notifications/initialized"));
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        assert_eq!(backoff_ms(0), 500);
        assert_eq!(backoff_ms(1), 1000);
        assert_eq!(backoff_ms(4), 8000);
        assert_eq!(backoff_ms(9), 8000);
    }

    #[test]
    fn sse_payloads_unframe() {
        let body = "event: message\ndata: {\"a\":1}\n\ndata: {\"b\":2}\n\n";
        let p = sse_data_payloads(body);
        assert_eq!(p, vec!["{\"a\":1}", "{\"b\":2}"]);
    }

    #[test]
    fn frame_parsing_detects_method_and_id() {
        let (m, has_id) = frame_method(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
        assert_eq!(m.as_deref(), Some("tools/list"));
        assert!(has_id);
        let (_, has_id) = frame_method(r#"{"jsonrpc":"2.0","method":"notifications/x"}"#);
        assert!(!has_id);
    }
}
