//! Black-box regression tests for RFC #15's audit contract: the durable
//! audit trail must record the allow/deny DECISION, not just allowed calls.
//!
//! `record_request`/`record_result` cover writes that clear policy. But a
//! policy-denied `tools/call` — off-allowlist tool, disallowed repository —
//! previously existed only in ephemeral tracing logs, leaving the durable
//! JSONL trail blind to exactly the probing a credential proxy exists to
//! detect. A denied call never reaches upstream, yet the attempt itself
//! must be auditable: `{decision: "deny", agent, tool, repo, reason}`.
//!
//! The test drives the real `octobroker` binary against a stub MCP upstream
//! and asserts the JSONL audit file gains a deny record per refused call.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

/// (status, lowercase response headers, body).
type HttpResponse = (u16, Vec<(String, String)>, String);

/// Minimal HTTP/1.1 helper: issues one request with `Connection: close` and
/// returns the response once the server closes the connection.
fn http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Option<HttpResponse> {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(15)))
        .ok()?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nhost: 127.0.0.1\r\nconnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() {
        req.push_str("content-type: application/json\r\n");
        req.push_str(&format!("content-length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    req.push_str(body);
    stream.write_all(req.as_bytes()).ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n")?;
    let mut lines = head.lines();
    let status: u16 = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string()))
        .collect();
    Some((status, headers, body.to_string()))
}

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn json_response(status: u16, extra_headers: &[(&str, &str)], body: &str) -> String {
    let mut resp = format!(
        "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n",
        body.len()
    );
    for (k, v) in extra_headers {
        resp.push_str(&format!("{k}: {v}\r\n"));
    }
    resp.push_str("connection: close\r\n\r\n");
    resp.push_str(body);
    resp
}

/// Stub upstream MCP server. Every POST replies 200; all request bodies are
/// recorded so tests can prove denied calls never leave the proxy.
struct StubMcp {
    port: u16,
    bodies: Arc<Mutex<Vec<String>>>,
}

fn spawn_stub_mcp() -> StubMcp {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let bodies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let bodies2 = bodies.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 8192];
            let mut header_end = None;
            loop {
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    header_end = Some(pos);
                    break;
                }
                match stream.read(&mut tmp) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
                if buf.len() > 1_000_000 {
                    break;
                }
            }
            let Some(header_end) = header_end else {
                continue;
            };
            let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
            let clen: usize = head
                .lines()
                .filter_map(|l| l.split_once(':'))
                .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.trim().parse().ok())
                .unwrap_or(0);
            let mut body = buf[header_end + 4..].to_vec();
            while body.len() < clen {
                match stream.read(&mut tmp) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => body.extend_from_slice(&tmp[..n]),
                }
            }
            let body = String::from_utf8_lossy(&body).into_owned();
            bodies2.lock().unwrap().push(body.clone());

            let resp = json_response(
                200,
                &[],
                r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#,
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    StubMcp { port, bodies }
}

/// A spawned `octobroker` server under test. Killed and cleaned up on drop.
struct Broker {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Broker {
    /// POST /mcp with a JSON-RPC frame and the given extra headers.
    fn mcp_post(&self, body: &str, headers: &[(&str, &str)]) -> HttpResponse {
        http(self.port, "POST", "/mcp", headers, body).expect("POST /mcp")
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn broker_config(port: u16, upstream_port: u16, audit_path: &Path) -> String {
    format!(
        r#"port = {port}
allowed_owners = ["openabdev"]

[[identities]]
id = "alice"
token = "token-alice"

[mcp]
enabled = true
upstream = "http://127.0.0.1:{upstream_port}"

[mcp.audit]
path = "{audit_path}"

[[mcp.agents]]
id = "bot-a"
keys = ["key-a"]
tools = ["issue_read"]
repos = ["openabdev/octobroker"]
"#,
        port = port,
        upstream_port = upstream_port,
        audit_path = audit_path.display(),
    )
}

/// Spawn a broker from a config-generating closure. Port probing is
/// inherently racy (a freed port can be claimed between probe and bind), so
/// each attempt regenerates the config with a fresh port and retries a few
/// times before giving up.
fn spawn_broker(mut config: impl FnMut(u16) -> String) -> Broker {
    let mut last_err = String::new();
    for _attempt in 0..3 {
        let dir = std::env::temp_dir().join(format!(
            "octobroker-deny-audit-it-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = config(free_port());
        std::fs::write(dir.join("config.toml"), &cfg).unwrap();
        let log_path = dir.join("server.log");
        let child = Command::new(env!("CARGO_BIN_EXE_octobroker"))
            .env_clear()
            .env("OCTOBROKER_CONFIG", dir.join("config.toml"))
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("RUST_LOG", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(&log_path).unwrap()))
            .spawn()
            .expect("spawn octobroker");
        let port = cfg
            .lines()
            .find_map(|l| l.strip_prefix("port = "))
            .and_then(|v| v.trim().parse().ok())
            .expect("config must set port");
        let mut broker = Broker { child, port, dir };
        match wait_ready(&mut broker, &log_path) {
            Ok(()) => return broker,
            Err(e) => last_err = e,
        }
    }
    panic!("octobroker failed to start after 3 attempts: {last_err}");
}

fn wait_ready(broker: &mut Broker, log_path: &Path) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = broker.child.try_wait().unwrap() {
            return Err(format!(
                "octobroker exited early ({status}); log:\n{}",
                std::fs::read_to_string(log_path).unwrap_or_default()
            ));
        }
        if let Some((200, _, _)) = http(broker.port, "GET", "/healthz", &[], "") {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "octobroker did not become ready; log:\n{}",
                std::fs::read_to_string(log_path).unwrap_or_default()
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn tools_call(id: serde_json::Value, tool: &str, arguments: serde_json::Value) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments}
    })
    .to_string()
}

fn read_audit(path: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// Assert the response is a model-visible tool error (result.isError, echoed
/// request id) — policy denials answer in-band so the agent can adapt.
fn assert_tool_denied(resp: &HttpResponse, expected_id: serde_json::Value) {
    assert_eq!(
        resp.0, 200,
        "tool denials are in-band 200s; body={}",
        resp.2
    );
    let v: serde_json::Value = serde_json::from_str(&resp.2).unwrap();
    assert_eq!(v["id"], expected_id, "tool error must echo the request id");
    assert_eq!(
        v["result"]["isError"], true,
        "policy denial must be an MCP tool error; got {}",
        resp.2
    );
    let text = v["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        text.contains("denied"),
        "tool error should explain the denial; got {}",
        resp.2
    );
}

/// RFC #15 enforcement-flow contract: every `tools/call` is audited with its
/// allow/deny decision. A call denied by policy must append a durable
/// `decision:"deny"` record — agent, tool, repo, reason, request id — even
/// though nothing is forwarded upstream.
#[test]
fn denied_tools_calls_are_durably_audited() {
    let stub = spawn_stub_mcp();
    let audit_dir = std::env::temp_dir().join(format!(
        "octobroker-deny-audit-log-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&audit_dir).unwrap();
    let audit_path = audit_dir.join("audit.jsonl");
    let broker = spawn_broker(|port| broker_config(port, stub.port, &audit_path));

    // Deny #1: tool is not on the agent's allowlist. A sentinel argument
    // VALUE proves the deny record leaks key names only, never values.
    let resp = broker.mcp_post(
        &tools_call(
            serde_json::json!(11),
            "delete_file",
            serde_json::json!({"owner": "openabdev", "repo": "octobroker", "content": "S3CR3T-VALUE-MARKER"}),
        ),
        &[("x-octobroker-key", "key-a")],
    );
    assert_tool_denied(&resp, serde_json::json!(11));

    // Deny #2: allowlisted tool, but the resolved repository is not allowed.
    let resp = broker.mcp_post(
        &tools_call(
            serde_json::json!(12),
            "issue_read",
            serde_json::json!({"owner": "evil", "repo": "other", "issue_number": 1}),
        ),
        &[("x-octobroker-key", "key-a")],
    );
    assert_tool_denied(&resp, serde_json::json!(12));

    // Neither denied call may have reached upstream.
    assert!(
        stub.bodies.lock().unwrap().is_empty(),
        "denied calls must never be forwarded upstream"
    );

    // The durable audit trail must carry both deny decisions.
    let records = read_audit(&audit_path);
    let denies: Vec<&serde_json::Value> =
        records.iter().filter(|r| r["decision"] == "deny").collect();
    assert_eq!(
        denies.len(),
        2,
        "expected 2 deny records in the durable audit; got {}",
        serde_json::to_string_pretty(&records).unwrap_or_default()
    );

    let d1 = denies[0];
    assert_eq!(d1["agent"], "bot-a");
    assert_eq!(d1["tool"], "delete_file");
    assert_eq!(d1["rpc_id"], serde_json::json!(11));
    assert_eq!(d1["repo"], "openabdev/octobroker");
    assert!(
        d1["reason"]
            .as_str()
            .unwrap_or("")
            .contains("not permitted"),
        "deny record must carry the policy reason; got {d1}"
    );

    let d2 = denies[1];
    assert_eq!(d2["agent"], "bot-a");
    assert_eq!(d2["tool"], "issue_read");
    assert_eq!(d2["rpc_id"], serde_json::json!(12));
    assert_eq!(d2["repo"], "evil/other");
    assert!(
        d2["reason"].as_str().unwrap_or("").contains("repository"),
        "repo deny record must carry the repository reason; got {d2}"
    );

    // Deny records carry argument KEY NAMES only — never argument values.
    let mut keys: Vec<String> = serde_json::from_value(d1["arg_keys"].clone()).unwrap();
    keys.sort();
    assert_eq!(keys, vec!["content", "owner", "repo"]);
    let raw = std::fs::read_to_string(&audit_path).unwrap_or_default();
    assert!(
        !raw.contains("S3CR3T-VALUE-MARKER"),
        "deny audit must not record argument values; got {raw}"
    );
}

/// An unauthenticated `tools/call` (401, no resolvable agent) is refused
/// before policy evaluation and must not produce a deny record — there is
/// no agent identity to attribute it to.
#[test]
fn unauthenticated_calls_are_not_attributed() {
    let stub = spawn_stub_mcp();
    let audit_dir = std::env::temp_dir().join(format!(
        "octobroker-deny-audit-log-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&audit_dir).unwrap();
    let audit_path = audit_dir.join("audit.jsonl");
    let broker = spawn_broker(|port| broker_config(port, stub.port, &audit_path));

    let resp = broker.mcp_post(
        &tools_call(
            serde_json::json!(21),
            "issue_read",
            serde_json::json!({"owner": "openabdev", "repo": "octobroker", "issue_number": 1}),
        ),
        &[],
    );
    assert_eq!(resp.0, 401, "missing key must be refused; body={}", resp.2);

    assert!(
        read_audit(&audit_path).is_empty(),
        "an unauthenticated request must not create audit records"
    );
    assert!(stub.bodies.lock().unwrap().is_empty());
}

/// A JSON-RPC batch (array) body carries no single frame for the policy
/// block to evaluate — a batched tools/call would bypass tool/repo policy
/// and the audit trail entirely. MCP Streamable HTTP dropped batching in
/// 2025-06-18, so the proxy rejects arrays fail-closed (400), forwarding
/// nothing and writing no half-attributed audit record.
#[test]
fn batch_requests_are_rejected_before_policy() {
    let stub = spawn_stub_mcp();
    let audit_dir = std::env::temp_dir().join(format!(
        "octobroker-deny-audit-log-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&audit_dir).unwrap();
    let audit_path = audit_dir.join("audit.jsonl");
    let broker = spawn_broker(|port| broker_config(port, stub.port, &audit_path));

    // Even an ALLOWLISTED tool inside a batch must be refused: the frame
    // parser yields no per-call object, so policy cannot be applied.
    let batch = format!(
        "[{}]",
        tools_call(
            serde_json::json!(31),
            "issue_read",
            serde_json::json!({"owner": "openabdev", "repo": "octobroker", "issue_number": 1})
        )
    );
    let resp = broker.mcp_post(&batch, &[("x-octobroker-key", "key-a")]);
    assert_eq!(
        resp.0, 400,
        "batch bodies must be rejected fail-closed; body={}",
        resp.2
    );
    let v: serde_json::Value = serde_json::from_str(&resp.2).unwrap();
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("batch"),
        "rejection should explain batching is unsupported; got {}",
        resp.2
    );

    assert!(
        stub.bodies.lock().unwrap().is_empty(),
        "a rejected batch must never reach upstream"
    );
}
