//! Black-box regression tests for issue #59 against the real `octobroker`
//! binary: a protocol-level JSON-RPC error body must echo the request id
//! whenever the request frame was parsed. An `id: null` error on an
//! in-flight call is un-correlatable and leaves strict JSON-RPC clients
//! (ACP agents, kiro-cli) waiting forever — the residual hang vector #58
//! left after fixing the tools/call policy-denial paths.
//!
//! A stub MCP upstream serves initialize (with an mcp-session-id header) so
//! session pinning engages; every rejected in-flight request must come back
//! with the caller's own id.

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

/// Stub upstream MCP server. Every POST replies 200; `initialize` requests
/// additionally carry `mcp-session-id: mock-sess-1` so the proxy pins the
/// session to the presenting agent. All request bodies are recorded.
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

            let resp = if body.contains("\"initialize\"") {
                json_response(
                    200,
                    &[("mcp-session-id", "mock-sess-1")],
                    r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"stub","version":"0"}}}"#,
                )
            } else {
                json_response(200, &[], r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#)
            };
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

fn broker_config(port: u16, upstream_port: u16) -> String {
    format!(
        r#"port = {port}
allowed_owners = ["openabdev"]

[[identities]]
id = "alice"
token = "token-alice"

[mcp]
enabled = true
upstream = "http://127.0.0.1:{upstream_port}"

[[mcp.agents]]
id = "bot-a"
keys = ["key-a"]
tools = ["issue_read"]

[[mcp.agents]]
id = "bot-b"
keys = ["key-b"]
tools = ["issue_read"]
"#,
        port = port,
        upstream_port = upstream_port,
    )
}

fn spawn_broker(config: &str) -> Broker {
    let dir = std::env::temp_dir().join(format!(
        "octobroker-rpcid-it-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("config.toml"), config).unwrap();
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
    let port = config
        .lines()
        .find_map(|l| l.strip_prefix("port = "))
        .and_then(|v| v.trim().parse().ok())
        .expect("config must set port");
    let mut broker = Broker { child, port, dir };
    wait_ready(&mut broker, &log_path);
    broker
}

fn wait_ready(broker: &mut Broker, log_path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = broker.child.try_wait().unwrap() {
            panic!(
                "octobroker exited early ({status}); log:\n{}",
                std::fs::read_to_string(log_path).unwrap_or_default()
            );
        }
        if let Some((200, _, _)) = http(broker.port, "GET", "/healthz", &[], "") {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "octobroker did not become ready; log:\n{}",
            std::fs::read_to_string(log_path).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn tools_call_frame(id: serde_json::Value) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": "issue_read", "arguments": {"repo": "openabdev/octobroker", "issue_number": 59}}
    })
    .to_string()
}

/// Parse the response body and assert it is a JSON-RPC error whose `id`
/// echoes `expected` — the correlation contract of #59.
fn assert_rpc_error(resp: &HttpResponse, status: u16, expected: serde_json::Value) {
    assert_eq!(resp.0, status, "unexpected HTTP status; body={}", resp.2);
    let v: serde_json::Value = serde_json::from_str(&resp.2).unwrap();
    assert_eq!(v["jsonrpc"], "2.0");
    assert!(
        v["error"]["message"].is_string(),
        "expected a JSON-RPC error body; got {}",
        resp.2
    );
    assert_eq!(
        v["id"], expected,
        "rpc_error must echo the request id — id:null hangs strict clients"
    );
}

/// Named hang vector #1 from the issue: `403 session not owned by this agent`
/// must echo the request id (numeric and string ids alike).
#[test]
fn session_binding_violation_echoes_request_id() {
    let stub = spawn_stub_mcp();
    let config = broker_config(free_port(), stub.port);
    let broker = spawn_broker(&config);

    // bot-a initializes: upstream pins mock-sess-1 to bot-a
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"it","version":"0"}}}"#;
    let (status, headers, _) = broker.mcp_post(init, &[("x-octobroker-key", "key-a")]);
    assert_eq!(status, 200);
    let session = headers
        .iter()
        .find(|(k, _)| k == "mcp-session-id")
        .map(|(_, v)| v.as_str())
        .expect("initialize must return mcp-session-id");
    assert_eq!(session, "mock-sess-1");

    // bot-b's in-flight tools/call on bot-a's session → 403 echoing id 7
    let resp = broker.mcp_post(
        &tools_call_frame(serde_json::json!(7)),
        &[
            ("x-octobroker-key", "key-b"),
            ("mcp-session-id", "mock-sess-1"),
        ],
    );
    assert_rpc_error(&resp, 403, serde_json::json!(7));

    // JSON-RPC permits string ids — they must echo verbatim
    let resp = broker.mcp_post(
        &tools_call_frame(serde_json::json!("req-9")),
        &[
            ("x-octobroker-key", "key-b"),
            ("mcp-session-id", "mock-sess-1"),
        ],
    );
    assert_rpc_error(&resp, 403, serde_json::json!("req-9"));

    // Upstream saw only the initialize — rejections never leave the proxy
    assert_eq!(stub.bodies.lock().unwrap().len(), 1);
}

/// The remaining post-parse rejection paths: an unknown session (404) and an
/// authentication failure (401) must also echo the request id — both answer
/// in-flight calls that a strict client is actively awaiting.
#[test]
fn session_and_auth_failures_echo_request_id() {
    let stub = spawn_stub_mcp();
    let config = broker_config(free_port(), stub.port);
    let broker = spawn_broker(&config);

    // Unknown/expired session → 404 echoing id 4
    let resp = broker.mcp_post(
        &tools_call_frame(serde_json::json!(4)),
        &[
            ("x-octobroker-key", "key-a"),
            ("mcp-session-id", "ghost-session"),
        ],
    );
    assert_rpc_error(&resp, 404, serde_json::json!(4));

    // Stale/unknown agent key → 401 echoing id 3
    let resp = broker.mcp_post(
        &tools_call_frame(serde_json::json!(3)),
        &[("x-octobroker-key", "stale-key")],
    );
    assert_rpc_error(&resp, 401, serde_json::json!(3));

    // Missing key entirely → 401 echoing id 2
    let resp = broker.mcp_post(&tools_call_frame(serde_json::json!(2)), &[]);
    assert_rpc_error(&resp, 401, serde_json::json!(2));

    // Nothing was forwarded upstream
    assert!(stub.bodies.lock().unwrap().is_empty());
}
