//! Black-box regression tests for issue #59: protocol-level `rpc_error`
//! responses must echo the parsed JSON-RPC request id whenever a frame was
//! parsed. An `id: null` error on an in-flight `tools/call` is
//! un-correlatable — strict JSON-RPC clients wait on the pending call
//! forever (the residual hang vectors #58 left on the `403 session not
//! owned` and `502 upstream credential unavailable` paths).
//!
//! These tests drive the real binary over localhost with a stub upstream:
//! unit tests in `src/mcp.rs` cover the same branches in-process.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static SEQ: AtomicUsize = AtomicUsize::new(0);

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind free port")
        .local_addr()
        .expect("free port addr")
        .port()
}

/// (status, lowercased response headers, body).
type HttpResponse = (u16, Vec<(String, String)>, String);

/// One HTTP/1.1 request with `Connection: close`; returns the response once
/// the server closes the connection.
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

fn read_http_request(stream: &mut TcpStream) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_len = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        match stream.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
        if buf.len() > 1_000_000 {
            return;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_len]).into_owned();
    let content_length: usize = head
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);
    let mut remaining = content_length.saturating_sub(buf.len().saturating_sub(header_len));
    while remaining > 0 {
        match stream.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                remaining = remaining.saturating_sub(n);
            }
        }
    }
}

/// Stub MCP upstream: every POST gets a 200 JSON-RPC response plus an
/// `mcp-session-id` header so the proxy pins a downstream session.
fn spawn_stub_upstream() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("stub bind");
    let port = listener.local_addr().expect("stub addr").port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
            read_http_request(&mut stream);
            let body = r#"{"jsonrpc":"2.0","id":0,"result":{}}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nmcp-session-id: mock-sess-1\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    port
}

struct Broker {
    child: Child,
    dir: PathBuf,
}

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Path of the `octobroker` binary under test, resolved at RUNTIME from the
/// test executable's own location (`target/<profile>/deps/` → sibling
/// `target/<profile>/octobroker`). This must not use
/// `env!("CARGO_BIN_EXE_octobroker")`: that bakes the absolute checkout path
/// in at compile time, and the fleet verifier replays test builds across
/// symlinked `target/` dirs from different checkout paths — a stale
/// fingerprint then points at a deleted replay tree.
fn broker_binary() -> PathBuf {
    let exe = std::env::current_exe().expect("test executable path");
    let profile_dir = exe
        .parent()
        .expect("deps dir")
        .parent()
        .expect("profile dir");
    profile_dir.join(format!("octobroker{}", std::env::consts::EXE_SUFFIX))
}

/// Launch the real binary with a temp config file. Extra env is scoped to
/// the child process (never set globally, so parallel tests cannot race).
fn spawn_broker(config_toml: &str, extra_env: &[(&str, &str)]) -> Broker {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("octo-issue59-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).expect("tempdir");
    let cfg = dir.join("octobroker.toml");
    std::fs::write(&cfg, config_toml).expect("write config");
    let mut cmd = Command::new(broker_binary());
    cmd.env("OCTOBROKER_CONFIG", &cfg)
        .env_remove("OCTOBROKER_PORT")
        .env_remove("OCTOBROKER_MCP_ENABLED")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let child = cmd.spawn().expect("spawn octobroker");
    Broker { child, dir }
}

fn broker_port(config_toml: &str) -> u16 {
    config_toml
        .lines()
        .find_map(|l| l.trim().strip_prefix("port ="))
        .and_then(|v| v.trim().parse().ok())
        .expect("config must set port")
}

/// Poll GET /healthz until the broker serves (cheap: never touches the
/// credential path, unlike /mcp which would trigger a mint).
fn wait_ready(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some((status, _, _)) = http(port, "GET", "/healthz", &[], "") {
            assert_eq!(status, 200, "healthz must succeed, got {status}");
            return;
        }
        if Instant::now() > deadline {
            panic!("broker on port {port} never became ready");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// POST initialize until the broker answers 200 (startup grace), then return
/// the downstream session id from the response headers.
fn initialize(port: u16, key: Option<&str>) -> String {
    let mut headers = vec![];
    let key_value;
    if let Some(k) = key {
        key_value = k.to_string();
        headers.push(("x-octobroker-key", key_value.as_str()));
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some((status, resp_headers, _)) = http(
            port,
            "POST",
            "/mcp",
            &headers,
            r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}"#,
        ) {
            assert_eq!(status, 200, "initialize must succeed, got {status}");
            return resp_headers
                .iter()
                .find(|(k, _)| k == "mcp-session-id")
                .map(|(_, v)| v.clone())
                .expect("initialize response must carry mcp-session-id");
        }
        if Instant::now() > deadline {
            panic!("broker on port {port} never became ready");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn error_id(status: u16, body: &str) -> serde_json::Value {
    let v: serde_json::Value = serde_json::from_str(body).expect("error body must be JSON");
    assert_eq!(v["jsonrpc"], "2.0");
    assert!(
        v["error"]["message"].is_string(),
        "must be a JSON-RPC error"
    );
    let _ = status;
    v["id"].clone()
}

#[test]
fn rpc_403_session_not_owned_echoes_request_id() {
    let upstream = spawn_stub_upstream();
    let port = free_port();
    let config = format!(
        r#"port = {port}
allowed_owners = ["openabdev"]
[[identities]]
id = "alice"
token = "token-alice"
[mcp]
enabled = true
upstream = "http://127.0.0.1:{upstream}/"
[[mcp.agents]]
id = "bot-a"
key = "key-a"
tools = ["issue_read"]
[[mcp.agents]]
id = "bot-b"
key = "key-b"
tools = ["issue_read"]
"#
    );
    assert_eq!(broker_port(&config), port);
    let _broker = spawn_broker(&config, &[]);

    // bot-a initializes and owns the session …
    let session = initialize(port, Some("key-a"));
    // … bot-b presents it with its own valid key → 403, id echoed.
    let (status, _, body) = http(
        port,
        "POST",
        "/mcp",
        &[
            ("x-octobroker-key", "key-b"),
            ("mcp-session-id", session.as_str()),
        ],
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"issue_read","arguments":{}}}"#,
    )
    .expect("403 response");
    assert_eq!(status, 403);
    assert_eq!(error_id(status, &body), serde_json::json!(7));
    assert!(
        body.contains("session not owned"),
        "unexpected body: {body}"
    );
}

#[test]
fn rpc_502_mint_failure_echoes_request_id() {
    // App backend with bogus credentials: the mint can never succeed
    // (401 offline or fast-fail), so a session-less tools/call is a 502.
    // The PEM is passed via env (scoped to the child, never global).
    let pem = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/test-app-key.pem"
    ));
    let port = free_port();
    let config = format!(
        r#"port = {port}
allowed_owners = ["openabdev"]
[mcp]
enabled = true
upstream = "http://127.0.0.1:9/"
[mcp.github_app]
app_id = "12345"
private_key = "env:OCTO_ISSUE59_PEM"
installation_id = 42
"#
    );
    assert_eq!(broker_port(&config), port);
    let _broker = spawn_broker(&config, &[("OCTO_ISSUE59_PEM", pem)]);
    wait_ready(port);
    // Session-less tools/call in open (agent-less) mode → mint → 502.
    let (status, _, body) = http(
        port,
        "POST",
        "/mcp",
        &[],
        r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"issue_read","arguments":{}}}"#,
    )
    .expect("502 response");
    assert_eq!(status, 502);
    assert_eq!(error_id(status, &body), serde_json::json!(9));
    assert!(
        body.contains("upstream credential unavailable"),
        "unexpected body: {body}"
    );
}
