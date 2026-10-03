//! Black-box integration tests for the octobroker-owned review-operations
//! MCP tools (issue #44 MVP): `octobroker_review_minimize_comment`,
//! `octobroker_review_restore_comment`, `octobroker_review_delete_pending`,
//! `octobroker_review_submit`, and `octobroker_commit_status_set`.
//!
//! The broker-owned tools are handled locally inside octobroker — they must
//! NEVER be silently proxied to the upstream GitHub MCP server, and they are
//! write-classified, so without an authenticated write-enabled agent every
//! call must fail closed as a model-visible tool error (`result.isError`).
//!
//! A stub upstream records what reaches it; denials are observed on the wire.

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

/// Stub upstream MCP endpoint: records request bodies and answers every
/// JSON-RPC frame with a fixed successful tool result.
struct StubUpstream {
    port: u16,
    captured: Arc<Mutex<Vec<String>>>,
}

fn spawn_stub_upstream() -> StubUpstream {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured2 = captured.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 8192];
            // Read until the header terminator, then the content-length body.
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
            captured2
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(&body).into_owned());
            let payload = r#"{"jsonrpc":"2.0","id":1,"result":{"isError":false,"content":[{"type":"text","text":"ok"}]}}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                payload.len(),
                payload
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    StubUpstream { port, captured }
}

/// A spawned `octobroker` server under test. Killed and cleaned up on drop.
struct Broker {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Broker {
    /// POST one JSON-RPC frame to /mcp with the given agent key ("" = none).
    fn mcp(&self, key: &str, frame: &str) -> HttpResponse {
        let headers: Vec<(&str, &str)> = if key.is_empty() {
            Vec::new()
        } else {
            vec![("x-octobroker-key", key)]
        };
        http(self.port, "POST", "/mcp", &headers, frame).expect("POST /mcp")
    }

    fn tools_call(&self, key: &str, tool: &str, arguments: &str) -> HttpResponse {
        self.mcp(
            key,
            &format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{tool}","arguments":{arguments}}}}}"#
            ),
        )
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Path of the `octobroker` binary built next to this test executable
/// (`target/<profile>/deps/<test-bin>` → `target/<profile>/octobroker`).
///
/// `env!("CARGO_BIN_EXE_octobroker")` bakes in an absolute path that is only
/// valid for the directory cargo happened to build in. These tests are also
/// run from detached verification worktrees that share one `target/`
/// directory, so a test binary compiled there would try to spawn a path that
/// no longer exists once that worktree is removed. Resolving relative to the
/// running test binary is correct in every build directory.
fn broker_binary() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    let profile_dir = exe
        .parent()
        .and_then(Path::parent)
        .expect("target/<profile>/deps/<test-bin> layout");
    let binary = profile_dir.join(format!("octobroker{}", std::env::consts::EXE_SUFFIX));
    assert!(
        binary.is_file(),
        "octobroker binary not built at {}",
        binary.display()
    );
    binary
}

/// One spawn attempt: returns `Err` when the child could not start or died
/// before `/healthz` answered (a lost port race looks exactly like this).
fn try_spawn_broker(config: &str, port: u16) -> Result<Broker, String> {
    let dir = std::env::temp_dir().join(format!(
        "octobroker-reviewops-it-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.toml");
    let config = config.replace("{PORT}", &port.to_string());
    std::fs::write(&config_path, config).unwrap();
    let log_path = dir.join("server.log");
    let child = Command::new(broker_binary())
        .env_clear()
        .env("OCTOBROKER_CONFIG", &config_path)
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(std::fs::File::create(&log_path).unwrap()))
        .spawn()
        .map_err(|e| format!("spawn octobroker: {e}"))?;
    let mut broker = Broker { child, port, dir };
    wait_ready(&mut broker, &log_path)?;
    Ok(broker)
}

/// Boot a broker on a free port, retrying on the bind race: the port is
/// chosen by binding and releasing a socket, so another process (or a
/// parallel test in this suite) can take it in between. A lost race is
/// reported by an early child exit, never by a flaky assertion.
fn spawn_broker(config: &str) -> Broker {
    const ATTEMPTS: usize = 5;
    let mut last = String::new();
    for _ in 0..ATTEMPTS {
        match try_spawn_broker(config, free_port()) {
            Ok(broker) => return broker,
            Err(e) => last = e,
        }
    }
    panic!("octobroker did not start after {ATTEMPTS} attempts: {last}");
}

/// Poll `/healthz` until it answers, or report why the child is not usable.
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

fn assert_denied(resp: &HttpResponse, needle: &str, ctx: &str) {
    assert_eq!(
        resp.0, 200,
        "{ctx}: denial must be a tool error, got {resp:?}"
    );
    assert!(
        resp.2.contains(r#""isError":true"#),
        "{ctx}: expected result.isError, got {}",
        resp.2
    );
    assert!(
        resp.2.contains(needle),
        "{ctx}: expected denial containing {needle:?}, got {}",
        resp.2
    );
}

/// Every octobroker-owned review tool — the complete #44 MVP surface.
const LOCAL_REVIEW_TOOLS: &[&str] = &[
    "octobroker_review_minimize_comment",
    "octobroker_review_restore_comment",
    "octobroker_review_delete_pending",
    "octobroker_review_submit",
    "octobroker_commit_status_set",
];

const REVIEW_ARGS: &str = r#"{"owner":"openabdev","repo":"octobroker","node_id":"IC_kwDOtest","classifier":"OUTDATED","event":"COMMENT","sha":"f7c937837bfb02b248d86ef28ed4fd5dbd8d1a63","state":"failure","context":"OpenAB PR Review"}"#;

/// Phase 1 (network-trust, no agents): every broker-owned tool is a write
/// and must be denied locally — never proxied upstream where GitHub's MCP
/// server would not even recognize it.
#[test]
fn local_review_tools_denied_in_network_trust_mode() {
    let upstream = spawn_stub_upstream();
    let up = upstream.port;
    let config = format!(
        r#"port = {{PORT}}

[[identities]]
id = "local"
token = "fake-token"

[mcp]
enabled = true
upstream = "http://127.0.0.1:{up}/"
"#
    );
    let broker = spawn_broker(&config);

    for tool in LOCAL_REVIEW_TOOLS {
        let resp = broker.tools_call("", tool, REVIEW_ARGS);
        assert_denied(&resp, "local write tools", tool);
    }
    assert!(
        upstream.captured.lock().unwrap().is_empty(),
        "broker-owned tools must never reach the upstream MCP server"
    );
}

/// Agent mode with writes disabled: an authenticated agent that allowlists a
/// broker-owned tool still cannot invoke it — the write gate applies before
/// any local dispatch and the call is never forwarded upstream.
#[test]
fn local_review_tools_denied_when_writes_disabled() {
    let upstream = spawn_stub_upstream();
    let up = upstream.port;
    let tools: Vec<String> = LOCAL_REVIEW_TOOLS
        .iter()
        .map(|t| format!("\"{t}\""))
        .collect();
    let config = format!(
        r#"port = {{PORT}}

[[identities]]
id = "local"
token = "fake-token"

[mcp]
enabled = true
upstream = "http://127.0.0.1:{up}/"

[[mcp.agents]]
id = "bot"
keys = ["test-key"]
tools = ["issue_read", {tools_list}]
repos = ["openabdev/octobroker"]
"#,
        tools_list = tools.join(", ")
    );
    let broker = spawn_broker(&config);

    for tool in LOCAL_REVIEW_TOOLS {
        let resp = broker.tools_call("test-key", tool, REVIEW_ARGS);
        assert_denied(&resp, "write tools are not enabled", tool);
    }
    assert!(
        upstream.captured.lock().unwrap().is_empty(),
        "broker-owned tools must never reach the upstream MCP server"
    );
}

/// The agent tool allowlist is still authoritative for broker-owned tools:
/// an agent that does not name them cannot invoke them.
#[test]
fn local_review_tools_require_explicit_allowlist() {
    let upstream = spawn_stub_upstream();
    let up = upstream.port;
    let config = format!(
        r#"port = {{PORT}}

[[identities]]
id = "local"
token = "fake-token"

[mcp]
enabled = true
upstream = "http://127.0.0.1:{up}/"

[[mcp.agents]]
id = "bot"
keys = ["test-key"]
tools = ["issue_read"]
"#
    );
    let broker = spawn_broker(&config);

    for tool in LOCAL_REVIEW_TOOLS {
        let resp = broker.tools_call("test-key", tool, REVIEW_ARGS);
        assert_denied(&resp, "not permitted by agent policy", tool);
    }
    assert!(upstream.captured.lock().unwrap().is_empty());
}

/// Upstream GitHub MCP tools keep working unchanged: an ordinary tool call
/// is proxied and answered by the upstream server.
#[test]
fn upstream_tools_still_proxied() {
    let upstream = spawn_stub_upstream();
    let up = upstream.port;
    let config = format!(
        r#"port = {{PORT}}

[[identities]]
id = "local"
token = "fake-token"

[mcp]
enabled = true
upstream = "http://127.0.0.1:{up}/"
"#
    );
    let broker = spawn_broker(&config);

    let resp = broker.tools_call("", "get_me", "{}");
    assert_eq!(resp.0, 200, "upstream tool call failed: {resp:?}");
    assert!(
        resp.2.contains(r#""isError":false"#),
        "upstream tool call should succeed, got {}",
        resp.2
    );
    assert_eq!(upstream.captured.lock().unwrap().len(), 1);
}
