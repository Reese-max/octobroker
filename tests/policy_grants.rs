//! Black-box policy-v2 (grant-based per-repo tool permissions, #35) tests
//! against the real `octobroker` binary. A stub upstream MCP endpoint records
//! requests and answers every JSON-RPC frame; policy decisions are observed
//! on the wire — denials surface as `result.isError: true` tool errors and
//! must never reach the stub.

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

#[derive(Clone)]
struct CapturedRequest {
    tools_hdr: Option<String>,
    body: String,
}

/// Stub upstream MCP endpoint: records (x-mcp-tools, body) per request and
/// answers every JSON-RPC frame with a fixed successful tool result.
struct StubUpstream {
    port: u16,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
}

fn spawn_stub_upstream() -> StubUpstream {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let captured: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
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
            let headers: Vec<(String, String)> = head
                .lines()
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string()))
                .collect();
            let clen: usize = headers
                .iter()
                .find(|(k, _)| k == "content-length")
                .and_then(|(_, v)| v.parse().ok())
                .unwrap_or(0);
            let mut body = buf[header_end + 4..].to_vec();
            while body.len() < clen {
                match stream.read(&mut tmp) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => body.extend_from_slice(&tmp[..n]),
                }
            }
            captured2.lock().unwrap().push(CapturedRequest {
                tools_hdr: headers
                    .iter()
                    .find(|(k, _)| k == "x-mcp-tools")
                    .map(|(_, v)| v.clone()),
                body: String::from_utf8_lossy(&body).into_owned(),
            });
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
    /// POST one JSON-RPC frame to /mcp with the given agent key.
    fn mcp(&self, key: &str, frame: &str) -> HttpResponse {
        http(
            self.port,
            "POST",
            "/mcp",
            &[("x-octobroker-key", key)],
            frame,
        )
        .expect("POST /mcp")
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

fn spawn_broker(config: &str) -> Broker {
    let dir = std::env::temp_dir().join(format!(
        "octobroker-grants-it-{}-{}",
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

fn assert_allowed(resp: &HttpResponse, ctx: &str) {
    assert_eq!(resp.0, 200, "{ctx}: expected HTTP 200, got {resp:?}");
    assert!(
        resp.2.contains(r#""isError":false"#),
        "{ctx}: call should have been forwarded upstream, got {}",
        resp.2
    );
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

/// The headline scenario from #35: an agent that is read-only on repo-A but
/// can use a different tool set on repo-B, plus a repo-unrestricted grant.
#[test]
fn grant_based_per_repo_tool_policy() {
    let upstream = spawn_stub_upstream();
    let port = free_port();
    let up = upstream.port;
    let config = format!(
        r#"port = {port}

[[identities]]
id = "local"
token = "fake-token"

[mcp]
enabled = true
upstream = "http://127.0.0.1:{up}/"

[[mcp.agents]]
id = "bot"
keys = ["test-key"]

[[mcp.agents.grants]]
repos = ["openabdev/repo-a"]
tools = ["issue_read"]

[[mcp.agents.grants]]
repos = ["oablab/repo-b"]
tools = ["pull_request_read", "list_issues"]

[[mcp.agents.grants]]
repos = []
tools = ["get_me"]

[[mcp.agents]]
id = "flat-bot"
keys = ["flat-key"]
tools = ["issue_read"]
repos = ["openabdev/repo-a"]
"#
    );
    let broker = spawn_broker(&config);

    // grant 1 allows issue_read on openabdev/repo-a
    let resp = broker.tools_call(
        "test-key",
        "issue_read",
        r#"{"owner":"openabdev","repo":"repo-a","issue_number":1}"#,
    );
    assert_allowed(&resp, "issue_read@repo-a");
    {
        let hits = upstream.captured.lock().unwrap();
        assert_eq!(hits.len(), 1, "allowed call must reach upstream");
        // X-MCP-Tools is the UNION of all granted tools (design wrinkle 1).
        assert_eq!(
            hits[0].tools_hdr.as_deref(),
            Some("issue_read,pull_request_read,list_issues,get_me"),
            "upstream must see the union of granted tools"
        );
        assert!(
            hits[0].body.contains("\"issue_read\""),
            "upstream must receive the original tool call, got {}",
            hits[0].body
        );
    }

    // Same tool, different repo: grant 1 covers the tool but not repo-b,
    // and grant 2 doesn't carry issue_read at all → repo-axis denial.
    let resp = broker.tools_call(
        "test-key",
        "issue_read",
        r#"{"owner":"oablab","repo":"repo-b","issue_number":2}"#,
    );
    assert_denied(&resp, "repository not permitted", "issue_read@repo-b");

    // grant 2 tool on grant 1's repo → repo-axis denial.
    let resp = broker.tools_call(
        "test-key",
        "pull_request_read",
        r#"{"owner":"openabdev","repo":"repo-a","pull_number":3}"#,
    );
    assert_denied(
        &resp,
        "repository not permitted",
        "pull_request_read@repo-a",
    );

    // grant 2 tool on grant 2's repo → allowed.
    let resp = broker.tools_call(
        "test-key",
        "pull_request_read",
        r#"{"owner":"oablab","repo":"repo-b","pull_number":3}"#,
    );
    assert_allowed(&resp, "pull_request_read@repo-b");

    // Deny-if-unresolvable generalizes: every grant carrying list_issues is
    // repo-restricted, so a call with no repo target matches nothing.
    let resp = broker.tools_call("test-key", "list_issues", r#"{"query":"x"}"#);
    assert_denied(
        &resp,
        "no resolvable repository",
        "list_issues unresolvable",
    );

    // A repo-unrestricted grant matches even when no repo resolves.
    let resp = broker.tools_call("test-key", "get_me", r#"{}"#);
    assert_allowed(&resp, "get_me via repo-less grant");

    // A tool present in no grant → default-deny on the tool axis.
    let resp = broker.tools_call(
        "test-key",
        "delete_file",
        r#"{"owner":"openabdev","repo":"repo-a"}"#,
    );
    assert_denied(&resp, "tool not permitted", "delete_file");

    // Exactly the allowed calls reached upstream: grant1 + grant2 + repo-less.
    assert_eq!(
        upstream.captured.lock().unwrap().len(),
        3,
        "denied calls must never reach upstream"
    );

    // Flat tools+repos remain sugar for a single grant (backward compat).
    let resp = broker.tools_call(
        "flat-key",
        "issue_read",
        r#"{"owner":"openabdev","repo":"repo-a","issue_number":1}"#,
    );
    assert_allowed(&resp, "flat sugar allow");
    let resp = broker.tools_call(
        "flat-key",
        "issue_read",
        r#"{"owner":"oablab","repo":"repo-b","issue_number":1}"#,
    );
    assert_denied(&resp, "repository not permitted", "flat sugar deny");
}
