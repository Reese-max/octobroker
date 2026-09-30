//! Black-box tests for `require_protected_default_branch` (issue #49)
//! against the real `octobroker` binary.
//!
//! A `contents:write` App token can push to ANY ref in its repo — including
//! the default branch — so the ref-level boundary must come from GitHub
//! itself (rulesets / classic branch protection). With
//! `require_protected_default_branch = true`, /git-credential verifies the
//! target repo's default branch is protected BEFORE minting and denies the
//! credential when it is not (or when the status cannot be verified —
//! fail-closed). With the flag off, issuance is unchanged and no repo
//! metadata reads happen at all.
//!
//! A stub api.github.com serves installation/token/repo/branch endpoints and
//! records every mint body; the binary under test is pointed at it via
//! OCTOBROKER_GITHUB_API_BASE.

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

fn json_response(status: u16, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

/// Stub api.github.com. Routes served:
///   GET  /app/installations/41                 → installation record
///   POST /app/installations/41/access_tokens   → token (body recorded)
///   GET  /repos/openabdev/<repo>               → repo metadata
///        ("shaky" → 500, "emptyrepo" → no default_branch)
///   GET  /repos/openabdev/<repo>/branches/<b>  → branch record
///        ("prot" → protected:true, others → protected:false)
struct StubGithub {
    port: u16,
    /// Bodies of POST /app/installations/41/access_tokens (every mint).
    mints: Arc<Mutex<Vec<String>>>,
    /// Paths of GET /repos/… metadata reads (the protection check).
    repo_reads: Arc<Mutex<Vec<String>>>,
}

fn spawn_stub_github() -> StubGithub {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let mints: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let repo_reads: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let mints2 = mints.clone();
    let repo_reads2 = repo_reads.clone();
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
            let mut request_line = head.lines().next().unwrap_or_default().split_whitespace();
            let method = request_line.next().unwrap_or_default().to_string();
            let path = request_line.next().unwrap_or_default().to_string();
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
            let body = String::from_utf8_lossy(&body).into_owned();

            let resp = if method == "GET" && path == "/app/installations/41" {
                json_response(200, r#"{"id":41,"account":{"login":"openabdev"}}"#)
            } else if method == "POST" && path == "/app/installations/41/access_tokens" {
                mints2.lock().unwrap().push(body.clone());
                json_response(
                    201,
                    r#"{"token":"ghs_test_token","expires_at":"2099-01-01T00:00:00Z"}"#,
                )
            } else if method == "GET" && path.starts_with("/repos/") {
                repo_reads2.lock().unwrap().push(path.clone());
                // /repos/openabdev/<repo>[/branches/<branch>]
                let segs: Vec<&str> = path.trim_start_matches("/repos/").split('/').collect();
                let repo = segs.get(1).copied().unwrap_or_default();
                if repo == "shaky" {
                    json_response(500, r#"{"message":"boom"}"#)
                } else if segs.len() == 2 {
                    // repo metadata
                    if repo == "emptyrepo" {
                        json_response(200, r#"{"name":"emptyrepo","default_branch":null}"#)
                    } else {
                        json_response(200, r#"{"default_branch":"main"}"#)
                    }
                } else if segs.len() == 4 && segs[2] == "branches" {
                    // branch record: only "prot" is protected
                    json_response(
                        200,
                        &format!(r#"{{"name":"{}","protected":{}}}"#, segs[3], repo == "prot"),
                    )
                } else {
                    json_response(404, r#"{"message":"not found"}"#)
                }
            } else {
                json_response(404, r#"{"message":"not found"}"#)
            };
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    StubGithub {
        port,
        mints,
        repo_reads,
    }
}

/// A spawned `octobroker` server under test. Killed and cleaned up on drop.
struct Broker {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Broker {
    /// GET /git-credential?repo=<repo> with the given agent key.
    fn git_credential(&self, key: &str, repo: &str) -> HttpResponse {
        http(
            self.port,
            "GET",
            &format!("/git-credential?repo={repo}"),
            &[("x-octobroker-key", key)],
            "",
        )
        .expect("GET /git-credential")
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn test_pem() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/test-app-key.pem"
    ))
    .unwrap()
}

fn broker_config(dir: &Path, port: u16, require_protected: bool, read_only: bool) -> String {
    let flag = if require_protected {
        "require_protected_default_branch = true\n"
    } else {
        ""
    };
    let ro = if read_only {
        "git_credentials_read_only = true\n"
    } else {
        ""
    };
    format!(
        r#"port = {port}

[mcp]
enable_git_credentials = true
{flag}{ro}
[mcp.audit]
path = "{audit}"

[mcp.github_app]
app_id = "111"
private_key = '''
{pem}'''
owner = "openabdev"
installation_id = 41

[[mcp.agents]]
id = "b0"
keys = ["key-b0"]
repos = ["openabdev/prot", "openabdev/unprot", "openabdev/shaky", "openabdev/emptyrepo"]
"#,
        port = port,
        flag = flag,
        audit = dir.join("audit.jsonl").display(),
        pem = test_pem(),
    )
}

fn spawn_broker(config: &str, github_api_base: &str) -> Broker {
    let dir = std::env::temp_dir().join(format!(
        "octobroker-prot-it-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("config.toml"), config).unwrap();
    let log_path = dir.join("server.log");
    let child = Command::new(env!("CARGO_BIN_EXE_octobroker"))
        .env_clear()
        .env("OCTOBROKER_CONFIG", dir.join("config.toml"))
        .env("OCTOBROKER_GITHUB_API_BASE", github_api_base)
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

/// Read the spawned server's audit JSONL (one JSON object per line).
fn audit_records(dir: &Path) -> Vec<serde_json::Value> {
    let path = dir.join("audit.jsonl");
    std::fs::read_to_string(&path)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn protected_default_branch_allows_issuance() {
    let gh = spawn_stub_github();
    let port = free_port();
    let dir = std::env::temp_dir().join(format!(
        "octobroker-prot-cfg-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let config = broker_config(&dir, port, true, false);
    let broker = spawn_broker(&config, &format!("http://127.0.0.1:{}", gh.port));

    let (status, _h, body) = broker.git_credential("key-b0", "openabdev/prot");
    assert_eq!(status, 200, "protected default branch must issue: {body}");
    assert!(body.contains(r#""username":"x-access-token""#), "{body}");
    assert!(body.contains("ghs_test_token"), "{body}");

    // The check itself rides a repo-scoped contents:read token; the issued
    // credential is contents:write — two mints, in that order.
    let mints = gh.mints.lock().unwrap();
    assert_eq!(
        mints.len(),
        2,
        "expected check + credential mints: {mints:?}"
    );
    assert!(
        mints[0].contains(r#""contents":"read""#),
        "check mint: {}",
        mints[0]
    );
    assert!(
        mints[1].contains(r#""contents":"write""#),
        "cred mint: {}",
        mints[1]
    );
    drop(mints);

    // And the repo/branch metadata reads happened.
    let reads = gh.repo_reads.lock().unwrap();
    assert!(
        reads
            .iter()
            .any(|p| p == "/repos/openabdev/prot/branches/main"),
        "branch protection read missing: {reads:?}"
    );
    drop(reads);

    let records = audit_records(&dir);
    assert_eq!(records.len(), 2, "preflight + result: {records:?}");
    assert_eq!(records[1]["success"], true);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn unprotected_default_branch_denied() {
    let gh = spawn_stub_github();
    let port = free_port();
    let dir = std::env::temp_dir().join(format!(
        "octobroker-prot-cfg-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let config = broker_config(&dir, port, true, false);
    let broker = spawn_broker(&config, &format!("http://127.0.0.1:{}", gh.port));

    let (status, _h, body) = broker.git_credential("key-b0", "openabdev/unprot");
    assert_eq!(status, 403, "unprotected default branch must deny: {body}");
    assert!(
        body.contains("protected"),
        "denial should name the reason, got {body}"
    );

    // Only the contents:read check token was minted — never the credential.
    let mints = gh.mints.lock().unwrap();
    assert_eq!(mints.len(), 1, "no credential mint expected: {mints:?}");
    assert!(mints[0].contains(r#""contents":"read""#), "{}", mints[0]);
    drop(mints);

    let records = audit_records(&dir);
    assert_eq!(records.len(), 2, "preflight + failed result: {records:?}");
    assert_eq!(records[1]["success"], false);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn unverifiable_protection_denied_fail_closed() {
    let gh = spawn_stub_github();
    let port = free_port();
    let dir = std::env::temp_dir().join(format!(
        "octobroker-prot-cfg-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let config = broker_config(&dir, port, true, false);
    let broker = spawn_broker(&config, &format!("http://127.0.0.1:{}", gh.port));

    // Repo metadata read fails → cannot verify → deny (not 200, not silent).
    let (status, _h, body) = broker.git_credential("key-b0", "openabdev/shaky");
    assert!(
        status == 502 || status == 403,
        "unverifiable status must deny, got {status}: {body}"
    );

    // A repo with no default branch at all → deny as well.
    let (status, _h, body) = broker.git_credential("key-b0", "openabdev/emptyrepo");
    assert!(
        status == 502 || status == 403,
        "missing default branch must deny, got {status}: {body}"
    );

    // Every denial is audited: two requests → preflight + failed result each.
    let records = audit_records(&dir);
    assert_eq!(
        records.len(),
        4,
        "preflight + result per request: {records:?}"
    );
    let results: Vec<&serde_json::Value> = records
        .iter()
        .filter(|r| r["phase"] == "git_credential_result")
        .collect();
    assert_eq!(results.len(), 2, "both denials must record a result");
    assert!(
        results.iter().all(|r| r["success"] == false),
        "no success results allowed: {records:?}"
    );

    // Deny-before-mint: the stub saw only the contents:read check tokens —
    // never a contents:write credential mint.
    let mints = gh.mints.lock().unwrap();
    assert!(
        !mints.is_empty() && mints.iter().all(|b| b.contains(r#""contents":"read""#)),
        "only read-scoped check mints expected: {mints:?}"
    );
    drop(mints);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn flag_off_leaves_issuance_unchanged() {
    let gh = spawn_stub_github();
    let port = free_port();
    let dir = std::env::temp_dir().join(format!(
        "octobroker-prot-cfg-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    // Flag absent: unprotected repo issues normally and NO metadata reads
    // are made — the default path makes zero extra GitHub calls.
    let config = broker_config(&dir, port, false, false);
    let broker = spawn_broker(&config, &format!("http://127.0.0.1:{}", gh.port));

    let (status, _h, body) = broker.git_credential("key-b0", "openabdev/unprot");
    assert_eq!(status, 200, "flag off must not change issuance: {body}");
    assert!(
        gh.repo_reads.lock().unwrap().is_empty(),
        "no repo metadata reads when the flag is off: {:?}",
        gh.repo_reads.lock().unwrap()
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn read_only_mode_skips_protection_check() {
    let gh = spawn_stub_github();
    let port = free_port();
    let dir = std::env::temp_dir().join(format!(
        "octobroker-prot-cfg-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    // Flag ON + fleet read-only: an unprotected repo still issues — a
    // contents:read token cannot push to any ref, so the check is skipped.
    let config = broker_config(&dir, port, true, true);
    let broker = spawn_broker(&config, &format!("http://127.0.0.1:{}", gh.port));

    let (status, _h, body) = broker.git_credential("key-b0", "openabdev/unprot");
    assert_eq!(
        status, 200,
        "read-only issuance must not be gated by push policy: {body}"
    );
    assert!(
        gh.repo_reads.lock().unwrap().is_empty(),
        "no repo metadata reads for read-only issuance: {:?}",
        gh.repo_reads.lock().unwrap()
    );
    let mints = gh.mints.lock().unwrap();
    assert!(
        !mints.is_empty() && mints.iter().all(|b| b.contains(r#""contents":"read""#)),
        "read-only fleet mints only read tokens: {mints:?}"
    );
    drop(mints);
    std::fs::remove_dir_all(&dir).ok();
}
