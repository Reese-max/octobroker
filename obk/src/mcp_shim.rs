//! `obk mcp` — MCP stdio shim (Phase 3, #18).
//!
//! Bridges a local MCP client (Claude Code, Codex, …) speaking newline-
//! delimited JSON-RPC on stdio to octobroker's `POST /mcp` endpoint. The
//! agent never sees a GitHub credential; authentication is either a shared
//! `OCTOBROKER_KEY` or a secretless presigned `sts:GetCallerIdentity` proof
//! built from ambient AWS credentials (env / ECS task role / EKS IRSA /
//! instance metadata — whatever `aws-config`'s default chain resolves).
//!
//! Behaviors per RFC:
//! - `Mcp-Session-Id` tracking; on 404 (expired/evicted session) the shim
//!   replays `initialize` + `notifications/initialized` and resends the
//!   original frame once — transparent re-init.
//! - `Retry-After` honored on 429/503; bounded exponential backoff
//!   (250ms → 4s, ≤3 retries) for idempotent methods only.
//! - `tools/call` is NEVER retried: it may be a non-idempotent write.
//! - Responses stream back as NDJSON: `application/json` bodies pass
//!   through; `text/event-stream` bodies are unwrapped to their `data:`
//!   payloads. Diagnostics go to stderr only.

use serde_json::Value;
use std::io::{BufRead, Write};
use std::time::{Duration, SystemTime};

/// Method names the shim may retry (read/lifecycle/notifications).
/// `tools/call` and anything unlisted are single-shot — they may carry
/// non-idempotent side effects upstream.
fn is_retryable(method: Option<&str>) -> bool {
    match method {
        Some(m) if m.starts_with("notifications/") => true,
        Some(
            "initialize"
            | "ping"
            | "tools/list"
            | "resources/list"
            | "resources/read"
            | "resources/templates/list"
            | "prompts/list"
            | "prompts/get"
            | "completion/complete"
            | "logging/setLevel"
            | "roots/list",
        ) => true,
        _ => false,
    }
}

/// Retry wait: server `Retry-After` (seconds, capped at 60) wins; otherwise
/// bounded exponential backoff 250ms → 4s.
fn retry_wait(attempt: u32, retry_after: Option<u64>) -> Duration {
    if let Some(secs) = retry_after {
        return Duration::from_secs(secs.min(60));
    }
    let ms = 250u64.saturating_mul(1u64 << attempt.min(4));
    Duration::from_millis(ms.min(4000))
}

/// Minimal JSON-RPC frame introspection — the raw line is forwarded
/// verbatim; we only need id/method to drive shim behavior.
#[derive(Debug, Default)]
struct Frame {
    id: Option<Value>,
    method: Option<String>,
}

fn parse_frame(line: &str) -> Frame {
    let Ok(v) = serde_json::from_str::<Value>(line) else {
        return Frame::default();
    };
    let id = match v.get("id") {
        Some(Value::Null) | None => None,
        Some(v) => Some(v.clone()),
    };
    let method = v
        .get("method")
        .and_then(|m| m.as_str())
        .map(str::to_string);
    Frame { id, method }
}

/// One upstream response, body as a readable stream.
pub struct UpstreamResp {
    pub status: u16,
    pub session_id: Option<String>,
    pub content_type: String,
    pub retry_after: Option<u64>,
    pub body: Box<dyn BufRead + Send>,
}

/// HTTP seam — the real impl POSTs to octobroker; tests script responses.
pub trait Transport {
    fn post(&self, headers: &[(String, String)], body: &str) -> Result<UpstreamResp, String>;
    fn delete(&self, headers: &[(String, String)]) -> Result<u16, String>;
}

/// How the shim authenticates to octobroker.
pub enum Auth {
    /// `X-Octobroker-Key` shared key.
    Key(String),
    /// `X-Octobroker-Iam` presigned sts:GetCallerIdentity URL — re-signed
    /// per request (cheap, ~50µs) so proofs never approach expiry mid-call.
    Iam { creds: crate::sigv4::AwsCredentials, region: String },
}

impl Auth {
    fn header(&self) -> (String, String) {
        match self {
            Auth::Key(k) => ("x-octobroker-key".to_string(), k.clone()),
            Auth::Iam { creds, region } => (
                "x-octobroker-iam".to_string(),
                crate::sigv4::presign_get_caller_identity(creds, region, 60, SystemTime::now()),
            ),
        }
    }
}

/// Stateful shim: session id, negotiated protocol version, replayable
/// initialize frame, retry config.
pub struct Shim<'a> {
    transport: &'a dyn Transport,
    auth: Auth,
    session_id: Option<String>,
    protocol_version: Option<String>,
    init_frame: Option<String>,
    max_retries: u32,
    sleeper: &'a dyn Fn(Duration),
}

impl<'a> Shim<'a> {
    pub fn new(
        transport: &'a dyn Transport,
        auth: Auth,
        max_retries: u32,
        sleeper: &'a dyn Fn(Duration),
    ) -> Self {
        Self {
            transport,
            auth,
            session_id: None,
            protocol_version: None,
            init_frame: None,
            max_retries,
            sleeper,
        }
    }

    fn headers(&self) -> Vec<(String, String)> {
        let mut h = vec![
            ("content-type".to_string(), "application/json".to_string()),
            (
                "accept".to_string(),
                "application/json, text/event-stream".to_string(),
            ),
            self.auth.header(),
        ];
        if let Some(sid) = &self.session_id {
            h.push(("mcp-session-id".to_string(), sid.clone()));
        }
        if let Some(pv) = &self.protocol_version {
            h.push(("mcp-protocol-version".to_string(), pv.clone()));
        }
        h
    }

    /// Pump stdin lines → upstream POSTs → stdout lines until EOF, then a
    /// best-effort DELETE to release the upstream session.
    pub fn pump<R: BufRead, W: Write>(&mut self, input: R, out: &mut W) {
        for line in input.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            if line.trim().is_empty() {
                continue;
            }
            let frame = parse_frame(&line);
            if frame.method.as_deref() == Some("initialize") {
                self.init_frame = Some(line.clone());
            }
            self.handle(&line, frame, out);
        }
        if self.session_id.is_some() {
            let _ = self.transport.delete(&self.headers());
        }
    }

    /// One client frame: bounded retries for idempotent methods, session
    /// re-init on 404, response streaming to stdout.
    fn handle<W: Write>(&mut self, line: &str, frame: Frame, out: &mut W) {
        let retryable = is_retryable(frame.method.as_deref());
        let mut attempt = 0u32;
        let mut reinitialized = false;
        loop {
            let resp = match self.transport.post(&self.headers(), line) {
                Ok(r) => r,
                Err(e) => {
                    if retryable && attempt < self.max_retries {
                        attempt += 1;
                        (self.sleeper)(retry_wait(attempt, None));
                        continue;
                    }
                    return self.fail(&frame, out, &format!("upstream unreachable: {}", e));
                }
            };
            match resp.status {
                429 | 503 if retryable && attempt < self.max_retries => {
                    attempt += 1;
                    (self.sleeper)(retry_wait(attempt, resp.retry_after));
                    continue;
                }
                404 if self.session_id.is_some() && !reinitialized => {
                    // Session expired/evicted server-side: replay
                    // initialize + initialized, then resend the frame once.
                    self.session_id = None;
                    reinitialized = true;
                    match self.reinit(out) {
                        Ok(()) => continue,
                        Err(e) => return self.fail(&frame, out, &e),
                    }
                }
                _ => {
                    self.emit(resp, &frame, out);
                    return;
                }
            }
        }
    }

    /// Replay `initialize` (fresh session + protocol version), then the
    /// `notifications/initialized` handshake. Returns Err when the replay
    /// itself fails.
    fn reinit<W: Write>(&mut self, out: &mut W) -> Result<(), String> {
        let init = self
            .init_frame
            .clone()
            .ok_or_else(|| "session lost before initialize".to_string())?;
        let frame = parse_frame(&init);
        let mut attempt = 0u32;
        let resp = loop {
            match self.transport.post(&self.headers(), &init) {
                Ok(r) => break r,
                Err(e) => {
                    if attempt < self.max_retries {
                        attempt += 1;
                        (self.sleeper)(retry_wait(attempt, None));
                    } else {
                        return Err(format!("session re-init failed: {}", e));
                    }
                }
            }
        };
        if !matches!(resp.status, 200) {
            return Err(format!("session re-init rejected (HTTP {})", resp.status));
        }
        self.emit(resp, &frame, out);
        let initialized =
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_string();
        let _ = self.transport.post(&self.headers(), &initialized);
        Ok(())
    }

    /// Forward an upstream response to the client: capture session headers,
    /// stream `data:` payloads (or the JSON body) as NDJSON. Error statuses
    /// become JSON-RPC errors for requests; notifications stay silent.
    fn emit<W: Write>(&mut self, mut resp: UpstreamResp, frame: &Frame, out: &mut W) {
        if let Some(sid) = resp.session_id {
            self.session_id = Some(sid);
        }
        if !matches!(resp.status, 200 | 202) {
            let mut body = String::new();
            use std::io::Read as _;
            let _ = (&mut resp.body).take(2048).read_to_string(&mut body);
            return self.fail(
                frame,
                out,
                &format!("upstream HTTP {}: {}", resp.status, body.trim()),
            );
        }
        if resp.content_type.contains("text/event-stream") {
            self.emit_sse(resp.body, frame, out);
        } else {
            let mut body = String::new();
            if resp.body.read_to_string(&mut body).is_ok() {
                let trimmed = body.trim();
                if !trimmed.is_empty() {
                    self.capture_protocol_version(trimmed, frame);
                    let _ = out.write_all(trimmed.as_bytes());
                    let _ = out.write_all(b"\n");
                    let _ = out.flush();
                }
            }
        }
    }

    /// Stream an SSE body: each event's `data:` payload becomes one stdout
    /// line (multi-line `data:` is joined). For a request with an id, stop
    /// after the matching terminal response arrives — resumable upstream
    /// streams may stay open.
    fn emit_sse<W: Write>(&mut self, mut body: Box<dyn BufRead + Send>, frame: &Frame, out: &mut W) {
        let mut data_lines: Vec<String> = Vec::new();
        loop {
            let mut line = String::new();
            match body.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                // Event boundary: flush accumulated data payload.
                if !data_lines.is_empty() {
                    let payload = data_lines.join("\n");
                    data_lines.clear();
                    self.capture_protocol_version(&payload, frame);
                    let _ = out.write_all(payload.as_bytes());
                    let _ = out.write_all(b"\n");
                    let _ = out.flush();
                    if self.is_terminal_response(&payload, frame) {
                        return;
                    }
                }
                continue;
            }
            if let Some(data) = trimmed.strip_prefix("data:") {
                data_lines.push(data.trim().to_string());
            }
            // event:/id:/retry:/comments ignored — shim output is NDJSON.
        }
        if !data_lines.is_empty() {
            let payload = data_lines.join("\n");
            self.capture_protocol_version(&payload, frame);
            let _ = out.write_all(payload.as_bytes());
            let _ = out.write_all(b"\n");
            let _ = out.flush();
        }
    }

    /// After initialize, the negotiated `result.protocolVersion` is sent on
    /// subsequent requests per the MCP Streamable HTTP spec.
    fn capture_protocol_version(&mut self, payload: &str, frame: &Frame) {
        if frame.method.as_deref() != Some("initialize") {
            return;
        }
        if let Ok(v) = serde_json::from_str::<Value>(payload) {
            if let Some(pv) = v
                .get("result")
                .and_then(|r| r.get("protocolVersion"))
                .and_then(|p| p.as_str())
            {
                self.protocol_version = Some(pv.to_string());
            }
        }
    }

    /// A JSON-RPC payload that carries a `result`/`error` for this frame's
    /// id — the terminal answer for a request on a possibly-open stream.
    fn is_terminal_response(&self, payload: &str, frame: &Frame) -> bool {
        let Some(id) = &frame.id else { return false };
        let Ok(v) = serde_json::from_str::<Value>(payload) else {
            return false;
        };
        v.get("id") == Some(id) && (v.get("result").is_some() || v.get("error").is_some())
    }

    /// Surface a failure to the client: JSON-RPC error for requests,
    /// stderr-only for notifications (they have no response channel).
    fn fail<W: Write>(&self, frame: &Frame, out: &mut W, message: &str) {
        match &frame.id {
            Some(id) => {
                let body = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32000, "message": format!("octobroker shim: {}", message) },
                });
                let _ = out.write_all(body.to_string().as_bytes());
                let _ = out.write_all(b"\n");
                let _ = out.flush();
            }
            None => eprintln!("obk mcp: {}", message),
        }
    }
}

// --- wiring: real transport, auth resolution, entry point ---

struct HttpTransport {
    client: reqwest::blocking::Client,
    url: String,
}

impl Transport for HttpTransport {
    fn post(&self, headers: &[(String, String)], body: &str) -> Result<UpstreamResp, String> {
        let mut req = self.client.post(&self.url).body(body.to_string());
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let resp = req.send().map_err(|e| e.to_string())?;
        let get = |n: &str| {
            resp.headers()
                .get(n)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        Ok(UpstreamResp {
            status: resp.status().as_u16(),
            session_id: get("mcp-session-id"),
            content_type: get("content-type").unwrap_or_default(),
            retry_after: get("retry-after").and_then(|v| v.trim().parse::<u64>().ok()),
            body: Box::new(std::io::BufReader::new(resp)),
        })
    }

    fn delete(&self, headers: &[(String, String)]) -> Result<u16, String> {
        let mut req = self.client.delete(&self.url);
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        req.timeout(Duration::from_secs(10))
            .send()
            .map(|r| r.status().as_u16())
            .map_err(|e| e.to_string())
    }
}

/// Resolve ambient AWS credentials through the default provider chain:
/// env vars → ECS task role → EKS IRSA → instance metadata. Returns
/// (credentials, signing-region); empty region = global STS endpoint.
fn ambient_aws() -> Option<(crate::sigv4::AwsCredentials, String)> {
    use aws_credential_types::provider::ProvideCredentials;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    let config = rt.block_on(aws_config::load_defaults(aws_config::BehaviorVersion::latest()));
    let region = config
        .region()
        .map(|r| r.to_string())
        .unwrap_or_default();
    let provider = config.credentials_provider()?;
    let creds = rt.block_on(provider.provide_credentials()).ok()?;
    Some((
        crate::sigv4::AwsCredentials {
            access_key_id: creds.access_key_id().to_string(),
            secret_access_key: creds.secret_access_key().to_string(),
            session_token: creds.session_token().map(str::to_string),
        },
        region,
    ))
}

fn is_loopback(url: &str) -> bool {
    let host = url
        .split("://")
        .nth(1)
        .unwrap_or(url)
        .split(['/', ':'])
        .next()
        .unwrap_or("");
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// `obk mcp` entry point. Exit 0 = clean EOF on stdin.
pub fn run(base: &str) -> i32 {
    let timeout_secs: u64 = std::env::var("OBK_MCP_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(150);
    let max_retries: u32 = std::env::var("OBK_MCP_MAX_RETRIES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);

    let auth = match std::env::var("OCTOBROKER_KEY") {
        Ok(k) if !k.is_empty() => Auth::Key(k),
        _ => match ambient_aws() {
            Some((creds, region)) => Auth::Iam { creds, region },
            None => {
                eprintln!(
                    "obk mcp: no credentials — set OCTOBROKER_KEY or provide AWS credentials \
                     (env, ECS task role, EKS IRSA, instance metadata)"
                );
                return 1;
            }
        },
    };
    // A presigned identity proof replayed over plaintext is replayable by any
    // network observer within its lifetime. Require TLS unless the broker is
    // on-loopback; shared-key auth on http stays allowed for parity with the
    // existing gh/git shims.
    if matches!(auth, Auth::Iam { .. }) && !base.starts_with("https://") && !is_loopback(base) {
        eprintln!("obk mcp: OCTOBROKER_URL must be https for IAM authentication (got {})", base);
        return 1;
    }

    let transport = HttpTransport {
        client: reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new()),
        url: format!("{}/mcp", base.trim_end_matches('/')),
    };
    let sleep = |d: Duration| std::thread::sleep(d);
    let mut shim = Shim::new(&transport, auth, max_retries, &sleep);
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    shim.pump(stdin.lock(), &mut stdout.lock());
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    type Headers = Vec<(String, String)>;

    /// Scripted upstream: queued responses + a call log for assertions.
    struct FakeTransport {
        responses: Mutex<VecDeque<Result<UpstreamResp, String>>>,
        calls: Mutex<Vec<(Headers, String)>>,
        deletes: Mutex<Vec<Headers>>,
    }

    impl FakeTransport {
        fn new(responses: Vec<Result<UpstreamResp, String>>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                calls: Mutex::new(Vec::new()),
                deletes: Mutex::new(Vec::new()),
            }
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().iter().map(|(_, b)| b.clone()).collect()
        }
        fn last_headers(&self) -> Headers {
            self.calls.lock().unwrap().last().unwrap().0.clone()
        }
        fn header(&self, n: &str) -> Option<String> {
            self.last_headers()
                .into_iter()
                .find(|(k, _)| k == n)
                .map(|(_, v)| v)
        }
    }

    impl Transport for FakeTransport {
        fn post(&self, headers: &[(String, String)], body: &str) -> Result<UpstreamResp, String> {
            self.calls
                .lock()
                .unwrap()
                .push((headers.to_vec(), body.to_string()));
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err("no scripted response".into()))
        }
        fn delete(&self, headers: &[(String, String)]) -> Result<u16, String> {
            self.deletes.lock().unwrap().push(headers.to_vec());
            Ok(200)
        }
    }

    fn json_resp(status: u16, body: &str) -> Result<UpstreamResp, String> {
        Ok(UpstreamResp {
            status,
            session_id: None,
            content_type: "application/json".to_string(),
            retry_after: None,
            body: Box::new(std::io::BufReader::new(std::io::Cursor::new(
                body.as_bytes().to_vec(),
            ))),
        })
    }

    fn json_resp_session(status: u16, sid: &str, body: &str) -> Result<UpstreamResp, String> {
        Ok(UpstreamResp {
            status,
            session_id: Some(sid.to_string()),
            content_type: "application/json".to_string(),
            retry_after: None,
            body: Box::new(std::io::BufReader::new(std::io::Cursor::new(
                body.as_bytes().to_vec(),
            ))),
        })
    }

    fn sse_resp(status: u16, body: &str) -> Result<UpstreamResp, String> {
        Ok(UpstreamResp {
            status,
            session_id: None,
            content_type: "text/event-stream".to_string(),
            retry_after: None,
            body: Box::new(std::io::BufReader::new(std::io::Cursor::new(
                body.as_bytes().to_vec(),
            ))),
        })
    }

    fn key_auth() -> Auth {
        Auth::Key("test-key".to_string())
    }

    fn no_sleep(_: Duration) {}

    fn pump_input<'a>(input: &str, t: &'a FakeTransport) -> (Vec<u8>, Shim<'a>) {
        let mut shim = Shim::new(t, key_auth(), 3, &no_sleep);
        let mut out = Vec::new();
        shim.pump(std::io::BufReader::new(input.as_bytes()), &mut out);
        (out, shim)
    }

    const INIT: &str = r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}"#;

    #[test]
    fn test_forwards_frame_and_streams_json() {
        let t = FakeTransport::new(vec![json_resp(
            200,
            r#"{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-06-18"}}"#,
        )]);
        let (out, _shim) = pump_input(&format!("{}\n", INIT), &t);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(r#""protocolVersion":"2025-06-18""#), "{}", text);
        assert_eq!(t.calls().len(), 1);
        assert_eq!(t.header("x-octobroker-key").as_deref(), Some("test-key"));
    }

    #[test]
    fn test_captures_session_and_protocol_version() {
        let t = FakeTransport::new(vec![
            json_resp_session(
                200,
                "sess-1",
                r#"{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-06-18"}}"#,
            ),
            json_resp(200, r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#),
        ]);
        let input = format!("{}\n{}\n", INIT, r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
        let (_out, shim) = pump_input(&input, &t);
        assert_eq!(shim.session_id.as_deref(), Some("sess-1"));
        assert_eq!(shim.protocol_version.as_deref(), Some("2025-06-18"));
        // Second request carried session + protocol headers
        assert_eq!(t.header("mcp-session-id").as_deref(), Some("sess-1"));
        assert_eq!(t.header("mcp-protocol-version").as_deref(), Some("2025-06-18"));
        // DELETE on EOF released the session
        assert_eq!(t.deletes.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_sse_body_streams_data_lines() {
        let sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n\n";
        let t = FakeTransport::new(vec![sse_resp(200, sse)]);
        let (out, _) = pump_input(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.to_string().as_str(),
            &t,
        );
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text.trim(),
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#
        );
    }

    #[test]
    fn test_sse_stops_at_terminal_response_on_open_stream() {
        // Open stream: response event, then silence (never EOFs — simulated
        // by the shim stopping at the terminal id match).
        let sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
        let t = FakeTransport::new(vec![sse_resp(200, sse)]);
        let (out, _) = pump_input(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.to_string().as_str(),
            &t,
        );
        assert!(String::from_utf8(out).unwrap().contains("\"result\":{}"));
    }

    #[test]
    fn test_404_triggers_reinit_and_resend() {
        let t = FakeTransport::new(vec![
            // initialize → session A
            json_resp_session(200, "sess-A", r#"{"jsonrpc":"2.0","id":0,"result":{}}"#),
            // tools/list on sess-A → 404 (session expired)
            json_resp(404, r#"{"jsonrpc":"2.0","error":{"message":"session not found"}}"#),
            // replayed initialize → session B
            json_resp_session(200, "sess-B", r#"{"jsonrpc":"2.0","id":0,"result":{}}"#),
            // notifications/initialized → 202
            json_resp(202, ""),
            // resent tools/list → OK
            json_resp(200, r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#),
        ]);
        let input = format!(
            "{}\n{}\n",
            INIT,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#
        );
        let (out, shim) = pump_input(&input, &t);
        let calls = t.calls();
        assert_eq!(calls.len(), 5, "{:?}", calls);
        assert!(calls[2].contains("initialize"), "re-init replays initialize");
        assert!(calls[3].contains("notifications/initialized"));
        assert!(calls[4].contains("tools/list"), "original frame resent");
        assert_eq!(shim.session_id.as_deref(), Some("sess-B"));
        assert!(String::from_utf8(out).unwrap().contains("\"tools\":[]"));
    }

    #[test]
    fn test_429_retries_with_retry_after_for_idempotent() {
        let mut r = json_resp(429, "");
        if let Ok(resp) = &mut r {
            resp.retry_after = Some(2);
        }
        let t = FakeTransport::new(vec![
            r,
            json_resp(200, r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#),
        ]);
        let (out, _) = pump_input(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.to_string().as_str(),
            &t,
        );
        assert_eq!(t.calls().len(), 2);
        assert!(String::from_utf8(out).unwrap().contains("\"tools\":[]"));
    }

    #[test]
    fn test_tools_call_never_retried_on_429() {
        // Non-idempotent boundary: a write may already have happened
        // upstream; replaying it silently could double-apply.
        let t = FakeTransport::new(vec![json_resp(429, "")]);
        let (out, _) = pump_input(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_issue"}}"#
                .to_string()
                .as_str(),
            &t,
        );
        assert_eq!(t.calls().len(), 1, "tools/call must not be retried");
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("-32000"), "{}", text);
    }

    #[test]
    fn test_tools_call_never_retried_on_transport_error() {
        let t = FakeTransport::new(vec![Err("connection reset".to_string())]);
        let (out, _) = pump_input(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}"#
                .to_string()
                .as_str(),
            &t,
        );
        assert_eq!(t.calls().len(), 1);
        assert!(String::from_utf8(out).unwrap().contains("-32000"));
    }

    #[test]
    fn test_transport_error_retries_then_fails() {
        let t = FakeTransport::new(vec![
            Err("reset".to_string()),
            Err("reset".to_string()),
            Err("reset".to_string()),
            Err("reset".to_string()),
            Err("reset".to_string()),
        ]);
        let (out, _) = pump_input(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.to_string().as_str(),
            &t,
        );
        assert_eq!(t.calls().len(), 4, "1 initial + 3 retries");
        assert!(String::from_utf8(out).unwrap().contains("-32000"));
    }

    #[test]
    fn test_notification_failures_stay_off_stdout() {
        let t = FakeTransport::new(vec![Err("reset".to_string())]);
        let (out, _) = pump_input(
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}"#
                .to_string()
                .as_str(),
            &t,
        );
        // 1 + 3 retries (notifications are retryable), nothing on stdout.
        assert_eq!(t.calls().len(), 4);
        assert!(out.is_empty());
    }

    #[test]
    fn test_upstream_error_becomes_jsonrpc_error() {
        let t = FakeTransport::new(vec![json_resp(500, "boom")]);
        let (out, _) = pump_input(
            r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"x"}}"#
                .to_string()
                .as_str(),
            &t,
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(r#""id":9"#), "{}", text);
        assert!(text.contains("-32000"), "{}", text);
    }

    #[test]
    fn test_retry_wait_honors_retry_after() {
        assert_eq!(retry_wait(0, Some(2)), Duration::from_secs(2));
        assert_eq!(retry_wait(0, Some(3600)), Duration::from_secs(60));
        assert_eq!(retry_wait(1, None), Duration::from_millis(500));
        assert_eq!(retry_wait(4, None), Duration::from_millis(4000));
        assert_eq!(retry_wait(10, None), Duration::from_millis(4000));
    }

    #[test]
    fn test_is_retryable() {
        for m in ["initialize", "ping", "tools/list", "notifications/initialized"] {
            assert!(is_retryable(Some(m)), "{}", m);
        }
        for m in ["tools/call", "sampling/createMessage", "unknown/method"] {
            assert!(!is_retryable(Some(m)), "{}", m);
        }
        assert!(!is_retryable(None));
    }

    #[test]
    fn test_iam_header_value_is_presigned_url() {
        let auth = Auth::Iam {
            creds: crate::sigv4::AwsCredentials {
                access_key_id: "AKIDEXAMPLE".to_string(),
                secret_access_key: "secret".to_string(),
                session_token: None,
            },
            region: "us-east-1".to_string(),
        };
        let (name, value) = auth.header();
        assert_eq!(name, "x-octobroker-iam");
        assert!(value.starts_with("https://sts.us-east-1.amazonaws.com/?"));
        assert!(value.contains("X-Amz-Signature="));
    }

    #[test]
    fn test_loopback_detection() {
        assert!(is_loopback("http://127.0.0.1:8080"));
        assert!(is_loopback("http://localhost:8080"));
        assert!(!is_loopback("http://octobroker.internal:8080"));
        assert!(!is_loopback("http://10.0.0.5:8080"));
    }
}
