//! `ghp mcp` — the secretless stdio MCP shim (Phase 3, #18).
//!
//! Runs *inside* the agent container. It reads newline-delimited JSON-RPC
//! frames on stdin, forwards each to octobroker's `/mcp` over HTTPS, and
//! writes the responses to stdout — the stdio transport every MCP client
//! already speaks.
//!
//! It holds no octobroker key and no long-lived AWS secret: the ambient role
//! credentials an ECS task role / EKS IRSA pod already has are used to mint a
//! **fresh presigned `sts:GetCallerIdentity` proof** for every request, and the
//! proof is re-minted at half its lifetime so a request is never sent with a
//! proof about to expire. octobroker maps the caller ARN STS reports to a
//! configured agent's `iam_role_arns` allowlist.
//!
//! Usage:
//! ```text
//! ghp mcp --proxy https://octobroker.internal:8080/mcp
//! ```
//! Environment:
//! - `OCTOBROKER_PROXY` / `OCTOBROKER_IAM_PROOF_TTL` — same as the flags.
//! - `AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN` — EKS IRSA.
//! - `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` / `AWS_CONTAINER_CREDENTIALS_FULL_URI`
//!   — ECS/EKS task role, including EKS Pod Identity.
//! - `AWS_REGION` / `AWS_DEFAULT_REGION` — signing region.
//!
//! The secret access key is held only in memory, is never logged, and never
//! written to stdout (stdout is the MCP transport).

use std::io::{BufRead, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use octobroker::iam::{
    presign_get_caller_identity, AmbientCredentials, IamProof, STS_ACTION, STS_SERVICE,
    STS_VERSION,
};

/// RFC cap on proof validity.
const MAX_PROOF_TTL_SECS: u64 = 60;
const DEFAULT_PROXY: &str = "http://127.0.0.1:8080/mcp";
/// ECS full-URI credentials endpoint is only used over HTTPS or on loopback
/// (EKS Pod Identity serves it over HTTP on the pod network).
const FULL_URI_ENV: &str = "AWS_CONTAINER_CREDENTIALS_FULL_URI";

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            // stderr, never stdout: stdout is the MCP frame channel.
            eprintln!("ghp: {message}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    if args.first().map(String::as_str) != Some("mcp") {
        return Err("usage: ghp mcp [--proxy URL] [--proof-ttl SECONDS]".into());
    }
    let mut proxy = std::env::var("OCTOBROKER_PROXY").unwrap_or_else(|_| DEFAULT_PROXY.into());
    let mut proof_ttl = std::env::var("OCTOBROKER_IAM_PROOF_TTL")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(MAX_PROOF_TTL_SECS);
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--proxy" => {
                proxy = args
                    .get(index + 1)
                    .ok_or_else(|| "--proxy needs a URL".to_string())?
                    .clone();
                index += 2;
            }
            "--proof-ttl" => {
                proof_ttl = args
                    .get(index + 1)
                    .ok_or_else(|| "--proof-ttl needs seconds".to_string())?
                    .parse::<u64>()
                    .map_err(|_| "--proof-ttl must be an integer".to_string())?;
                index += 2;
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if proof_ttl == 0 || proof_ttl > MAX_PROOF_TTL_SECS {
        return Err(format!(
            "--proof-ttl must be 1..={MAX_PROOF_TTL_SECS} (octobroker's RFC cap)"
        ));
    }
    if !proxy.starts_with("https://") && !is_loopback(&proxy) {
        return Err(format!(
            "refusing to send frames to non-TLS proxy {proxy:?} — use https:// or loopback"
        ));
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start runtime: {e}"))?;
    runtime.block_on(serve(&proxy, proof_ttl))
}

fn is_loopback(url: &str) -> bool {
    ["http://127.0.0.1", "http://localhost", "http://[::1]"]
        .iter()
        .any(|prefix| url.starts_with(prefix))
}

async fn serve(proxy: &str, proof_ttl: u64) -> Result<(), String> {
    let client = reqwest::Client::new();
    let mut credentials: Option<AmbientCredentials> = None;
    let mut proof: Option<IamProof> = None;
    let mut proof_minted_at = Instant::now() - Duration::from_secs(proof_ttl);
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let line = line.map_err(|e| format!("stdin read failed: {e}"))?;
        let frame = line.trim();
        if frame.is_empty() {
            continue;
        }
        // A notification (no `id`) gets no response; MCP clients do not expect
        // one, and writing a null-id frame back would confuse them.
        if is_notification(frame) {
            continue;
        }
        if is_shutdown_request(frame) {
            break;
        }

        // Re-mint at half life so a proof is never close to expiry in flight.
        if proof.is_none() || proof_minted_at.elapsed() >= Duration::from_secs(proof_ttl / 2) {
            if credentials.is_none() {
                credentials = Some(resolve_ambient_credentials().await?);
            }
            let minted = presign_get_caller_identity(
                credentials.as_ref().expect("just populated"),
                sts_host(),
                unix_now(),
                proof_ttl,
            )?;
            proof = Some(IamProof {
                host: sts_host().to_string(),
                region: credentials
                    .as_ref()
                    .map(|c| c.region.clone())
                    .unwrap_or_default(),
                access_key_id: String::new(),
                expires_in_secs: proof_ttl,
                signed_headers: vec!["host".into()],
                signature: proof_signature(&minted),
            });
            // The shim keeps only the URL; the proof value above is never
            // emitted anywhere.
            proof_url = Some(minted);
            proof_minted_at = Instant::now();
        }

        let response = post_frame(&client, proxy, frame, proof_url.as_deref().unwrap()).await;
        match response {
            Ok(text) => {
                writeln!(stdout, "{text}").map_err(|e| format!("stdout write failed: {e}"))?;
                stdout
                    .flush()
                    .map_err(|e| format!("stdout flush failed: {e}"))?;
            }
            Err(message) => {
                // Surface transport failures as a JSON-RPC error frame so the
                // client sees a protocol-level answer instead of a dead pipe.
                let error = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": serde_json::Value::Null,
                    "error": { "code": -32000, "message": message }
                });
                writeln!(stdout, "{error}").map_err(|e| format!("stdout write failed: {e}"))?;
                stdout.flush().map_err(|e| format!("stdout flush failed: {e}"))?;
            }
        }
    }
    Ok(())
}

async fn post_frame(
    client: &reqwest::Client,
    proxy: &str,
    frame: &str,
    proof_url: &str,
) -> Result<String, String> {
    let response = client
        .post(proxy)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header(octobroker::iam::PROOF_HEADER, proof_url)
        .body(frame.to_string())
        .send()
        .await
        .map_err(|e| format!("proxy request failed: {e}"))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|e| format!("proxy response unreadable: {e}"))?;
    if !status.is_success() {
        return Err(format!("proxy returned {status}: {}", first_line(&text)));
    }
    // Strip SSE framing: stdio transports carry bare JSON frames.
    Ok(strip_sse(&text))
}

fn first_line(text: &str) -> String {
    text.lines()
        .find(|l| !l.starts_with("data:") && !l.trim().is_empty())
        .unwrap_or("")
        .chars()
        .take(200)
        .collect()
}

/// Reduce an SSE body to its last `data:` payload, or return plain JSON as-is.
fn strip_sse(text: &str) -> String {
    let trimmed = text.trim();
    if !trimmed.starts_with("event:") && !trimmed.starts_with("data:") {
        return trimmed.to_string();
    }
    trimmed
        .lines()
        .filter_map(|line| line.strip_prefix("data:").map(str::trim_start))
        .filter(|payload| *payload != "[DONE]")
        .next_back()
        .unwrap_or("")
        .to_string()
}

fn is_notification(frame: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(frame)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .is_none()
}

fn is_shutdown_request(frame: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(frame)
        .ok()
        .and_then(|v| v.get("method").and_then(|m| m.as_str()).map(str::to_string))
        .is_some_and(|m| m == "shutdown")
}

fn proof_signature(proof_url: &str) -> String {
    proof_url
        .split("X-Amz-Signature=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .unwrap_or("")
        .to_string()
}

fn sts_host() -> &'static str {
    "sts.amazonaws.com"
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Ambient credential resolution
// ---------------------------------------------------------------------------

/// Resolve role credentials from the ambient provider — EKS IRSA first, then the
/// ECS/EKS container credentials endpoint.
///
/// No static AWS keys are read from the environment on purpose: an agent
/// container that must not hold secrets should not be able to fall back to one
/// from a plain environment variable.
async fn resolve_ambient_credentials() -> Result<AmbientCredentials, String> {
    let region = std::env::var("AWS_REGION")
        .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
        .unwrap_or_else(|_| "us-east-1".to_string());

    if let Some(token_file) = env_non_empty("AWS_WEB_IDENTITY_TOKEN_FILE") {
        let token = std::fs::read_to_string(&token_file)
            .map_err(|e| format!("cannot read web identity token {token_file}: {e}"))?;
        let token = token.trim().to_string();
        let role = env_non_empty("AWS_ROLE_ARN")
            .ok_or_else(|| "AWS_WEB_IDENTITY_TOKEN_FILE is set but AWS_ROLE_ARN is not".to_string())?;
        return assume_role_with_web_identity(&role, &token, &region).await;
    }

    if let Some(relative) = env_non_empty("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") {
        let host = env_non_empty("AWS_CONTAINER_CREDENTIALS_HOST")
            .unwrap_or_else(|| "169.254.170.2".to_string());
        let host = host.trim_start_matches("http://").trim_end_matches('/');
        return container_credentials(&format!("http://{host}{relative}"), &region).await;
    }
    if let Some(full) = env_non_empty(FULL_URI_ENV) {
        if !full.starts_with("https://") && !is_loopback(&full) {
            return Err(format!(
                "{FULL_URI_ENV} must be https:// (or loopback): refusing {full}"
            ));
        }
        return container_credentials(&full, &region).await;
    }

    Err("no ambient AWS credentials found — expected AWS_WEB_IDENTITY_TOKEN_FILE (IRSA) or \
         AWS_CONTAINER_CREDENTIALS_{RELATIVE,FULL}_URI (ECS task role / EKS Pod Identity)"
        .into())
}

fn env_non_empty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

async fn container_credentials(url: &str, region: &str) -> Result<AmbientCredentials, String> {
    let token = env_non_empty("AWS_CONTAINER_AUTHORIZATION_TOKEN")
        .or_else(|| env_non_empty("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE").and_then(|p| std::fs::read_to_string(p).ok()))
        .map(|t| format!("Bearer {}", t.trim()));
    let mut request = reqwest::Client::new().get(url);
    if let Some(token) = token {
        request = request.header("Authorization", token);
    }
    let body = request
        .send()
        .await
        .map_err(|e| format!("container credentials request failed: {e}"))?
        .text()
        .await
        .map_err(|e| format!("container credentials unreadable: {e}"))?;
    let value: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("container credentials malformed: {e}"))?;
    Ok(AmbientCredentials {
        access_key_id: json_field(&value, "AccessKeyId")?,
        secret_access_key: json_field(&value, "SecretAccessKey")?,
        session_token: json_field(&value, "Token").ok(),
        region: json_field(&value, "Region").unwrap_or_else(|_| region.to_string()),
        account_id: None,
    })
}

/// EKS IRSA: exchange the projected web-identity token for role credentials.
async fn assume_role_with_web_identity(
    role_arn: &str,
    web_token: &str,
    region: &str,
) -> Result<AmbientCredentials, String> {
    let role = role_arn
        .rsplit('/')
        .next()
        .ok_or_else(|| format!("malformed AWS_ROLE_ARN {role_arn:?}"))?;
    let query = serde_json::to_string(&serde_json::json!({
        "Action": "AssumeRoleWithWebIdentity",
        "Version": STS_VERSION,
        "RoleArn": role_arn,
        "RoleSessionName": role,
        "WebIdentityToken": web_token,
    }))
    .map_err(|e| format!("cannot encode STS request: {e}"))?;
    let endpoint = format!("https://{sts_host()}/?{query}");
    let body = reqwest::Client::new()
        .get(&endpoint)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("AssumeRoleWithWebIdentity failed: {e}"))?
        .text()
        .await
        .map_err(|e| format!("AssumeRoleWithWebIdentity response unreadable: {e}"))?;
    let value: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("AssumeRoleWithWebIdentity response malformed: {e}"))?;
    // Query-protocol responses wrap the result; accept both shapes.
    let result = value
        .pointer("/AssumeRoleWithWebIdentityResponse/AssumeRoleWithWebIdentityResult")
        .or_else(|| value.pointer("/AssumeRoleWithWebIdentityResult"))
        .ok_or_else(|| "AssumeRoleWithWebIdentity response had no result".to_string())?;
    Ok(AmbientCredentials {
        access_key_id: json_field(result, "AccessKeyId")?,
        secret_access_key: json_field(result, "SecretAccessKey")?,
        session_token: json_field(result, "SessionToken").ok(),
        region: json_field(result, "Region").unwrap_or_else(|_| region.to_string()),
        account_id: None,
    })
}

fn json_field(value: &serde_json::Value, key: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .filter(|v| !v.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("ambient credentials response has no {key}"))
}

/// Silences the unused-import warning for the STS action constant while keeping
/// the action name documented next to the minting call.
#[allow(dead_code)]
const PROOF_ACTION: &str = STS_ACTION;
#[allow(dead_code)]
const PROOF_SERVICE: &str = STS_SERVICE;