//! Secretless agent authentication via AWS SigV4 identity proofs
//! (Phase 3, #18).
//!
//! An agent running under an AWS workload identity (ECS task role, EKS IRSA,
//! EC2 instance profile) proves its identity to octobroker WITHOUT any shared
//! secret: it presents a **presigned `sts:GetCallerIdentity` URL** in the
//! `X-Octobroker-Iam` header. octobroker validates the URL structure and then
//! executes it server-side — the signature is verified by AWS STS itself, so
//! a 200 response with an `<Arn>` is cryptographic proof of the caller's
//! identity (the same pattern as aws-iam-authenticator for Kubernetes).
//!
//! Controls (per RFC Revision 2):
//! - **TLS required** — only `https://` proof URLs are accepted, and the
//!   verification fetch never follows redirects.
//! - **≤ 60s proof validity** — `X-Amz-Expires` is capped at 60 and the
//!   proof must not already be expired when checked.
//! - **Allowlisted STS host/region** — only `sts.amazonaws.com` (global) and
//!   `sts.<region>.amazonaws.com[.cn]` for configured regions are valid
//!   targets; the credential's signing region must match the endpoint.
//! - **Strict signed-header validation** — `X-Amz-SignedHeaders` must be
//!   exactly `host`: anything else either cannot verify through our fetch
//!   (we send only Host) or would widen what the signature binds to.
//! - `Action` must be `GetCallerIdentity` — a presigned URL for any other
//!   API is not an identity proof.
//!
//! The resolved caller ARN is matched against each agent's `iam_principals`
//! allowlist (exact ARN, trailing-`*` prefix wildcard, or a bare 12-digit
//! account id). Assumed-role ARNs (`arn:aws:sts::acct:assumed-role/Role/Sess`)
//! are also tried in their canonical role form (`arn:aws:iam::acct:role/Role`)
//! so operators can write the IAM role ARN they actually manage.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::IamConfig;

/// Header carrying the presigned GetCallerIdentity URL.
pub const IAM_HEADER: &str = "x-octobroker-iam";

/// Max allowed `X-Amz-Expires` — RFC bound (≤60s proof validity).
pub const MAX_PROOF_EXPIRES_SECS: u64 = 60;
/// Clock skew tolerated when judging X-Amz-Date freshness.
const CLOCK_SKEW_SECS: u64 = 300;

/// A verified STS caller identity (the signature was checked by AWS itself).
#[derive(Debug, Clone, PartialEq)]
pub struct CallerIdentity {
    pub arn: String,
    pub account: String,
    pub user_id: String,
}

/// Structural result of validating a presigned URL, before it is executed.
#[derive(Debug)]
pub struct PresignedProof {
    /// Time (unix secs) after which the proof is expired.
    pub valid_until: u64,
}

/// Verifies presigned GetCallerIdentity proofs and resolves caller identity.
/// Verified proofs are cached (keyed by SHA-256 of the URL) until their own
/// expiry so a shim presenting the same URL for many frames does not cost an
/// STS call per frame.
pub struct IamVerifier {
    cfg: IamConfig,
    /// GET url → response body. Injectable for tests; production builds the
    /// real HTTPS fetch (no redirects, bounded timeout).
    fetch: FetchFn,
    cache: Mutex<HashMap<String, CachedIdentity>>,
}

struct CachedIdentity {
    identity: CallerIdentity,
    valid_until: Instant,
}

pub type FetchFn = std::sync::Arc<
    dyn Fn(
            String,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send>>
        + Send
        + Sync,
>;

impl IamVerifier {
    /// Production verifier: dedicated client, redirects disabled (a presigned
    /// URL must be answered by STS itself, not wherever a redirect points).
    pub fn new(cfg: IamConfig) -> Self {
        let timeout = Duration::from_secs(cfg.fetch_timeout_secs.max(1));
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .expect("iam verifier http client");
        let fetch: FetchFn = std::sync::Arc::new(move |url: String| {
            let http = http.clone();
            Box::pin(async move {
                let resp = http
                    .get(&url)
                    .header("accept", "application/json")
                    .send()
                    .await
                    .map_err(|e| format!("sts fetch failed: {e}"))?;
                if !resp.status().is_success() {
                    return Err(format!("sts rejected proof: {}", resp.status()));
                }
                resp.text()
                    .await
                    .map_err(|e| format!("sts response read failed: {e}"))
            })
        });
        Self {
            cfg,
            fetch,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Test constructor: stub the STS fetch entirely.
    #[cfg(test)]
    pub fn with_fetch(cfg: IamConfig, fetch: FetchFn) -> Self {
        Self {
            cfg,
            fetch,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Validate + execute a proof URL. Returns the caller identity on success.
    /// The URL is a bearer credential; it is never logged beyond a hash.
    pub async fn caller_identity(&self, url: &str) -> Result<CallerIdentity, String> {
        let proof = validate_presigned_url(url, &self.cfg, unix_now())?;
        let key = hex_sha256(url.as_bytes());
        if let Some(hit) = self.cache_get(&key) {
            return Ok(hit);
        }
        let body = (self.fetch)(url.to_string()).await?;
        let identity = parse_caller_identity(&body)
            .ok_or_else(|| "sts response missing caller identity".to_string())?;
        self.cache_put(key, identity.clone(), proof.valid_until);
        Ok(identity)
    }

    fn cache_get(&self, key: &str) -> Option<CallerIdentity> {
        let mut cache = self.cache.lock().unwrap();
        match cache.get(key) {
            Some(c) if c.valid_until > Instant::now() => Some(c.identity.clone()),
            Some(_) => {
                cache.remove(key);
                None
            }
            None => None,
        }
    }

    fn cache_put(&self, key: String, identity: CallerIdentity, valid_until_unix: u64) {
        let now = unix_now();
        let ttl = valid_until_unix.saturating_sub(now);
        if ttl == 0 {
            return;
        }
        let mut cache = self.cache.lock().unwrap();
        // Bound the cache: proofs are ≤60s lived; evict expired lazily.
        cache.retain(|_, c| c.valid_until > Instant::now());
        cache.insert(
            key,
            CachedIdentity {
                identity,
                valid_until: Instant::now() + Duration::from_secs(ttl),
            },
        );
    }
}

/// Validate a presigned GetCallerIdentity URL WITHOUT executing it.
/// Pure and deterministic (takes `now`) so every control is unit-testable.
pub fn validate_presigned_url(
    raw: &str,
    cfg: &IamConfig,
    now: u64,
) -> Result<PresignedProof, String> {
    let url = parse_url(raw)?;

    // TLS required — the proof is a bearer credential.
    if url.scheme != "https" {
        return Err("proof URL must use https".to_string());
    }
    if url.port.is_some_and(|p| p != 443) {
        return Err("proof URL must not use a non-default port".to_string());
    }
    if !url.path.is_empty() && url.path != "/" {
        return Err("proof URL must target the STS root path".to_string());
    }
    let host = url.host.to_lowercase();
    let Some(expected_region) = endpoint_region(&host, cfg) else {
        return Err("proof URL host is not an allowlisted STS endpoint".to_string());
    };

    // Parse the query; duplicate keys are rejected (an ambiguous signature
    // input is not a valid proof).
    let mut params: HashMap<String, String> = HashMap::new();
    for (k, v) in &url.query_pairs {
        if params.insert(k.clone(), v.clone()).is_some() {
            return Err(format!("duplicate query parameter '{}'", k));
        }
    }

    // The proof must be for GetCallerIdentity — any other action is not an
    // identity proof.
    match params.get("Action").map(String::as_str) {
        Some("GetCallerIdentity") => {}
        _ => return Err("proof URL must be a GetCallerIdentity request".to_string()),
    }
    match params.get("Version").map(String::as_str) {
        Some("2011-06-15") => {}
        _ => return Err("proof URL must use STS API version 2011-06-15".to_string()),
    }
    match params.get("X-Amz-Algorithm").map(String::as_str) {
        Some("AWS4-HMAC-SHA256") => {}
        _ => return Err("proof URL must be SigV4-signed".to_string()),
    }

    // Strict signed-header validation: exactly "host". A wider set cannot
    // verify through our fetch (we only send Host) and a set missing host
    // would not bind the signature to the STS endpoint.
    match params.get("X-Amz-SignedHeaders").map(String::as_str) {
        Some("host") => {}
        _ => return Err("proof URL must sign exactly the host header".to_string()),
    }

    let signature = params
        .get("X-Amz-Signature")
        .ok_or_else(|| "proof URL missing X-Amz-Signature".to_string())?;
    if signature.len() != 64
        || !signature
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("proof URL signature must be 64 lowercase hex chars".to_string());
    }

    // Credential scope: <key>/<yyyymmdd>/<region>/sts/aws4_request — the
    // service must be sts and the region must match the endpoint's.
    let cred = params
        .get("X-Amz-Credential")
        .ok_or_else(|| "proof URL missing X-Amz-Credential".to_string())?;
    let scope: Vec<&str> = cred.split('/').collect();
    if scope.len() != 5 || scope[0].is_empty() || scope[3] != "sts" || scope[4] != "aws4_request" {
        return Err("proof URL credential scope is malformed".to_string());
    }
    if scope[2] != expected_region {
        return Err("proof URL signing region does not match the STS endpoint".to_string());
    }

    let amz_date = params
        .get("X-Amz-Date")
        .ok_or_else(|| "proof URL missing X-Amz-Date".to_string())?;
    let signed_at = parse_amz_date(amz_date).ok_or("proof URL has malformed X-Amz-Date")?;
    if scope[1] != &amz_date[..8] {
        return Err("credential scope date does not match X-Amz-Date".to_string());
    }
    if signed_at > now + CLOCK_SKEW_SECS {
        return Err("proof URL signed in the future".to_string());
    }

    let expires: u64 = params
        .get("X-Amz-Expires")
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| "proof URL has malformed X-Amz-Expires".to_string())?;
    if expires == 0 || expires > cfg.max_expires_secs.min(MAX_PROOF_EXPIRES_SECS) {
        return Err("proof URL lifetime exceeds the 60s bound".to_string());
    }
    let valid_until = signed_at + expires;
    if valid_until <= now {
        return Err("proof URL already expired".to_string());
    }

    // Optional session token: present for all temporary (role) credentials;
    // must simply be non-empty when present.
    if params
        .get("X-Amz-Security-Token")
        .is_some_and(|t| t.is_empty())
    {
        return Err("proof URL has an empty X-Amz-Security-Token".to_string());
    }

    // Nothing outside the known presign parameter set — strict allowlist.
    for k in params.keys() {
        match k.as_str() {
            "Action"
            | "Version"
            | "X-Amz-Algorithm"
            | "X-Amz-Credential"
            | "X-Amz-Date"
            | "X-Amz-Expires"
            | "X-Amz-SignedHeaders"
            | "X-Amz-Signature"
            | "X-Amz-Security-Token" => {}
            _ => return Err(format!("unexpected query parameter '{}'", k)),
        }
    }

    Ok(PresignedProof { valid_until })
}

/// Whether `host` is an allowlisted STS endpoint; returns the signing region
/// the endpoint requires (global endpoint signs as us-east-1).
fn endpoint_region(host: &str, cfg: &IamConfig) -> Option<String> {
    if host == "sts.amazonaws.com" {
        return cfg.allow_global_sts.then(|| "us-east-1".to_string());
    }
    for suffix in [".amazonaws.com", ".amazonaws.com.cn"] {
        if let Some(region) = host
            .strip_prefix("sts.")
            .and_then(|h| h.strip_suffix(suffix))
        {
            if !region.is_empty()
                && cfg
                    .sts_regions
                    .iter()
                    .any(|r| r.eq_ignore_ascii_case(region))
            {
                return Some(region.to_string());
            }
        }
    }
    None
}

/// Match a verified caller identity against an agent's `iam_principals`
/// allowlist. Entry forms:
///   - exact ARN
///   - `prefix*` (trailing wildcard only)
///   - bare 12-digit AWS account id
///
/// Assumed-role ARNs are additionally tried in canonical IAM role form so
/// `arn:aws:iam::acct:role/Name` matches a caller that assumed it.
pub fn arn_allowed(patterns: &[String], identity: &CallerIdentity) -> bool {
    let mut candidates = vec![identity.arn.clone()];
    // arn:<partition>:sts::123456789012:assumed-role/MyRole/session → canonical
    // IAM role ARN (arn:<partition>:iam::<acct>:role/MyRole), any partition.
    let parts: Vec<&str> = identity.arn.splitn(6, ':').collect();
    if parts.len() == 6 && parts[0] == "arn" && parts[2] == "sts" {
        if let Some((role, _session)) = parts[5]
            .strip_prefix("assumed-role/")
            .and_then(|p| p.split_once('/'))
        {
            candidates.push(format!("arn:{}:iam::{}:role/{}", parts[1], parts[4], role));
        }
    }
    for pattern in patterns {
        let p = pattern.trim();
        if p.len() == 12 && p.bytes().all(|b| b.is_ascii_digit()) {
            if identity.account == p {
                return true;
            }
            continue;
        }
        if let Some(prefix) = p.strip_suffix('*') {
            if candidates.iter().any(|c| c.starts_with(prefix)) {
                return true;
            }
        } else if candidates.iter().any(|c| *c == p) {
            return true;
        }
    }
    false
}

/// Extract `<Arn>`/`<Account>`/`<UserId>` from a GetCallerIdentity XML body.
fn parse_caller_identity(body: &str) -> Option<CallerIdentity> {
    Some(CallerIdentity {
        arn: xml_tag(body, "Arn")?,
        account: xml_tag(body, "Account")?,
        user_id: xml_tag(body, "UserId")?,
    })
}

fn xml_tag(body: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&close)? + start;
    let value = body[start..end].trim();
    (!value.is_empty()).then(|| value.to_string())
}

struct ParsedUrl {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
    query_pairs: Vec<(String, String)>,
}

/// Minimal URL parse sufficient for proof validation — strict about the
/// shapes a presigned URL may take. Rejects userinfo and fragments outright.
fn parse_url(raw: &str) -> Result<ParsedUrl, String> {
    if raw.len() > 8192 {
        return Err("proof URL too long".to_string());
    }
    if raw.contains('#') || raw.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return Err("proof URL contains forbidden characters".to_string());
    }
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| "proof URL missing scheme".to_string())?;
    let rest = rest.to_string();
    let (authority, path_and_query) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => match rest.find('?') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest.as_str(), ""),
        },
    };
    if authority.is_empty() || authority.contains('@') {
        return Err("proof URL has malformed authority".to_string());
    }
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (
            h,
            Some(
                p.parse::<u16>()
                    .map_err(|_| "proof URL has malformed port".to_string())?,
            ),
        ),
        None => (authority, None),
    };
    if host.is_empty() {
        return Err("proof URL has empty host".to_string());
    }
    let (path, query) = match path_and_query.find('?') {
        Some(i) => (&path_and_query[..i], &path_and_query[i + 1..]),
        None => (path_and_query, ""),
    };
    let mut pairs = Vec::new();
    if !query.is_empty() {
        for pair in query.split('&') {
            let (k, v) = pair
                .split_once('=')
                .ok_or_else(|| "malformed query parameter".to_string())?;
            pairs.push((percent_decode(k)?, percent_decode(v)?));
        }
    }
    Ok(ParsedUrl {
        scheme: scheme.to_string(),
        host: host.to_string(),
        port,
        path: path.to_string(),
        query_pairs: pairs,
    })
}

fn percent_decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .map_err(|_| "invalid percent-encoding".to_string())?;
                let v = u8::from_str_radix(hex, 16)
                    .map_err(|_| "invalid percent-encoding".to_string())?;
                out.push(v);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| "invalid utf-8 in parameter".to_string())
}

/// `YYYYMMDDTHHMMSSZ` → unix seconds (UTC).
fn parse_amz_date(s: &str) -> Option<u64> {
    if s.len() != 16 || !s.ends_with('Z') || s.as_bytes()[8] != b'T' {
        return None;
    }
    let n = |r: &str| r.parse::<i64>().ok();
    let (year, month, day) = (n(&s[0..4])?, n(&s[4..6])?, n(&s[6..8])?);
    let (hour, min, sec) = (n(&s[9..11])?, n(&s[11..13])?, n(&s[13..15])?);
    if !(1..=12).contains(&month) || day == 0 || day > 31 || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    // days-from-civil (Howard Hinnant)
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    if days < 0 {
        return None;
    }
    Some((days * 86400 + hour * 3600 + min * 60 + sec) as u64)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// unix seconds → `YYYYMMDDTHHMMSSZ` (UTC). Test helper for building
/// non-expired proof URLs.
#[cfg(test)]
pub(crate) fn format_amz_date(unix: u64) -> String {
    let days = unix / 86400;
    let secs = unix % 86400;
    // civil-from-days (Hinnant inverse)
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        y,
        m,
        d,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

fn hex_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> IamConfig {
        IamConfig {
            sts_regions: vec!["us-east-1".to_string(), "eu-west-1".to_string()],
            allow_global_sts: true,
            max_expires_secs: 60,
            fetch_timeout_secs: 10,
        }
    }

    /// A structurally valid proof URL for tests; signature content is not
    /// checked by validation (STS verifies it).
    fn proof_url(host: &str, extra: &str) -> String {
        format!(
            "https://{}/?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fsts%2Faws4_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host&X-Amz-Signature={}{}",
            host, "a".repeat(64), extra
        )
    }

    const NOW: u64 = 1440938160; // 2015-08-30T12:36:00Z — matches X-Amz-Date

    #[test]
    fn test_valid_regional_proof_accepted() {
        let p = validate_presigned_url(&proof_url("sts.us-east-1.amazonaws.com", ""), &cfg(), NOW)
            .unwrap();
        assert_eq!(p.valid_until, NOW + 60);
    }

    #[test]
    fn test_valid_global_proof_accepted() {
        // Global endpoint signs with us-east-1
        validate_presigned_url(&proof_url("sts.amazonaws.com", ""), &cfg(), NOW).unwrap();
    }

    #[test]
    fn test_global_endpoint_rejected_when_not_allowed() {
        let mut c = cfg();
        c.allow_global_sts = false;
        let err = validate_presigned_url(&proof_url("sts.amazonaws.com", ""), &c, NOW).unwrap_err();
        assert!(err.contains("allowlisted"), "{}", err);
    }

    #[test]
    fn test_non_sts_and_lookalike_hosts_rejected() {
        for host in [
            "sts.us-west-2.amazonaws.com",      // region not allowlisted
            "sts.amazonaws.com.evil.com",       // suffix lookalike
            "evil-sts.us-east-1.amazonaws.com", // prefix lookalike
            "sts.us-east-1.amazonaws.com.evil.com",
            "ec2.us-east-1.amazonaws.com", // wrong service
            "sts.us-east-1.amazonaws.com.attacker.io",
        ] {
            let err = validate_presigned_url(&proof_url(host, ""), &cfg(), NOW).unwrap_err();
            assert!(
                err.contains("allowlisted"),
                "host {} must be rejected",
                host
            );
        }
    }

    #[test]
    fn test_http_scheme_rejected() {
        let url = proof_url("sts.us-east-1.amazonaws.com", "").replacen("https://", "http://", 1);
        let err = validate_presigned_url(&url, &cfg(), NOW).unwrap_err();
        assert!(err.contains("https"), "{}", err);
    }

    #[test]
    fn test_non_default_port_rejected() {
        let url = proof_url("sts.us-east-1.amazonaws.com:8443", "");
        let err = validate_presigned_url(&url, &cfg(), NOW).unwrap_err();
        assert!(err.contains("port"), "{}", err);
    }

    #[test]
    fn test_expires_over_60_rejected() {
        let url = proof_url("sts.us-east-1.amazonaws.com", "")
            .replace("X-Amz-Expires=60", "X-Amz-Expires=3600");
        let err = validate_presigned_url(&url, &cfg(), NOW).unwrap_err();
        assert!(err.contains("60s"), "{}", err);
    }

    #[test]
    fn test_expired_proof_rejected() {
        // 61 seconds after signing with 60s expiry
        let err = validate_presigned_url(
            &proof_url("sts.us-east-1.amazonaws.com", ""),
            &cfg(),
            NOW + 61,
        )
        .unwrap_err();
        assert!(err.contains("expired"), "{}", err);
    }

    #[test]
    fn test_future_signed_proof_rejected() {
        let err = validate_presigned_url(
            &proof_url("sts.us-east-1.amazonaws.com", ""),
            &cfg(),
            NOW - 400,
        )
        .unwrap_err();
        assert!(err.contains("future"), "{}", err);
    }

    #[test]
    fn test_signed_headers_must_be_exactly_host() {
        for bad in [
            "host%3Bx-amz-content-sha256",
            "content-type",
            "host%3Buser-agent",
        ] {
            let url = proof_url("sts.us-east-1.amazonaws.com", "").replace(
                "X-Amz-SignedHeaders=host",
                &format!("X-Amz-SignedHeaders={}", bad),
            );
            let err = validate_presigned_url(&url, &cfg(), NOW).unwrap_err();
            assert!(err.contains("host"), "{}: {}", bad, err);
        }
    }

    #[test]
    fn test_wrong_action_rejected() {
        // A presigned URL for a different API is not an identity proof.
        let url = proof_url("sts.us-east-1.amazonaws.com", "")
            .replace("Action=GetCallerIdentity", "Action=AssumeRole");
        let err = validate_presigned_url(&url, &cfg(), NOW).unwrap_err();
        assert!(err.contains("GetCallerIdentity"), "{}", err);
    }

    #[test]
    fn test_signing_region_must_match_endpoint() {
        // Credential signs eu-west-1 but the endpoint is us-east-1.
        let url = proof_url("sts.us-east-1.amazonaws.com", "")
            .replace("us-east-1%2Fsts", "eu-west-1%2Fsts");
        let err = validate_presigned_url(&url, &cfg(), NOW).unwrap_err();
        assert!(err.contains("region"), "{}", err);
    }

    #[test]
    fn test_credential_service_must_be_sts() {
        let url = proof_url("sts.us-east-1.amazonaws.com", "")
            .replace("%2Fsts%2Faws4_request", "%2Fs3%2Faws4_request");
        let err = validate_presigned_url(&url, &cfg(), NOW).unwrap_err();
        assert!(err.contains("scope"), "{}", err);
    }

    #[test]
    fn test_duplicate_and_unknown_params_rejected() {
        let dup = proof_url("sts.us-east-1.amazonaws.com", "&Action=GetCallerIdentity");
        assert!(validate_presigned_url(&dup, &cfg(), NOW)
            .unwrap_err()
            .contains("duplicate"));
        let extra = proof_url("sts.us-east-1.amazonaws.com", "&X-Amz-Sneaky=1");
        assert!(validate_presigned_url(&extra, &cfg(), NOW)
            .unwrap_err()
            .contains("unexpected"));
    }

    #[test]
    fn test_session_token_allowed_and_empty_rejected() {
        let ok = proof_url(
            "sts.us-east-1.amazonaws.com",
            "&X-Amz-Security-Token=AQoDYXdz",
        );
        validate_presigned_url(&ok, &cfg(), NOW).unwrap();
        let empty = proof_url("sts.us-east-1.amazonaws.com", "&X-Amz-Security-Token=");
        assert!(validate_presigned_url(&empty, &cfg(), NOW)
            .unwrap_err()
            .contains("empty"));
    }

    #[test]
    fn test_signature_shape_enforced() {
        let url = proof_url("sts.us-east-1.amazonaws.com", "").replace(
            &format!("X-Amz-Signature={}", "a".repeat(64)),
            "X-Amz-Signature=nothex",
        );
        assert!(validate_presigned_url(&url, &cfg(), NOW)
            .unwrap_err()
            .contains("hex"));
    }

    #[test]
    fn test_amz_date_parser() {
        assert_eq!(parse_amz_date("20150830T123600Z"), Some(1440938160));
        assert_eq!(parse_amz_date("20260217T000000Z"), Some(1771286400));
        assert!(parse_amz_date("2015-08-30").is_none());
        assert!(parse_amz_date("20150830T256000Z").is_none());
        assert!(parse_amz_date("garbage").is_none());
    }

    #[test]
    fn test_arn_allowed_matching() {
        let ident = CallerIdentity {
            arn: "arn:aws:sts::123456789012:assumed-role/agent-bot/session-42".to_string(),
            account: "123456789012".to_string(),
            user_id: "AROAEXAMPLE:session-42".to_string(),
        };
        // exact assumed-role arn
        assert!(arn_allowed(
            &["arn:aws:sts::123456789012:assumed-role/agent-bot/session-42".to_string()],
            &ident
        ));
        // canonical role form
        assert!(arn_allowed(
            &["arn:aws:iam::123456789012:role/agent-bot".to_string()],
            &ident
        ));
        // prefix wildcard on canonical form
        assert!(arn_allowed(
            &["arn:aws:iam::123456789012:role/agent-*".to_string()],
            &ident
        ));
        // bare account id
        assert!(arn_allowed(&["123456789012".to_string()], &ident));
        // non-matching
        assert!(!arn_allowed(
            &["arn:aws:iam::123456789012:role/other".to_string()],
            &ident
        ));
        assert!(!arn_allowed(&["999999999999".to_string()], &ident));
    }

    #[test]
    fn test_parse_caller_identity_xml() {
        let body = r#"<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:sts::123456789012:assumed-role/agent-bot/session-42</Arn>
    <UserId>AROAEXAMPLE:session-42</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata><RequestId>c6104cbe-af31-11e0-8154-cbc7ccf896c6</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>"#;
        let id = parse_caller_identity(body).unwrap();
        assert_eq!(
            id.arn,
            "arn:aws:sts::123456789012:assumed-role/agent-bot/session-42"
        );
        assert_eq!(id.account, "123456789012");
        assert_eq!(id.user_id, "AROAEXAMPLE:session-42");
        assert!(parse_caller_identity("<html>nope</html>").is_none());
    }

    #[tokio::test]
    async fn test_verifier_fetches_and_caches() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let calls2 = calls.clone();
        let fetch: FetchFn = std::sync::Arc::new(move |_url| {
            calls2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async {
                Ok(r#"<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:role/agent-bot</Arn><UserId>AROAX</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>"#.to_string())
            })
        });
        let verifier = IamVerifier::with_fetch(cfg(), fetch);
        let url = proof_url("sts.us-east-1.amazonaws.com", "");
        // Note: proof uses X-Amz-Date=20150830 → expired relative to real now;
        // build a fresh proof with a current date for the verifier path.
        let amz_now = format_amz_date(unix_now());
        let fresh = url
            .replace("20150830T123600Z", &amz_now)
            .replace("20150830%2F", &format!("{}%2F", &amz_now[..8]));
        let id1 = verifier.caller_identity(&fresh).await.unwrap();
        assert_eq!(id1.arn, "arn:aws:iam::123456789012:role/agent-bot");
        // Second call hits the cache — no second fetch.
        let id2 = verifier.caller_identity(&fresh).await.unwrap();
        assert_eq!(id2, id1);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_verifier_rejects_expired_before_fetch() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let calls2 = calls.clone();
        let fetch: FetchFn = std::sync::Arc::new(move |_url| {
            calls2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Ok("unreachable".to_string()) })
        });
        let verifier = IamVerifier::with_fetch(cfg(), fetch);
        // Stale X-Amz-Date → rejected without any STS fetch.
        let err = verifier
            .caller_identity(&proof_url("sts.us-east-1.amazonaws.com", ""))
            .await
            .unwrap_err();
        assert!(err.contains("expired"), "{}", err);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}
