//! Secretless IAM authentication for the MCP proxy (Phase 3, #18).
//!
//! The `ghp mcp` stdio shim (see `src/bin/ghp.rs`) runs *inside* the agent
//! container and holds no octobroker key. On every proxied request it attaches
//! a SigV4 **presigned** `sts:GetCallerIdentity` URL minted from the ambient
//! role credentials it already has (ECS/EKS task role, EKS IRSA). The proxy
//! never receives an AWS secret: only the short-lived, single-purpose URL.
//!
//! ## What is verified locally, and what is not
//!
//! A presigned URL's signature cannot be checked without the secret access
//! key, so this module does **not** pretend to verify it. What it does is
//! enforce the RFC's SigV4 controls *before* any credential leaves the
//! process, then the caller performs the request itself so that **STS** is the
//! party that validates the signature:
//!
//! 1. TLS only — no `http://`, no scheme-relative or bare-host forms.
//! 2. Host allowlisted (default `sts.amazonaws.com`); no explicit port, no
//!    userinfo, so there is no way to smuggle a different endpoint.
//! 3. Allowlisted region in the credential scope, `sts` service,
//!    `aws4_request` terminator.
//! 4. Action is exactly `GetCallerIdentity` (never `AssumeRole`/`GetRoleCredential`).
//! 5. `X-Amz-Expires` ≤ [`PROOF_MAX_VALIDITY_SECS`] (60s). An operator may
//!    tighten this; [`IamProofPolicy::validate`] refuses a value above the cap.
//! 6. `X-Amz-Date` inside the window (with bounded clock skew), not expired,
//!    not future-dated.
//! 7. Strict signed-header validation: the `X-Amz-SignedHeaders` list must be
//!    lowercase, sorted, duplicate-free, contain `host`, and contain nothing
//!    outside [`IamProofPolicy::allowed_signed_headers`].
//! 8. `X-Amz-Signature` is 64 lowercase hex characters.
//! 9. No duplicate query keys — a repeated parameter must not let the local
//!    validator and STS disagree about the effective request.
//!
//! After local shape validation the caller replays the URL to the allowlisted
//! STS endpoint and reads the caller ARN out of the response
//! ([`parse_caller_identity_arn`]); that ARN — not the proof — selects the
//! agent whose policy applies. Finally [`ReplayGuard`] makes each proof
//! single-use inside its own validity window.
//!
//! This module is deliberately free of `crate::` references so the regression
//! suite can include it directly (`tests/phase3_operational.rs`).

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::Duration;

use sha2::{Digest, Sha256};

/// Request header carrying the presigned proof from the shim to the proxy.
pub const PROOF_HEADER: &str = "x-octobroker-iam-proof";

/// RFC cap on proof validity. A proof is single-use and must expire within a
/// minute; config can only tighten this.
pub const PROOF_MAX_VALIDITY_SECS: u64 = 60;

/// The only signing algorithm accepted.
pub const SIGV4_ALGORITHM: &str = "AWS4-HMAC-SHA256";
/// The only STS API version accepted.
pub const STS_VERSION: &str = "2011-06-15";
/// The only STS action accepted — a read-only "who am I" call.
pub const STS_ACTION: &str = "GetCallerIdentity";
/// SigV4 service name in the credential scope.
pub const STS_SERVICE: &str = "sts";
/// SigV4 credential-scope terminator.
pub const SIGV4_TERMINATOR: &str = "aws4_request";

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// Operator-tunable SigV4 controls for the secretless IAM path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IamProofPolicy {
    /// Allowed STS endpoint hosts (exact, case-insensitive match).
    pub allowed_hosts: Vec<String>,
    /// Allowed regions in the credential scope.
    pub allowed_regions: Vec<String>,
    /// Maximum `X-Amz-Expires`, in seconds. Clamped to
    /// [`PROOF_MAX_VALIDITY_SECS`] on construction from config.
    pub max_validity_secs: u64,
    /// Tolerance for clock drift between the shim and the proxy.
    pub clock_skew_secs: u64,
    /// Actions accepted in the query string. Fixed to `GetCallerIdentity` by
    /// default; kept configurable only so the value can be *narrowed*, never
    /// widened past the default set.
    pub allowed_actions: Vec<String>,
    /// Headers the shim is permitted to include in `X-Amz-SignedHeaders`.
    /// Anything outside this list is rejected (strict validation).
    pub allowed_signed_headers: Vec<String>,
}

impl Default for IamProofPolicy {
    fn default() -> Self {
        Self {
            allowed_hosts: vec!["sts.amazonaws.com".to_string()],
            allowed_regions: vec!["us-east-1".to_string()],
            max_validity_secs: PROOF_MAX_VALIDITY_SECS,
            clock_skew_secs: 5,
            allowed_actions: vec![STS_ACTION.to_string()],
            allowed_signed_headers: vec![
                "host".to_string(),
                "x-amz-content-sha256".to_string(),
                "x-amz-date".to_string(),
                "x-amz-security-token".to_string(),
            ],
        }
    }
}

impl IamProofPolicy {
    /// Build a policy from operator config. `max_validity_secs` may only
    /// *tighten* the RFC cap: a larger configured value is clamped down here,
    /// and [`Self::validate`] independently refuses any over-cap policy that
    /// reached it by another route.
    pub fn from_config(max_validity_secs: u64) -> Self {
        let mut policy = Self::default();
        if max_validity_secs > 0 {
            policy.max_validity_secs = max_validity_secs.min(PROOF_MAX_VALIDITY_SECS);
        }
        policy
    }

    /// Reject configurations that would weaken or disable the controls.
    /// Called at startup; a failure aborts boot rather than silently opening
    /// the path.
    pub fn validate(&self) -> Result<(), String> {
        if self.allowed_hosts.is_empty() {
            return Err("mcp.iam.sts_hosts must not be empty".into());
        }
        if self.allowed_hosts.iter().any(|h| {
            h.is_empty()
                || h.contains('/')
                || h.contains(':')
                || !h.eq_ignore_ascii_case(h.trim())
        }) {
            return Err(
                "mcp.iam.sts_hosts entries must be bare hostnames (no scheme, port or path)".into(),
            );
        }
        if self.allowed_regions.is_empty() {
            return Err("mcp.iam.regions must not be empty".into());
        }
        if self.allowed_actions.is_empty() {
            return Err("mcp.iam.actions must not be empty".into());
        }
        if self
            .allowed_actions
            .iter()
            .any(|a| a != STS_ACTION)
        {
            return Err(format!(
                "mcp.iam.actions may only contain {STS_ACTION} — the proof path is read-only"
            ));
        }
        if self.max_validity_secs == 0 || self.max_validity_secs > PROOF_MAX_VALIDITY_SECS {
            return Err(format!(
                "mcp.iam.max_proof_age_secs must be 1..={PROOF_MAX_VALIDITY_SECS} (RFC cap)"
            ));
        }
        if self.clock_skew_secs > self.max_validity_secs {
            return Err(
                "mcp.iam.clock_skew_secs must not exceed max_proof_age_secs — a skew larger than the proof lifetime would accept any stale proof"
                    .into(),
            );
        }
        if !self
            .allowed_signed_headers
            .iter()
            .any(|h| h == "host")
        {
            return Err("mcp.iam.signed_headers must include `host`".into());
        }
        if self
            .allowed_signed_headers
            .iter()
            .any(|h| h.is_empty() || h.chars().any(|c| c.is_ascii_uppercase()))
        {
            return Err(
                "mcp.iam.signed_headers entries must be non-empty lowercase HTTP header names"
                    .into(),
            );
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Rejections
// ---------------------------------------------------------------------------

/// Why a presigned proof was refused. Deliberately coarse in what it reveals:
/// the variants name the violated control, never the offending value of a
/// signature or token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofRejection {
    /// The proof was not an `https://` URL.
    NotHttps,
    /// The URL could not be taken apart as scheme://host/path?query.
    MalformedUrl,
    /// The endpoint host is not allowlisted.
    HostNotAllowed,
    /// A required query parameter is absent.
    QueryMissing(&'static str),
    /// A query key appears more than once.
    DuplicateQueryKey(String),
    /// `X-Amz-Algorithm` is not SigV4.
    AlgorithmNotSigV4,
    /// The STS action is not allowlisted.
    ActionNotAllowed,
    /// The `Version` parameter is not the STS API version.
    VersionNotSupported,
    /// `X-Amz-Expires` is missing or not a positive integer.
    ExpiryInvalid,
    /// `X-Amz-Expires` exceeds the configured (RFC-capped) maximum.
    ExpiryTooLong { requested: u64, max: u64 },
    /// `X-Amz-Date` is missing or unparseable.
    DateInvalid,
    /// `X-Amz-Date` is further ahead than the tolerated clock skew.
    DateInFuture { skew: u64 },
    /// The proof's validity window has passed.
    Expired,
    /// The credential scope is malformed, or names a wrong date/service/terminator.
    CredentialScopeInvalid,
    /// The credential scope region is not allowlisted.
    RegionNotAllowed,
    /// The signed-header list violates the strict format rules.
    SignedHeadersInvalid(&'static str),
    /// A signed header is outside the operator allowlist.
    SignedHeaderNotAllowed(String),
    /// A header the policy requires to be signed was not signed.
    RequiredHeaderUnsigned(String),
    /// `X-Amz-Signature` is not 64 lowercase hex characters.
    SignatureInvalid,
}

impl ProofRejection {
    /// Stable, secret-free reason string for logs and JSON-RPC errors.
    pub fn as_str(&self) -> &'static str {
        match self {
            ProofRejection::NotHttps => "iam_proof_requires_tls",
            ProofRejection::MalformedUrl => "iam_proof_malformed_url",
            ProofRejection::HostNotAllowed => "iam_proof_host_not_allowed",
            ProofRejection::QueryMissing(_) => "iam_proof_missing_parameter",
            ProofRejection::DuplicateQueryKey(_) => "iam_proof_duplicate_parameter",
            ProofRejection::AlgorithmNotSigV4 => "iam_proof_algorithm_not_sigv4",
            ProofRejection::ActionNotAllowed => "iam_proof_action_not_allowed",
            ProofRejection::VersionNotSupported => "iam_proof_version_not_supported",
            ProofRejection::ExpiryInvalid => "iam_proof_expiry_invalid",
            ProofRejection::ExpiryTooLong { .. } => "iam_proof_expiry_too_long",
            ProofRejection::DateInvalid => "iam_proof_date_invalid",
            ProofRejection::DateInFuture { .. } => "iam_proof_date_in_future",
            ProofRejection::Expired => "iam_proof_expired",
            ProofRejection::CredentialScopeInvalid => "iam_proof_credential_scope_invalid",
            ProofRejection::RegionNotAllowed => "iam_proof_region_not_allowed",
            ProofRejection::SignedHeadersInvalid(_) => "iam_proof_signed_headers_invalid",
            ProofRejection::SignedHeaderNotAllowed(_) => "iam_proof_signed_header_not_allowed",
            ProofRejection::RequiredHeaderUnsigned(_) => "iam_proof_required_header_unsigned",
            ProofRejection::SignatureInvalid => "iam_proof_signature_invalid",
        }
    }
}

impl fmt::Display for ProofRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A structurally valid, in-window presigned proof. The secret access key is
/// never part of this value; `signature` is retained only so the replay guard
/// can fingerprint it and must never be logged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IamProof {
    pub host: String,
    pub region: String,
    pub access_key_id: String,
    pub expires_in_secs: u64,
    pub signed_headers: Vec<String>,
    pub signature: String,
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Validate a presigned `sts:GetCallerIdentity` proof against the operator's
/// SigV4 controls. Pure and clock-injected so it is fully testable.
pub fn verify_presigned_proof(
    url: &str,
    now_epoch_secs: u64,
    policy: &IamProofPolicy,
) -> Result<IamProof, ProofRejection> {
    let rest = url.strip_prefix("https://").ok_or(ProofRejection::NotHttps)?;
    let (authority, query) = match rest.find('?') {
        Some(index) => (&rest[..index], &rest[index + 1..]),
        // No query string at all cannot be a presigned proof; the missing
        // parameter is reported further down, which is more useful.
        None => (rest, ""),
    };
    // Authority must be a bare host with at most the empty "/" path: no
    // userinfo, no port, no request path. Anything else is a way to point the
    // replay at a different endpoint, so it is rejected outright.
    let (authority, path) = match authority.split_once('/') {
        Some((host, path)) => (host, path),
        None => (authority, ""),
    };
    if !path.is_empty() {
        return Err(ProofRejection::MalformedUrl);
    }
    let host = authority.to_ascii_lowercase();
    if host.is_empty() || host.contains('@') || host.contains(':') {
        return Err(ProofRejection::MalformedUrl);
    }
    if !policy
        .allowed_hosts
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&host))
    {
        return Err(ProofRejection::HostNotAllowed);
    }

    let params = parse_query(query)?;

    if require(&params, "X-Amz-Algorithm")? != SIGV4_ALGORITHM {
        return Err(ProofRejection::AlgorithmNotSigV4);
    }
    if require(&params, "Action")? != STS_ACTION {
        return Err(ProofRejection::ActionNotAllowed);
    }
    if require(&params, "Version")? != STS_VERSION {
        return Err(ProofRejection::VersionNotSupported);
    }

    let expires = params
        .get("X-Amz-Expires")
        .ok_or(ProofRejection::ExpiryInvalid)?
        .parse::<u64>()
        .map_err(|_| ProofRejection::ExpiryInvalid)?;
    if expires == 0 {
        return Err(ProofRejection::ExpiryInvalid);
    }
    if expires > policy.max_validity_secs {
        return Err(ProofRejection::ExpiryTooLong {
            requested: expires,
            max: policy.max_validity_secs,
        });
    }

    let signed_at = parse_amz_date(require(&params, "X-Amz-Date")?)
        .ok_or(ProofRejection::DateInvalid)?;
    if signed_at > now_epoch_secs.saturating_add(policy.clock_skew_secs) {
        return Err(ProofRejection::DateInFuture {
            skew: policy.clock_skew_secs,
        });
    }
    if now_epoch_secs > signed_at.saturating_add(expires) {
        return Err(ProofRejection::Expired);
    }

    let (access_key_id, scope_date, region, service, terminator) =
        split_credential(require(&params, "X-Amz-Credential")?)
            .ok_or(ProofRejection::CredentialScopeInvalid)?;
    if access_key_id.is_empty()
        || terminator != SIGV4_TERMINATOR
        || service != STS_SERVICE
        || scope_date != amz_date_stamp(signed_at)
    {
        return Err(ProofRejection::CredentialScopeInvalid);
    }
    if !policy
        .allowed_regions
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(region))
    {
        return Err(ProofRejection::RegionNotAllowed);
    }

    let signed_headers = parse_signed_headers(require(&params, "X-Amz-SignedHeaders")?)?;
    for header in &signed_headers {
        if !policy.allowed_signed_headers.iter().any(|a| a == header) {
            return Err(ProofRejection::SignedHeaderNotAllowed(header.clone()));
        }
    }
    for required in &policy.required_signed_headers() {
        if !signed_headers.iter().any(|h| h == required) {
            return Err(ProofRejection::RequiredHeaderUnsigned(required.clone()));
        }
    }

    let signature = params
        .get("X-Amz-Signature")
        .ok_or(ProofRejection::SignatureInvalid)?;
    if !is_lower_hex(signature, 64) {
        return Err(ProofRejection::SignatureInvalid);
    }

    Ok(IamProof {
        host,
        region: region.to_ascii_lowercase(),
        access_key_id: access_key_id.to_string(),
        expires_in_secs: expires,
        signed_headers,
        signature: signature.to_string(),
    })
}

impl IamProofPolicy {
    /// Headers that must always appear in `X-Amz-SignedHeaders`.
    fn required_signed_headers(&self) -> Vec<String> {
        vec!["host".to_string()]
    }
}

fn require<'a>(params: &'a HashMap<String, String>, key: &'static str) -> Result<&'a str, ProofRejection> {
    params
        .get(key)
        .map(String::as_str)
        .ok_or(ProofRejection::QueryMissing(key))
}

/// Percent-decoded query string into a map, rejecting duplicate keys.
fn parse_query(query: &str) -> Result<HashMap<String, String>, ProofRejection> {
    let mut map: HashMap<String, String> = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        };
        if map.insert(key.clone(), value).is_some() {
            return Err(ProofRejection::DuplicateQueryKey(key));
        }
    }
    Ok(map)
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `accessKeyId/date/region/service/aws4_request`
fn split_credential(credential: &str) -> Option<(&str, &str, &str, &str, &str)> {
    let parts: Vec<&str> = credential.split('/').collect();
    if parts.len() != 5 {
        return None;
    }
    Some((parts[0], parts[1], parts[2], parts[3], parts[4]))
}

/// Strict `X-Amz-SignedHeaders` validation: lowercase, sorted, duplicate-free.
fn parse_signed_headers(raw: &str) -> Result<Vec<String>, ProofRejection> {
    if raw.is_empty() {
        return Err(ProofRejection::SignedHeadersInvalid("empty list"));
    }
    let headers: Vec<String> = raw.split(';').map(str::to_string).collect();
    let mut sorted = headers.clone();
    sorted.sort();
    if sorted != headers {
        return Err(ProofRejection::SignedHeadersInvalid("not sorted"));
    }
    sorted.dedup();
    if sorted.len() != headers.len() {
        return Err(ProofRejection::SignedHeadersInvalid("duplicate header"));
    }
    if headers
        .iter()
        .any(|h| h.is_empty() || h.chars().any(|c| c.is_ascii_uppercase() || c == ' '))
    {
        return Err(ProofRejection::SignedHeadersInvalid("not lowercase"));
    }
    Ok(headers)
}

// ---------------------------------------------------------------------------
// Minting (shim side)
// ---------------------------------------------------------------------------

/// Ambient role credentials resolved by the shim from the task role / IRSA
/// web-identity provider. Never serialized into logs or error messages.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AmbientCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    /// Present for every temporary/assumed role (ECS task role, IRSA).
    pub session_token: Option<String>,
    pub region: String,
    /// Decoded from `GetCallerIdentity.Account` when known.
    pub account_id: Option<String>,
}

impl AmbientCredentials {
    fn is_usable(&self) -> bool {
        !self.access_key_id.is_empty()
            && !self.secret_access_key.is_empty()
            && !self.region.is_empty()
    }
}

/// Mint a SigV4 presigned `sts:GetCallerIdentity` URL.
///
/// `expires_secs` is honoured verbatim and must already satisfy the RFC cap:
/// minting a longer-lived proof is refused rather than silently shortened, so a
/// caller can never believe it has a window the proxy would not accept.
pub fn presign_get_caller_identity(
    credentials: &AmbientCredentials,
    host: &str,
    now_epoch_secs: u64,
    expires_secs: u64,
) -> Result<String, String> {
    if !credentials.is_usable() {
        return Err("ambient credentials are incomplete (need access key, secret key and region)".into());
    }
    if host.is_empty() || host.contains('/') || host.contains(':') || host.contains('@') {
        return Err(format!("invalid STS host {host:?} — expected a bare hostname"));
    }
    if expires_secs == 0 {
        return Err("presigned proof expiry must be at least one second".into());
    }
    if expires_secs > PROOF_MAX_VALIDITY_SECS {
        return Err(format!(
            "presigned proof expiry {expires_secs}s exceeds the {PROOF_MAX_VALIDITY_SECS}s RFC cap"
        ));
    }

    let amz_date = format_amz_date(now_epoch_secs);
    let datestamp = amz_date_stamp(now_epoch_secs);

    let mut signed_headers: Vec<&str> = vec!["host", "x-amz-date"];
    if credentials.session_token.as_deref().is_some_and(|t| !t.is_empty()) {
        signed_headers.push("x-amz-security-token");
    }
    signed_headers.sort_unstable();

    // Canonical query: every X-Amz-* parameter except the signature itself,
    // percent-encoded and sorted by key.
    let mut query: Vec<(String, String)> = vec![
        ("Action".to_string(), STS_ACTION.to_string()),
        ("Version".to_string(), STS_VERSION.to_string()),
        ("X-Amz-Algorithm".to_string(), SIGV4_ALGORITHM.to_string()),
        (
            "X-Amz-Credential".to_string(),
            format!(
                "{}/{}/{}/{}/{}",
                credentials.access_key_id, datestamp, credentials.region, STS_SERVICE, SIGV4_TERMINATOR
            ),
        ),
        ("X-Amz-Date".to_string(), amz_date.clone()),
        ("X-Amz-Expires".to_string(), expires_secs.to_string()),
        ("X-Amz-SignedHeaders".to_string(), signed_headers.join(";")),
    ];
    if let Some(token) = credentials.session_token.as_deref().filter(|t| !t.is_empty()) {
        query.push(("X-Amz-Security-Token".to_string(), token.to_string()));
    }
    query.sort_by(|a, b| a.0.cmp(&b.0));
    let canonical_query: Vec<String> = query
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
        .collect();
    let canonical_query = canonical_query.join("&");

    let canonical_headers = signed_headers
        .iter()
        .map(|h| {
            let value = match *h {
                "host" => host.to_string(),
                "x-amz-date" => amz_date.clone(),
                "x-amz-security-token" => credentials.session_token.clone().unwrap_or_default(),
                other => other.to_string(),
            };
            format!("{}:{}\n", h, value)
        })
        .collect::<String>();

    let canonical_request = format!(
        "GET\n/\n{}\n{}\n{}\nUNSIGNED-PAYLOAD",
        canonical_query,
        canonical_headers,
        signed_headers.join(";")
    );

    let scope = format!(
        "{}/{}/{}/{}",
        datestamp, credentials.region, STS_SERVICE, SIGV4_TERMINATOR
    );
    let string_to_sign = format!(
        "{}\n{}\n{}\n{}",
        SIGV4_ALGORITHM,
        amz_date,
        scope,
        hex(&sha256(canonical_request.as_bytes()))
    );

    let k_date = hmac_sha256(
        format!("AWS4{}", credentials.secret_access_key).as_bytes(),
        datestamp.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, credentials.region.as_bytes());
    let k_service = hmac_sha256(&k_region, STS_SERVICE.as_bytes());
    let k_signing = hmac_sha256(&k_service, SIGV4_TERMINATOR.as_bytes());
    let signature = hex(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    Ok(format!(
        "https://{host}/?{canonical_query}&X-Amz-Signature={signature}",
    ))
}

/// Extract the caller ARN from an `sts:GetCallerIdentity` response body.
///
/// STS answers a query-protocol action in whichever of three shapes the
/// request negotiated, so all of them are accepted: JSON with the result at the
/// top level, JSON wrapped in the protocol envelope, and the default XML.
/// Anything else yields None and the caller is rejected.
pub fn parse_caller_identity_arn(body: &str) -> Option<String> {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
        for candidate in [
            value.pointer("/Arn").and_then(serde_json::Value::as_str),
            value
                .pointer("/GetCallerIdentityResponse/GetCallerIdentityResult/Arn")
                .and_then(serde_json::Value::as_str),
            value
                .pointer("/GetCallerIdentityResult/Arn")
                .and_then(serde_json::Value::as_str),
        ] {
            if let Some(arn) = candidate.filter(|a| a.starts_with("arn:")) {
                return Some(arn.to_string());
            }
        }
        return None;
    }
    // XML: <GetCallerIdentityResult><Arn>arn:...</Arn>...</GetCallerIdentityResult>
    let start = body.find("<Arn>")? + "<Arn>".len();
    let end = body[start..].find("</Arn>")? + start;
    let arn = body[start..end].trim();
    if arn.starts_with("arn:") {
        Some(arn.to_string())
    } else {
        None
    }
}

/// Normalize a caller ARN to a stable role identity for allowlist matching:
/// `arn:aws:sts::123:assumed-role/role-name/session` → `arn:aws:iam::123:role/role-name`.
/// IRSA and ECS assume the role through STS, so the assumed-role ARN is what
/// arrives on the wire; the IAM role ARN is what operators configure.
pub fn normalize_caller_arn(arn: &str) -> String {
    let mut segments = arn.split(':');
    // arn : partition : service : region : account : resource...
    let (Some("arn"), Some(partition), Some(service), Some(_region), Some(account)) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return arn.to_string();
    };
    let resource = segments.collect::<Vec<&str>>().join(":");
    match resource.split_once('/') {
        Some(("assumed-role", tail)) => match tail.split_once('/') {
            Some((role, _session)) => format!("arn:{partition}:iam::{account}:role/{role}"),
            None => format!("arn:{partition}:iam::{account}:role/{tail}"),
        },
        _ if service == "iam" => arn.to_string(),
        _ => arn.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Replay guard
// ---------------------------------------------------------------------------

/// Bounded, in-memory record of proofs already spent.
///
/// Each proof is only meaningful for its own (≤60s) window, so remembering the
/// signature fingerprints for that window is enough to make a captured proof
/// unusable a second time. Bounded so a flood of distinct proofs cannot grow
/// the process without limit.
pub struct ReplayGuard {
    window_secs: u64,
    capacity: usize,
    seen: Mutex<Vec<(String, u64)>>,
}

impl ReplayGuard {
    pub fn new(window_secs: u64, capacity: usize) -> Self {
        Self {
            window_secs,
            capacity: capacity.max(1),
            seen: Mutex::new(Vec::new()),
        }
    }

    /// Record `signature` as spent. Returns true when this is its first use
    /// (the caller may proceed) and false when it is a replay.
    pub fn claim(&self, signature: &str, now_epoch_secs: u64) -> bool {
        let mut seen = match self.seen.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let cutoff = now_epoch_secs.saturating_sub(self.window_secs);
        seen.retain(|(_, at)| *at >= cutoff);
        if seen.iter().any(|(sig, _)| sig == signature) {
            return false;
        }
        seen.push((signature.to_string(), now_epoch_secs));
        if seen.len() > self.capacity {
            // Drop the oldest entries; ordering is insertion order.
            let excess = seen.len() - self.capacity;
            seen.drain(0..excess);
        }
        true
    }

    pub fn len(&self) -> usize {
        self.seen
            .lock()
            .map(|seen| seen.len())
            .unwrap_or_else(|poisoned| poisoned.into_inner().len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new(PROOF_MAX_VALIDITY_SECS, 20_000)
    }
}

/// Refresh interval for a proof the shim mints for `expires_secs` validity:
/// re-mint at half life so a request is never sent with a proof about to
/// expire mid-flight.
pub fn refresh_interval(expires_secs: u64) -> Duration {
    Duration::from_secs((expires_secs.min(PROOF_MAX_VALIDITY_SECS) / 2).max(1))
}

// ---------------------------------------------------------------------------
// Crypto primitives (SigV4 needs HMAC-SHA256; `sha2` is already a dependency)
// ---------------------------------------------------------------------------

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// HMAC-SHA256 (RFC 2104) over `sha2`'s block-level primitive.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut padded = [0u8; BLOCK];
    if key.len() > BLOCK {
        padded[..32].copy_from_slice(&sha256(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }

    let mut inner_key = [0x36u8; BLOCK];
    let mut outer_key = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        inner_key[i] ^= padded[i];
        outer_key[i] ^= padded[i];
    }

    let mut inner = Sha256::new();
    inner.update(inner_key);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_key);
    outer.update(inner_digest);
    outer.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
    }
    out
}

/// AWS SigV4 compact timestamp: `YYYYMMDDTHHMMSSZ`.
const AMZ_DATE_FORMAT: &[time::format_description::FormatItem<'static>] =
    time::macros::format_description!("[year][month][day]T[hour][minute][second]Z");

fn format_amz_date(unix_secs: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix_secs as i64)
        .ok()
        .and_then(|dt| dt.format(&AMZ_DATE_FORMAT).ok())
        .unwrap_or_else(|| "19700101T000000Z".to_string())
}

fn parse_amz_date(value: &str) -> Option<u64> {
    // The format carries no offset, so parse into a naive date-time and treat
    // it as UTC — which is what a SigV4 timestamp is.
    time::PrimitiveDateTime::parse(value, &AMZ_DATE_FORMAT)
        .ok()
        .map(|dt| dt.assume_utc())
        .and_then(|dt| u64::try_from(dt.unix_timestamp()).ok())
}

fn amz_date_stamp(unix_secs: u64) -> String {
    let formatted = format_amz_date(unix_secs);
    formatted.get(..8).unwrap_or("19700101").to_string()
}

/// AWS URI encoding: unreserved characters pass through, everything else is
/// percent-encoded from its uppercase hex.
fn uri_encode(value: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        let keep = byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (*byte == b'/' && !encode_slash);
        if keep {
            out.push(*byte as char);
        } else {
            out.push('%');
            out.push(char::from_digit((byte >> 4) as u32, 16).unwrap().to_ascii_uppercase());
            out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap().to_ascii_uppercase());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_caller_identity_arn_reads_every_sts_response_shape() {
        let arn = "arn:aws:sts::123456789012:assumed-role/octobroker-bot/bot-a";
        let json = serde_json::json!({
            "GetCallerIdentityResponse": {
                "GetCallerIdentityResult": { "Arn": arn, "UserId": "AROA:bot" }
            }
        });
        assert_eq!(
            parse_caller_identity_arn(&json.to_string()).as_deref(),
            Some(arn)
        );
        let xml = format!(
            "<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>{arn}</Arn>\
             <UserId>AROA:bot</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>"
        );
        assert_eq!(parse_caller_identity_arn(&xml).as_deref(), Some(arn));
        assert_eq!(parse_caller_identity_arn("<html>nope</html>"), None);
    }

    const NOW: u64 = 1_780_000_000;

    fn test_creds() -> AmbientCredentials {
        AmbientCredentials {
            access_key_id: "ASIAEXAMPLEKEYID01".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: Some("FwoGZXIvYXdzEExampleSessionToken".to_string()),
            region: "us-east-1".to_string(),
            account_id: None,
        }
    }

    #[test]
    fn test_hmac_matches_rfc4231_case_two() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn test_hmac_handles_keys_longer_than_the_block_size() {
        let key = [0xaa_u8; 131];
        let mac = hmac_sha256(&key, b"Test Using Larger Than Block-Size Key - Hash Key First");
        assert_eq!(
            hex(&mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn test_amz_date_roundtrip() {
        // 1_780_000_000 == 20601 days after the epoch, i.e. 2026-05-28T20:26:40Z.
        assert_eq!(NOW / 86_400, 20_601);
        assert_eq!(format_amz_date(NOW), "20260528T202640Z");
        assert_eq!(parse_amz_date("20260528T202640Z"), Some(NOW));
        assert_eq!(parse_amz_date("nonsense"), None);
        assert_eq!(amz_date_stamp(NOW), "20260528");
    }

    #[test]
    fn test_uri_encode_matches_sigv4_rules() {
        assert_eq!(uri_encode("a b", true), "a%20b");
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
        assert_eq!(uri_encode("a/b", false), "a/b");
        assert_eq!(uri_encode("-_.~AZaz09", true), "-_.~AZaz09");
    }

    #[test]
    fn test_normalize_caller_arn_maps_assumed_role_to_iam_role() {
        assert_eq!(
            normalize_caller_arn("arn:aws:sts::123456789012:assumed-role/octobroker-bot/bot-a"),
            "arn:aws:iam::123456789012:role/octobroker-bot"
        );
        // Other partitions keep their partition.
        assert_eq!(
            normalize_caller_arn("arn:aws-us-gov:sts::1:assumed-role/r/s"),
            "arn:aws-us-gov:iam::1:role/r"
        );
        // Already-normalized IAM ARNs pass through unchanged.
        let iam = "arn:aws:iam::123456789012:role/octobroker-bot";
        assert_eq!(normalize_caller_arn(iam), iam);
        // Not a role ARN → returned as-is rather than mangled.
        assert_eq!(normalize_caller_arn("arn:aws:iam::1:user/x"), "arn:aws:iam::1:user/x");
        assert_eq!(normalize_caller_arn("garbage"), "garbage");
    }

    #[test]
    fn test_presign_preserves_exact_rfc_cap() {
        assert_eq!(
            refresh_interval(PROOF_MAX_VALIDITY_SECS),
            Duration::from_secs(30)
        );
        assert_eq!(refresh_interval(1), Duration::from_secs(1));
        assert_eq!(refresh_interval(600), Duration::from_secs(30));
    }

    #[test]
    fn test_presign_rejects_incomplete_credentials_and_host() {
        let mut creds = test_creds();
        creds.secret_access_key = String::new();
        assert!(presign_get_caller_identity(&creds, "sts.amazonaws.com", NOW, 30).is_err());
        assert!(presign_get_caller_identity(&test_creds(), "https://sts", NOW, 30).is_err());
        assert!(presign_get_caller_identity(&test_creds(), "sts.amazonaws.com:443", NOW, 30).is_err());
        assert!(presign_get_caller_identity(&test_creds(), "sts.amazonaws.com", NOW, 0).is_err());
    }

    #[test]
    fn test_presign_without_session_token_omits_security_token_header() {
        let creds = AmbientCredentials {
            session_token: None,
            ..test_creds()
        };
        let proof = presign_get_caller_identity(&creds, "sts.amazonaws.com", NOW, 30).unwrap();
        assert!(!proof.contains("X-Amz-Security-Token"));
        assert!(proof.contains("X-Amz-SignedHeaders=host%3Bx-amz-date"));
        assert!(verify_presigned_proof(&proof, NOW, &IamProofPolicy::default()).is_ok());
    }

    #[test]
    fn test_presign_rejects_expiry_beyond_the_rfc_cap() {
        // Refused loudly rather than silently shortened: a caller must never
        // believe it holds a window the proxy would reject.
        let err =
            presign_get_caller_identity(&test_creds(), "sts.amazonaws.com", NOW, 3600).unwrap_err();
        assert!(err.contains("RFC cap"), "unexpected error: {}", err);
        let ok = presign_get_caller_identity(&test_creds(), "sts.amazonaws.com", NOW, 60).unwrap();
        assert!(ok.contains("X-Amz-Expires=60"));
        assert!(verify_presigned_proof(&ok, NOW, &IamProofPolicy::default()).is_ok());
    }

    #[test]
    fn test_policy_from_config_clamps_and_validates() {
        assert_eq!(
            IamProofPolicy::from_config(3600).max_validity_secs,
            PROOF_MAX_VALIDITY_SECS
        );
        assert!(IamProofPolicy::from_config(3600).validate().is_ok());
        assert_eq!(IamProofPolicy::from_config(0).max_validity_secs, PROOF_MAX_VALIDITY_SECS);
        assert_eq!(IamProofPolicy::from_config(20).max_validity_secs, 20);
    }

    #[test]
    fn test_policy_validation_rejects_widened_controls() {
        let mut policy = IamProofPolicy::default();
        policy.allowed_actions = vec!["AssumeRole".to_string()];
        assert!(policy.validate().is_err());

        let mut skew = IamProofPolicy::default();
        skew.clock_skew_secs = 120;
        assert!(skew.validate().is_err(), "skew must not exceed the proof lifetime");

        let mut headers = IamProofPolicy::default();
        headers.allowed_signed_headers = vec!["x-amz-date".to_string()];
        assert!(headers.validate().is_err(), "host must remain required");
    }

    #[test]
    fn test_replay_guard_drops_stale_entries() {
        let guard = ReplayGuard::new(60, 4);
        assert!(guard.is_empty());
        assert!(guard.claim("aa", NOW));
        assert!(!guard.claim("aa", NOW));
        assert!(guard.claim("bb", NOW + 61));
        assert!(guard.claim("aa", NOW + 62));
        assert_eq!(guard.len(), 2);
    }
}