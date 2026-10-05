//! Phase 3 operational hardening regression suite (issue #18).
//!
//! The modules under test are pure (no `crate::` references) so this file can
//! include them directly with `#[path]` — the package is a binary-only crate
//! and has no library target to import from.
//!
//! Coverage:
//! - `iam`: SigV4 presigned `sts:GetCallerIdentity` proof shape validation
//!   (TLS, host/region allowlists, <=60s validity, strict signed-header
//!   validation), proof minting, replay guard, and caller-ARN extraction.
//! - `quota`: per-agent token bucket, `Retry-After` parsing/clamping,
//!   upstream circuit breaker, idempotent-read exponential backoff.
//! - `metrics`: MCP request/deny/upstream-latency accounting and the
//!   Prometheus rendering used by the dashboards.
//! - `session_store`: shared (cross-replica) MCP session pin state, including
//!   the fail-closed rule that token material is never journalled.

#![allow(dead_code)]

#[path = "../src/iam.rs"]
mod iam;
#[path = "../src/metrics.rs"]
mod metrics;
#[path = "../src/quota.rs"]
mod quota;
#[path = "../src/session_store.rs"]
mod session_store;

use iam::{
    presign_get_caller_identity, verify_presigned_proof, AmbientCredentials, IamProofPolicy,
    ProofRejection, ReplayGuard, STS_ACTION,
};
use metrics::{Metrics, Outcome};
use quota::{parse_retry_after, backoff_ms, Decision, QuotaConfig, QuotaRegistry};
use session_store::{PinCredRecord, PinStore, PinnedCred, SessionPin};

// ---------------------------------------------------------------------------
// iam: presigned STS proof validation
// ---------------------------------------------------------------------------

const T0: u64 = 1_780_000_000; // 2026-05-29T14:26:40Z

fn creds() -> AmbientCredentials {
    AmbientCredentials {
        access_key_id: "ASIAEXAMPLEKEYID01".to_string(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
        session_token: Some("FwoGZXIvYXdzEExampleSessionToken".to_string()),
        region: "us-east-1".to_string(),
        account_id: None,
    }
}

fn policy() -> IamProofPolicy {
    IamProofPolicy::default()
}

fn mint(now: u64, expires: u64) -> Result<String, String> {
    presign_get_caller_identity(&creds(), "sts.amazonaws.com", now, expires)
}

#[test]
fn iam_minted_proof_verifies() {
    let proof = mint(T0, 45).unwrap();
    let verified = verify_presigned_proof(&proof, T0 + 5, &policy()).unwrap();
    assert_eq!(verified.host, "sts.amazonaws.com");
    assert_eq!(verified.region, "us-east-1");
    assert_eq!(verified.access_key_id, "ASIAEXAMPLEKEYID01");
    assert_eq!(verified.expires_in_secs, 45);
    assert!(verified.signed_headers.contains(&"host".to_string()));
    assert!(verified.signed_headers.contains(&"x-amz-date".to_string()));
}

#[test]
fn iam_proof_never_carries_secret_material() {
    let proof = mint(T0, 45).unwrap();
    // The proof must NOT contain the secret access key. The session token is
    // part of the SigV4 signature input (a legitimate presigned-URL component)
    // but the SECRET access key must never appear.
    assert!(
        !proof.contains("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
        "secret access key leaked into proof: {}",
        proof
    );
    assert!(proof.starts_with("https://sts.amazonaws.com/?"));
}

#[test]
fn iam_rejects_non_tls_proof() {
    let https = mint(T0, 45).unwrap();
    let http = https.replacen("https://", "http://", 1);
    assert_eq!(
        verify_presigned_proof(&http, T0, &policy()),
        Err(ProofRejection::NotHttps)
    );
    assert_eq!(
        verify_presigned_proof("sts.amazonaws.com/?X-Amz-Algorithm=AWS4-HMAC-SHA256", T0, &policy()),
        Err(ProofRejection::NotHttps)
    );
}

#[test]
fn iam_rejects_host_outside_allowlist() {
    let proof = mint(T0, 45).unwrap();
    let evil = proof.replacen("sts.amazonaws.com", "sts.attacker.example", 1);
    assert_eq!(
        verify_presigned_proof(&evil, T0, &policy()),
        Err(ProofRejection::HostNotAllowed)
    );
}

#[test]
fn iam_host_allowlist_is_case_insensitive_but_port_is_rejected() {
    let mut p = policy();
    p.allowed_hosts = vec!["STS.amazonaws.com".to_string()];
    let upper = mint(T0, 45).unwrap().replacen("sts.amazonaws.com", "STS.AMAZONAWS.COM", 1);
    assert!(verify_presigned_proof(&upper, T0, &p).is_ok());

    let with_port = mint(T0, 45)
        .unwrap()
        .replacen("sts.amazonaws.com", "sts.amazonaws.com:443", 1);
    assert_eq!(
        verify_presigned_proof(&with_port, T0, &p),
        Err(ProofRejection::MalformedUrl)
    );
}

#[test]
fn iam_rejects_non_getcalleridentity_action() {
    let proof = mint(T0, 45).unwrap().replacen(
        "Action=GetCallerIdentity",
        "Action=AssumeRole",
        1,
    );
    assert_eq!(
        verify_presigned_proof(&proof, T0, &policy()),
        Err(ProofRejection::ActionNotAllowed)
    );
}

#[test]
fn iam_rejects_unknown_sts_version() {
    let proof = mint(T0, 45).unwrap().replacen("Version=2011-06-15", "Version=2000-01-01", 1);
    assert_eq!(
        verify_presigned_proof(&proof, T0, &policy()),
        Err(ProofRejection::VersionNotSupported)
    );
}

#[test]
fn iam_enforces_rfc_sixty_second_cap() {
    // Exactly at the cap: accepted.
    let ok = mint(T0, iam::PROOF_MAX_VALIDITY_SECS).unwrap();
    assert!(verify_presigned_proof(&ok, T0, &policy()).is_ok());

    // One second past the cap: rejected without any network round trip.
    let too_long = mint(T0, iam::PROOF_MAX_VALIDITY_SECS)
        .unwrap()
        .replacen("X-Amz-Expires=60", "X-Amz-Expires=61", 1);
    assert_eq!(
        verify_presigned_proof(&too_long, T0, &policy()),
        Err(ProofRejection::ExpiryTooLong {
            requested: 61,
            max: 60,
        })
    );

    // A tighter operator setting still accepts what it allows.
    let mut strict = policy();
    strict.max_validity_secs = 30;
    let short = mint(T0, 30).unwrap();
    assert!(verify_presigned_proof(&short, T0, &strict).is_ok());
    assert!(verify_presigned_proof(&ok, T0, &strict).is_err());

    // Config may tighten the cap but never raise it past the RFC limit.
    assert_eq!(IamProofPolicy::from_config(3_600).max_validity_secs, 60);
    assert_eq!(IamProofPolicy::from_config(0).max_validity_secs, 60);
    let mut widened = IamProofPolicy::default();
    widened.max_validity_secs = 61;
    assert!(widened.validate().is_err());
    assert!(IamProofPolicy::default().validate().is_ok());
}

#[test]
fn iam_rejects_expired_and_future_dated_proofs() {
    let proof = mint(T0, 10).unwrap();
    assert_eq!(
        verify_presigned_proof(&proof, T0 + 11, &policy()),
        Err(ProofRejection::Expired)
    );
    assert!(
        verify_presigned_proof(&proof, T0 + 10, &policy()).is_ok(),
        "valid through the last second of the window"
    );

    let mut p = policy();
    p.clock_skew_secs = 0;
    assert_eq!(
        verify_presigned_proof(&proof, T0 - 1, &p),
        Err(ProofRejection::DateInFuture { skew: 0 })
    );
}

#[test]
fn iam_rejects_region_outside_allowlist() {
    let eu = presign_get_caller_identity(
        &AmbientCredentials {
            region: "eu-west-1".to_string(),
            ..creds()
        },
        "sts.amazonaws.com",
        T0,
        45,
    )
    .unwrap();
    assert_eq!(
        verify_presigned_proof(&eu, T0, &policy()),
        Err(ProofRejection::RegionNotAllowed)
    );
}

#[test]
fn iam_rejects_malformed_signature() {
    let proof = mint(T0, 45).unwrap();
    let sig_at = proof.find("X-Amz-Signature=").unwrap() + "X-Amz-Signature=".len();

    let short = proof.replace(&proof[sig_at..sig_at + 64], "deadbeef");
    assert_eq!(
        verify_presigned_proof(&short, T0, &policy()),
        Err(ProofRejection::SignatureInvalid)
    );

    // Uppercase hex is not the canonical SigV4 form.
    let upper = format!(
        "{}X-Amz-Signature={}",
        &proof[..sig_at],
        proof[sig_at..sig_at + 64].to_ascii_uppercase()
    );
    assert_eq!(
        verify_presigned_proof(&upper, T0, &policy()),
        Err(ProofRejection::SignatureInvalid)
    );

    assert_eq!(
        verify_presigned_proof(&proof.replace("X-Amz-Signature=", "X-Amz-Signature="), T0, &policy()).is_ok(),
        true,
        "baseline sanity"
    );
}

/// Documents *why* the proxy replays the proof to STS instead of trusting a
/// local signature check: flipping a hex digit keeps the proof structurally
/// valid, so no local validator can reject it. The signature itself is only
/// ever checked by the party holding the secret — STS.
#[test]
fn iam_cannot_locally_detect_a_well_formed_signature_flip() {
    let proof = mint(T0, 45).unwrap();
    let sig_at = proof.find("X-Amz-Signature=").unwrap() + "X-Amz-Signature=".len();
    let first = proof.as_bytes()[sig_at];
    let replacement = if first == b'a' { 'b' } else { 'a' };
    let mut flipped = proof.clone();
    flipped.replace_range(sig_at..sig_at + 1, &replacement.to_string());
    assert!(
        verify_presigned_proof(&flipped, T0, &policy()).is_ok(),
        "a structurally valid flip is undetectable locally by design"
    );
    assert_ne!(
        verify_presigned_proof(&proof, T0, &policy())
            .unwrap()
            .signature,
        verify_presigned_proof(&flipped, T0, &policy())
            .unwrap()
            .signature,
        "the flip does change the signature the proxy hands to STS"
    );
}

#[test]
fn iam_signed_headers_must_be_sorted_unique_and_allowlisted() {
    // Unsigned `host` → rejected.
    let signed = "X-Amz-SignedHeaders=host%3Bx-amz-date%3Bx-amz-security-token";
    let proof = mint(T0, 45)
        .unwrap()
        .replacen(signed, "X-Amz-SignedHeaders=x-amz-date", 1);
    assert_eq!(
        verify_presigned_proof(&proof, T0, &policy()),
        Err(ProofRejection::RequiredHeaderUnsigned("host".to_string()))
    );

    // A signed header outside the allowlist → rejected.
    let extra = mint(T0, 45)
        .unwrap()
        .replacen(signed, "X-Amz-SignedHeaders=host%3Buser-agent", 1);
    assert_eq!(
        verify_presigned_proof(&extra, T0, &policy()),
        Err(ProofRejection::SignedHeaderNotAllowed("user-agent".to_string()))
    );

    // Unsorted signed-header list → rejected.
    let unsorted = mint(T0, 45).unwrap().replacen(
        "X-Amz-SignedHeaders=host%3Bx-amz-date%3Bx-amz-security-token",
        "X-Amz-SignedHeaders=host%3Bx-amz-security-token%3Bx-amz-date",
        1,
    );
    assert_eq!(
        verify_presigned_proof(&unsorted, T0, &policy()),
        Err(ProofRejection::SignedHeadersInvalid("not sorted"))
    );
}

#[test]
fn iam_rejects_missing_and_duplicate_query_parameters() {
    let proof = mint(T0, 45).unwrap();
    let no_action = proof.replace("Action=GetCallerIdentity&", "");
    assert_eq!(
        verify_presigned_proof(&no_action, T0, &policy()),
        Err(ProofRejection::QueryMissing("Action"))
    );

    let dup = format!(
        "{}&Action={}",
        proof.split("X-Amz-Signature=").next().unwrap(),
        STS_ACTION
    );
    assert_eq!(
        verify_presigned_proof(&dup, T0, &policy()),
        Err(ProofRejection::DuplicateQueryKey("Action".to_string()))
    );
}

#[test]
fn iam_rejects_credential_scope_tampering() {
    // Scope date must agree with X-Amz-Date, service must be sts, terminator
    // must be aws4_request.
    let wrong_service = mint(T0, 45)
        .unwrap()
        .replacen("%2Fsts%2Faws4_request", "%2Fs3%2Faws4_request", 1);
    assert_eq!(
        verify_presigned_proof(&wrong_service, T0, &policy()),
        Err(ProofRejection::CredentialScopeInvalid)
    );

    let wrong_terminator = mint(T0, 45)
        .unwrap()
        .replacen("%2Faws4_request", "%2Faws5_request", 1);
    assert_eq!(
        verify_presigned_proof(&wrong_terminator, T0, &policy()),
        Err(ProofRejection::CredentialScopeInvalid)
    );
}

#[test]
fn iam_rejects_non_sigv4_algorithm() {
    let proof = mint(T0, 45)
        .unwrap()
        .replacen("X-Amz-Algorithm=AWS4-HMAC-SHA256", "X-Amz-Algorithm=AWS4-ECDSA-P256-SHA256", 1);
    assert_eq!(
        verify_presigned_proof(&proof, T0, &policy()),
        Err(ProofRejection::AlgorithmNotSigV4)
    );
}

#[test]
fn iam_replay_guard_single_uses_each_proof() {
    let mut guard = ReplayGuard::new(60, 128);
    let proof = mint(T0, 45).unwrap();
    let sig = proof
        .split("X-Amz-Signature=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_string();

    assert!(guard.claim(&sig, T0), "first use is fresh");
    assert!(!guard.claim(&sig, T0 + 1), "second use inside the window is a replay");
    // Once the window has passed the signature cannot be replayed anyway
    // (expiry validation rejects it first), so the guard forgets it.
    assert!(guard.claim(&sig, T0 + 61), "guard forgets entries past the window");
}

#[test]
fn iam_replay_guard_is_bounded() {
    let mut guard = ReplayGuard::new(60, 8);
    for i in 0..64 {
        assert!(guard.claim(&format!("{:064x}", i), T0));
    }
    assert!(guard.len() <= 8, "guard grew to {}", guard.len());
}

#[test]
fn iam_parses_caller_identity_arn() {
    let body = r#"{"Arn":"arn:aws:sts::123456789012:assumed-role/octobroker-agent/bot-a","UserId":"AROA:bot"}"#;
    assert_eq!(
        iam::parse_caller_identity_arn(body).as_deref(),
        Some("arn:aws:sts::123456789012:assumed-role/octobroker-agent/bot-a")
    );
    assert_eq!(iam::parse_caller_identity_arn("not json"), None);
    assert_eq!(iam::parse_caller_identity_arn("{}"), None);
}

#[test]
fn iam_policy_rejects_empty_allowlists() {
    let mut p = policy();
    p.allowed_hosts.clear();
    assert!(p.validate().is_err(), "an empty host allowlist would accept nothing");
    let mut q = policy();
    q.allowed_regions.clear();
    assert!(q.validate().is_err());
    let mut r = policy();
    r.allowed_actions.clear();
    assert!(r.validate().is_err());
}

// ---------------------------------------------------------------------------
// quota: per-agent rate quotas, Retry-After, circuit breaker
// ---------------------------------------------------------------------------

fn quota_cfg() -> QuotaConfig {
    QuotaConfig {
        enabled: true,
        per_agent_per_min: 60.0,
        per_agent_burst: 3.0,
        retry_after_cap_secs: 120,
        circuit_failure_threshold: 2,
        circuit_cooldown_secs: 30,
        circuit_half_open_successes: 1,
        retry_max_attempts: 3,
        retry_base_backoff_ms: 100,
        retry_max_backoff_ms: 1_000,
    }
}

#[test]
fn quota_token_bucket_throttles_noisy_neighbour() {
    let q = QuotaRegistry::new(quota_cfg());
    assert_eq!(q.check("a", 0), Decision::Allow);
    assert_eq!(q.check("a", 0), Decision::Allow);
    assert_eq!(q.check("a", 0), Decision::Allow);
    match q.check("a", 0) {
        Decision::Throttled { retry_after_secs } => assert!(retry_after_secs >= 1),
        other => panic!("expected throttle, got {:?}", other),
    }
    // A second agent has its own bucket.
    assert_eq!(q.check("b", 0), Decision::Allow);
}

#[test]
fn quota_bucket_refills_over_time() {
    let q = QuotaRegistry::new(quota_cfg());
    for _ in 0..3 {
        assert_eq!(q.check("a", 0), Decision::Allow);
    }
    assert!(matches!(q.check("a", 0), Decision::Throttled { .. }));
    // 60/min = 1/s; after one full second exactly one token is back.
    assert_eq!(q.check("a", 1_000), Decision::Allow);
}

#[test]
fn quota_disabled_never_throttles() {
    let mut cfg = quota_cfg();
    cfg.enabled = false;
    let q = QuotaRegistry::new(cfg);
    for i in 0..50 {
        assert_eq!(q.check("a", i * 1_000), Decision::Allow);
    }
}

#[test]
fn quota_circuit_opens_after_repeated_upstream_failures() {
    let q = QuotaRegistry::new(quota_cfg());
    q.record_upstream_failure("a", 0);
    assert_eq!(q.check("a", 0), Decision::Allow, "one failure does not trip");
    q.record_upstream_failure("a", 0);
    match q.check("a", 0) {
        Decision::CircuitOpen { retry_after_secs } => assert_eq!(retry_after_secs, 30),
        other => panic!("expected circuit open, got {:?}", other),
    }
}

#[test]
fn quota_circuit_half_opens_then_closes_on_success() {
    let q = QuotaRegistry::new(quota_cfg());
    q.record_upstream_failure("a", 0);
    q.record_upstream_failure("a", 0);
    assert!(matches!(q.check("a", 0), Decision::CircuitOpen { .. }));

    // After the cooldown exactly one probe is admitted...
    assert_eq!(q.check("a", 30_000), Decision::Allow);
    // ...and a concurrent second probe is still refused.
    assert!(matches!(q.check("a", 30_000), Decision::CircuitOpen { .. }));

    q.record_success("a", 30_100);
    assert_eq!(q.check("a", 30_200), Decision::Allow, "circuit closed again");
    let snap = q.snapshot();
    let a = snap.iter().find(|s| s.agent == "a").unwrap();
    assert!(!a.circuit_open);
    assert_eq!(a.consecutive_failures, 0);
}

#[test]
fn quota_circuit_reopens_when_probe_fails() {
    let q = QuotaRegistry::new(quota_cfg());
    q.record_upstream_failure("a", 0);
    q.record_upstream_failure("a", 0);
    assert!(matches!(q.check("a", 0), Decision::CircuitOpen { .. }));
    assert_eq!(q.check("a", 30_000), Decision::Allow);
    q.record_upstream_failure("a", 30_050);
    match q.check("a", 30_060) {
        Decision::CircuitOpen { retry_after_secs } => assert_eq!(retry_after_secs, 30),
        other => panic!("expected reopened circuit, got {:?}", other),
    }
}

#[test]
fn quota_upstream_throttle_sets_cooldown_and_clamps_retry_after() {
    let q = QuotaRegistry::new(quota_cfg());
    let applied = q.record_upstream_throttle("a", Some(86_400), 0);
    assert_eq!(applied, 120, "Retry-After is clamped to the configured cap");
    match q.check("a", 1_000) {
        Decision::Throttled { retry_after_secs } => assert_eq!(retry_after_secs, 119),
        other => panic!("expected throttle, got {:?}", other),
    }

    let honoured = q.record_upstream_throttle("a", Some(5), 0);
    assert_eq!(honoured, 5, "a shorter Retry-After is honoured verbatim");
}

#[test]
fn quota_snapshot_counts_allow_and_reject() {
    let q = QuotaRegistry::new(quota_cfg());
    for _ in 0..3 {
        q.check("a", 0);
    }
    q.check("a", 0); // rejected
    let snap = q.snapshot();
    let a = snap.iter().find(|s| s.agent == "a").unwrap();
    assert_eq!(a.allowed, 3);
    assert_eq!(a.rejected, 1);
}

#[test]
fn quota_config_validation_rejects_unusable_values() {
    let mut c = quota_cfg();
    c.per_agent_per_min = 0.0;
    assert!(c.validate().is_err());
    let mut d = quota_cfg();
    d.per_agent_burst = 0.0;
    assert!(d.validate().is_err());
    let mut e = quota_cfg();
    e.circuit_failure_threshold = 0;
    assert!(e.validate().is_err());
    let mut f = quota_cfg();
    f.retry_max_attempts = 0;
    assert!(f.validate().is_err());
    let mut g = quota_cfg();
    g.retry_base_backoff_ms = 5_000;
    g.retry_max_backoff_ms = 100;
    assert!(g.validate().is_err());
    let mut h = quota_cfg();
    h.retry_after_cap_secs = 0;
    assert!(h.validate().is_err());
    assert!(quota_cfg().validate().is_ok());
}

#[test]
fn quota_parses_retry_after_delta_seconds_and_http_date() {
    assert_eq!(parse_retry_after("30", 1_000), Some(30));
    assert_eq!(parse_retry_after(" 7 ", 1_000), Some(7));
    assert_eq!(parse_retry_after("", 0), None);
    assert_eq!(parse_retry_after("soon", 0), None);
    assert_eq!(parse_retry_after("-5", 0), None, "a negative delta is not usable");

    // RFC 7231 IMF-fixdate, 40s after now.
    let now = 1_780_000_000u64;
    let when = now + 40;
    let header = imf_fixdate(when);
    assert_eq!(parse_retry_after(&header, now), Some(40));
    // A date already in the past means "retry now".
    assert_eq!(parse_retry_after(&imf_fixdate(now - 10), now), Some(0));
}

#[test]
fn quota_backoff_is_exponential_and_capped() {
    assert_eq!(backoff_ms(1, 100, 1_000), 100);
    assert_eq!(backoff_ms(2, 100, 1_000), 200);
    assert_eq!(backoff_ms(3, 100, 1_000), 400);
    assert_eq!(backoff_ms(9, 100, 1_000), 1_000);
    assert_eq!(backoff_ms(40, 100, 1_000), 1_000, "never exceeds the cap");
    assert_eq!(backoff_ms(0, 100, 1_000), 100);
}

fn imf_fixdate(unix_secs: u64) -> String {
    // Minimal IMF-fixdate formatter so the test does not depend on a clock.
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days_since_epoch = unix_secs / 86_400;
    let secs_of_day = unix_secs % 86_400;
    // 1970-01-01 was a Thursday.
    let weekday = DAYS[(days_since_epoch % 7) as usize];
    let (y, m, d) = civil_from_days(days_since_epoch as i64);
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        weekday,
        d,
        MONTHS[(m - 1) as usize],
        y,
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ---------------------------------------------------------------------------
// metrics: dashboards + alerting
// ---------------------------------------------------------------------------

#[test]
fn metrics_counts_requests_denies_and_upstream_latency() {
    let m = Metrics::new();
    m.observe_mcp(Some("bot-a"), Some("get_me"), Outcome::Allowed);
    m.observe_mcp(Some("bot-a"), Some("create_issue"), Outcome::Denied);
    m.observe_mcp(Some("bot-a"), None, Outcome::QuotaRejected);
    m.observe_mcp(Some("bot-a"), None, Outcome::CircuitOpen);
    m.observe_upstream(Some("bot-a"), 42, 200);
    m.observe_upstream(Some("bot-a"), 1_800, 503);

    let snap = m.snapshot_json();
    assert_eq!(snap["mcp"]["requests"], 4);
    assert_eq!(snap["mcp"]["denied"], 1);
    assert_eq!(snap["mcp"]["quota_rejected"], 1);
    assert_eq!(snap["mcp"]["circuit_open"], 1);
    assert_eq!(snap["mcp"]["upstream"]["requests"], 2);
    assert_eq!(snap["mcp"]["upstream"]["errors"], 1);
    assert_eq!(snap["mcp"]["upstream"]["latency_ms"]["count"], 2);
    assert_eq!(snap["mcp"]["upstream"]["latency_ms"]["sum"], 1_842);
    assert_eq!(snap["mcp"]["by_agent"]["bot-a"]["requests"], 4);
    assert_eq!(snap["mcp"]["by_agent"]["bot-a"]["denied"], 1);
    assert_eq!(snap["mcp"]["by_agent_tool"]["bot-a/create_issue"]["denied"], 1);
}

#[test]
fn metrics_anonymous_agent_is_counted_not_dropped() {
    let m = Metrics::new();
    m.observe_mcp(None, None, Outcome::Allowed);
    let snap = m.snapshot_json();
    assert_eq!(snap["mcp"]["by_agent"]["<anonymous>"]["requests"], 1);
}

#[test]
fn metrics_render_prometheus_dashboards_and_alerts() {
    let m = Metrics::new();
    m.observe_mcp(Some("bot-a"), Some("get_me"), Outcome::Allowed);
    m.observe_mcp(Some("bot-a"), Some("delete_file"), Outcome::Denied);
    m.observe_upstream(Some("bot-a"), 30, 200);

    let text = m.render_prometheus();
    for needle in [
        "octobroker_mcp_requests_total",
        "octobroker_mcp_denied_total",
        "octobroker_mcp_quota_rejected_total",
        "octobroker_mcp_circuit_open_total",
        "octobroker_mcp_upstream_requests_total",
        "octobroker_mcp_upstream_latency_ms_bucket",
        "octobroker_mcp_upstream_latency_ms_sum",
        "octobroker_mcp_by_agent_denied_total{agent=\"bot-a\"}",
    ] {
        assert!(text.contains(needle), "missing metric {} in:\n{}", needle, text);
    }
    // Every rendered line must be a valid Prometheus exposition line.
    for line in text.lines() {
        assert!(
            line.starts_with('#') || line.split(' ').nth(1).is_some_and(|v| {
                v.parse::<f64>().is_ok()
            }),
            "malformed exposition line: {}",
            line
        );
    }
}

#[test]
fn metrics_reset_clears_all_series() {
    let m = Metrics::new();
    m.observe_mcp(Some("bot-a"), None, Outcome::Denied);
    m.observe_upstream(Some("bot-a"), 5, 200);
    m.reset();
    let snap = m.snapshot_json();
    assert_eq!(snap["mcp"]["requests"], 0);
    assert_eq!(snap["mcp"]["by_agent"], serde_json::json!({}));
    assert_eq!(snap["mcp"]["upstream"]["latency_ms"]["count"], 0);
}

// ---------------------------------------------------------------------------
// session_store: shared session state for horizontal scaling
// ---------------------------------------------------------------------------

fn pat_pin(agent: &str, identity: &str) -> SessionPin {
    SessionPin {
        agent_id: Some(agent.to_string()),
        cred: PinnedCred::Pat {
            identity_id: identity.to_string(),
        },
    }
}

fn journal(name: &str) -> String {
    let dir = std::env::temp_dir().join(format!(
        "octobroker-pins-{}-{}-{}",
        std::process::id(),
        name,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("mcp-sessions.jsonl").to_str().unwrap().to_string()
}

#[test]
fn session_store_memory_store_roundtrips_and_expires() {
    let store = PinStore::memory(60);
    store.insert("s1", pat_pin("bot-a", "pat-1"), T0).unwrap();
    assert_eq!(store.get("s1", T0 + 10).unwrap().cred, PinnedCred::Pat { identity_id: "pat-1".into() });
    assert!(store.get("s1", T0 + 61).is_none(), "pin expires with the session TTL");
    store.invalidate("s1", T0).unwrap();
    assert!(store.get("s1", T0).is_none());
}

#[test]
fn session_store_shared_state_is_visible_to_another_replica() {
    let path = journal("shared");
    let replica_a = PinStore::shared(&path, 3600, "replica-a").unwrap();
    let replica_b = PinStore::shared(&path, 3600, "replica-b").unwrap();

    assert!(replica_b.get("s1", T0).is_none());
    replica_a.insert("s1", pat_pin("bot-a", "pat-1"), T0).unwrap();
    let rehydrated = replica_b.get("s1", T0 + 5).expect("pin visible on the other replica");
    assert_eq!(rehydrated.agent_id.as_deref(), Some("bot-a"));
    assert_eq!(rehydrated.cred, PinnedCred::Pat { identity_id: "pat-1".into() });
    assert_eq!(replica_a.get("s1", T0 + 5).unwrap(), rehydrated);

    std::fs::remove_file(&path).ok();
}

#[test]
fn session_store_shared_tombstone_invalidates_on_every_replica() {
    let path = journal("tombstone");
    let a = PinStore::shared(&path, 3600, "replica-a").unwrap();
    let b = PinStore::shared(&path, 3600, "replica-b").unwrap();
    a.insert("s1", pat_pin("bot-a", "pat-1"), T0).unwrap();
    assert!(b.get("s1", T0).is_some());
    a.invalidate("s1", T0 + 1).unwrap();
    assert!(b.get("s1", T0 + 2).is_none(), "tombstone reached replica b");
    std::fs::remove_file(&path).ok();
}

#[test]
fn session_store_journal_never_persists_token_material() {
    let path = journal("no-secrets");
    let a = PinStore::shared(&path, 3600, "replica-a").unwrap();
    let b = PinStore::shared(&path, 3600, "replica-b").unwrap();

    let app_pin = SessionPin {
        agent_id: Some("bot-a".to_string()),
        cred: PinnedCred::App {
            token: "ghs_SUPERSECRETINSTALLATIONTOKEN".to_string(),
            expires_at: T0 + 3600,
        },
    };
    a.insert("s1", app_pin, T0).unwrap();

    let bytes = std::fs::read_to_string(&path).unwrap();
    assert!(
        !bytes.contains("ghs_SUPERSECRETINSTALLATIONTOKEN"),
        "installation token written to the shared journal: {}",
        bytes
    );
    // Fail-closed: a replica that cannot resolve the pin terminates the session
    // rather than re-pinning a different credential.
    assert!(
        b.get("s1", T0 + 1).is_none(),
        "an unresolvable pin must not be served from shared state"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn session_store_shared_is_fail_closed_when_the_journal_is_unwritable() {
    let store = PinStore::shared("/nonexistent-dir/pins.jsonl", 3600, "replica-a");
    assert!(store.is_err(), "an unusable journal path must fail at startup");
}

#[test]
fn session_store_pin_record_never_carries_secrets() {
    let pin = SessionPin {
        agent_id: Some("bot-a".to_string()),
        cred: PinnedCred::App {
            token: "ghs_SUPERSECRET".to_string(),
            expires_at: 42,
        },
    };
    let record = pin.to_record(Some(42), T0);
    let encoded = serde_json::to_string(&record).unwrap();
    assert!(!encoded.contains("ghs_SUPERSECRET"));
    assert_eq!(record.cred, PinCredRecord::App { expires_at: 42 });
    assert!(SessionPin::from_record(&record).is_err());
}