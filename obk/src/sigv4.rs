//! AWS SigV4 presigning of `sts:GetCallerIdentity` — the client half of
//! octobroker's secretless IAM authentication (#18).
//!
//! The output is a presigned URL which octobroker executes server-side to
//! resolve the caller's ARN (same pattern as aws-iam-authenticator). Only the
//! `host` header is signed; proof lifetime is capped at 60s by the server.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Ambient AWS credentials resolved from the environment (env vars, ECS task
/// role, EKS IRSA, instance metadata — via `aws-config`'s default chain).
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

/// The STS endpoint host for a signing region. `""`/none → global endpoint
/// (signing region us-east-1).
pub fn sts_host(region: &str) -> String {
    if region.is_empty() {
        "sts.amazonaws.com".to_string()
    } else if region.starts_with("cn-") {
        format!("sts.{}.amazonaws.com.cn", region)
    } else {
        format!("sts.{}.amazonaws.com", region)
    }
}

/// Presign `GET https://<sts-host>/?Action=GetCallerIdentity...`.
/// `region` is the signing region — for the global endpoint pass the empty
/// string (signs as us-east-1). `expires_secs` ≤ 60.
pub fn presign_get_caller_identity(
    creds: &AwsCredentials,
    region: &str,
    expires_secs: u64,
    now: SystemTime,
) -> String {
    let (host, sign_region) = if region.is_empty() {
        ("sts.amazonaws.com".to_string(), "us-east-1".to_string())
    } else {
        (sts_host(region), region.to_string())
    };
    let unix = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (amz_date, date_stamp) = amz_dates(unix);
    let scope = format!("{}/{}/sts/aws4_request", date_stamp, sign_region);

    let mut params: Vec<(String, String)> = vec![
        ("Action".into(), "GetCallerIdentity".into()),
        ("Version".into(), "2011-06-15".into()),
        ("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()),
        (
            "X-Amz-Credential".into(),
            format!("{}/{}", creds.access_key_id, scope),
        ),
        ("X-Amz-Date".into(), amz_date.clone()),
        ("X-Amz-Expires".into(), expires_secs.to_string()),
        ("X-Amz-SignedHeaders".into(), "host".into()),
    ];
    if let Some(token) = &creds.session_token {
        params.push(("X-Amz-Security-Token".into(), token.clone()));
    }
    params.sort();
    let canonical_query: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k), uri_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let canonical_request = format!(
        "GET\n/\n{}\nhost:{}\n\nhost\nUNSIGNED-PAYLOAD",
        canonical_query, host
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        scope,
        hex(&Sha256::digest(canonical_request.as_bytes()))
    );
    let signing_key = derive_key(&creds.secret_access_key, &date_stamp, &sign_region);
    let signature = hex(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    format!(
        "https://{}/?{}&X-Amz-Signature={}",
        host, canonical_query, signature
    )
}

/// SigV4 URI encoding: unreserved characters pass through, everything else
/// is %XX (uppercase hex).
fn uri_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

fn derive_key(secret: &str, date_stamp: &str, region: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{}", secret).as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"sts");
    hmac_sha256(&k_service, b"aws4_request")
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// unix seconds → (`YYYYMMDDTHHMMSSZ`, `YYYYMMDD`).
fn amz_dates(unix: u64) -> (String, String) {
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
    (
        format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            y, m, d,
            secs / 3600,
            (secs % 3600) / 60,
            secs % 60
        ),
        format!("{:04}{:02}{:02}", y, m, d),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical AWS documentation example credentials, at the classic
    /// SigV4 test-suite timestamp 2015-08-30T12:36:00Z.
    fn example_creds() -> AwsCredentials {
        AwsCredentials {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
        }
    }

    const T_20150830: u64 = 1440938160; // 2015-08-30T12:36:00Z

    #[test]
    fn test_presign_known_answer() {
        // Reference: SigV4 presign computed per AWS docs (verified against an
        // independent Python implementation).
        let url = presign_get_caller_identity(
            &example_creds(),
            "us-east-1",
            60,
            UNIX_EPOCH + std::time::Duration::from_secs(T_20150830),
        );
        assert_eq!(
            url,
            "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fsts%2Faws4_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host&X-Amz-Signature=84cf97280bfefc799e1db4ab2b5d171f238ed426872ae15c96ac463a8cc0e0b1"
        );
    }

    #[test]
    fn test_presign_known_answer_with_session_token() {
        let mut creds = example_creds();
        creds.session_token = Some("AQoDYXdzEPT//////////wEXAMPLE".to_string());
        let url = presign_get_caller_identity(
            &creds,
            "us-east-1",
            60,
            UNIX_EPOCH + std::time::Duration::from_secs(T_20150830),
        );
        assert!(url.contains("X-Amz-Security-Token=AQoDYXdzEPT"));
        assert!(url.ends_with(
            "X-Amz-Signature=42f71616c2a14c32c31cb62706035cf87891355f45930a4c6edd8b60bb0769b5"
        ));
    }

    #[test]
    fn test_presign_global_endpoint_signs_us_east_1() {
        let url = presign_get_caller_identity(
            &example_creds(),
            "",
            60,
            UNIX_EPOCH + std::time::Duration::from_secs(T_20150830),
        );
        assert!(url.starts_with("https://sts.amazonaws.com/?"));
        assert!(url.contains("%2Fus-east-1%2Fsts%2Faws4_request"));
    }

    #[test]
    fn test_presign_cn_region_uses_cn_host() {
        assert_eq!(sts_host("cn-north-1"), "sts.cn-north-1.amazonaws.com.cn");
        let url = presign_get_caller_identity(
            &example_creds(),
            "cn-north-1",
            60,
            UNIX_EPOCH + std::time::Duration::from_secs(T_20150830),
        );
        assert!(url.starts_with("https://sts.cn-north-1.amazonaws.com.cn/?"));
        assert!(url.contains("%2Fcn-north-1%2Fsts%2Faws4_request"));
    }

    #[test]
    fn test_uri_encode() {
        assert_eq!(uri_encode("abc-._~XYZ09"), "abc-._~XYZ09");
        assert_eq!(uri_encode("a/b+c d"), "a%2Fb%2Bc%20d");
    }

    #[test]
    fn test_amz_dates() {
        let (amz, day) = amz_dates(T_20150830);
        assert_eq!(amz, "20150830T123600Z");
        assert_eq!(day, "20150830");
        let (amz, _) = amz_dates(1771286400);
        assert_eq!(amz, "20260217T000000Z");
    }

    #[test]
    fn test_presign_changes_with_secret() {
        let mut creds = example_creds();
        creds.secret_access_key = "different-secret".to_string();
        let url = presign_get_caller_identity(
            &creds,
            "us-east-1",
            60,
            UNIX_EPOCH + std::time::Duration::from_secs(T_20150830),
        );
        assert!(!url.contains("84cf9728"), "signature must depend on the secret");
    }
}
