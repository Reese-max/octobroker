//! Ref-level push policy decision table (#49).
//!
//! The module under test is included from `src/` (the crate is binary-only, so
//! integration tests cannot import it by crate name). This exercises the real
//! product code, not a copy: any change to `src/ref_policy.rs` is what runs
//! here.

#[path = "../src/ref_policy.rs"]
mod ref_policy;

use ref_policy::{branch_protected, default_branch, default_branch_protected, Protection};

fn repo(default: &str) -> serde_json::Value {
    serde_json::json!({"default_branch": default})
}

/// Same, with a `default_branch` that is not a string at all.
fn repo_raw(default: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"default_branch": default})
}

fn branch(protected: bool) -> serde_json::Value {
    serde_json::json!({"name": "main", "protected": protected})
}

#[test]
fn test_default_branch_is_read_from_repo_metadata() {
    assert_eq!(default_branch(&repo("main")), Some("main"));
    assert_eq!(default_branch(&repo("  trunk  ")), Some("trunk"));
    // Unusable shapes have no default branch — never "main" as a guess.
    assert_eq!(default_branch(&serde_json::json!({})), None);
    assert_eq!(default_branch(&repo("")), None);
    assert_eq!(default_branch(&repo("   ")), None);
    assert_eq!(default_branch(&repo_raw(serde_json::json!(7))), None);
    assert_eq!(default_branch(&repo_raw(serde_json::Value::Null)), None);
    assert_eq!(default_branch(&repo_raw(serde_json::json!(["main"]))), None);
}

#[test]
fn test_only_an_explicit_true_counts_as_protected() {
    assert!(branch_protected(&branch(true)));
    assert!(!branch_protected(&branch(false)));
    // Missing / null / non-boolean protection must never read as protection.
    assert!(!branch_protected(&serde_json::json!({})));
    assert!(!branch_protected(&serde_json::json!({"protected": null})));
    assert!(!branch_protected(&serde_json::json!({"protected": "true"})));
}

#[test]
fn test_protected_default_branch_is_allowed() {
    assert_eq!(
        default_branch_protected(Some(&repo("main")), Some(&branch(true))),
        Protection::Protected
    );
}

#[test]
fn test_unprotected_default_branch_is_denied() {
    assert_eq!(
        default_branch_protected(Some(&repo("main")), Some(&branch(false))),
        Protection::Unprotected
    );
}

#[test]
fn test_unreadable_repository_fails_closed() {
    // GitHub read failed (None) or answered without a default branch, or the
    // branch read failed — a broker that proved nothing must not pass.
    assert_eq!(
        default_branch_protected(None, None),
        Protection::Unprotected
    );
    assert_eq!(
        default_branch_protected(None, Some(&branch(true))),
        Protection::Unprotected
    );
    assert_eq!(
        default_branch_protected(Some(&repo("main")), None),
        Protection::Unprotected
    );
    assert_eq!(
        default_branch_protected(Some(&serde_json::json!({})), Some(&branch(true))),
        Protection::Unprotected
    );
}
