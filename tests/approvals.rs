//! Integration tests for the durable human-approval store (#51).
//!
//! The store backs the `tools_approval` policy tier: a `tools/call` on an
//! approval-tier tool records a pending approval in the fail-closed audit
//! JSONL, an operator decides via the /approvals management API, and a
//! re-invocation with an identical (agent, tool, args hash) consumes the
//! approval exactly once.

use octobroker::approvals::{
    args_hash, ApprovalStatus, ApprovalStore, ConsumeError, DecideError, GateDecision,
};

fn tmp_path(name: &str) -> String {
    std::env::temp_dir()
        .join(format!(
            "octobroker-approvals-it-{}-{}.jsonl",
            name,
            std::process::id()
        ))
        .to_str()
        .unwrap()
        .to_string()
}

fn open(name: &str, ttl: u64) -> (String, ApprovalStore) {
    let path = tmp_path(name);
    let store = ApprovalStore::open(&path, ttl).unwrap();
    (path, store)
}

fn hash(tool: &str, args: serde_json::Value) -> String {
    args_hash(tool, Some(&args))
}

fn pending_id(d: GateDecision) -> String {
    match d {
        GateDecision::Pending { id, .. } => id,
        GateDecision::Approved { id } => panic!("expected pending, got approved {}", id),
    }
}

#[test]
fn pending_record_is_durable_and_deduped() {
    let (path, store) = open("pending", 900);
    let h = hash(
        "merge_pull_request",
        serde_json::json!({"owner": "o", "repo": "r", "pull_number": 7}),
    );
    let keys = vec![
        "owner".to_string(),
        "repo".to_string(),
        "pull_number".to_string(),
    ];

    let first = store
        .gate("bot-a", "merge_pull_request", &h, &keys, Some("o/r"))
        .unwrap();
    let id = pending_id(first);
    assert!(id.starts_with("apv_"));

    // Identical re-request while pending returns the SAME approval id
    // (deduped — no duplicate records for the operator).
    let second = store
        .gate("bot-a", "merge_pull_request", &h, &keys, Some("o/r"))
        .unwrap();
    assert_eq!(pending_id(second), id);

    // The JSONL audit file holds a durable pending record — without any
    // argument values.
    let lines: Vec<serde_json::Value> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["phase"], "approval_request");
    assert_eq!(lines[0]["id"], id);
    assert_eq!(lines[0]["agent"], "bot-a");
    assert_eq!(lines[0]["tool"], "merge_pull_request");
    assert_eq!(lines[0]["repo"], "o/r");
    assert_eq!(lines[0]["status"], "pending");
    assert!(lines[0]["expires_at"].as_u64().unwrap() > 0);
    assert!(!lines[0].to_string().contains("\"pull_number\":7"));

    // Listed as pending.
    let pending = store.list(Some("pending"));
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].status, ApprovalStatus::Pending);
    assert!(store.get(&id).is_some());
    std::fs::remove_file(&path).ok();
}

#[test]
fn args_hash_pins_tool_and_exact_arguments() {
    // Canonical JSON: key order does not matter, values do.
    let a = args_hash(
        "merge_pull_request",
        Some(&serde_json::json!({"a": 1, "b": 2})),
    );
    let b = args_hash(
        "merge_pull_request",
        Some(&serde_json::json!({"b": 2, "a": 1})),
    );
    assert_eq!(a, b, "canonical serialization sorts keys");
    let c = args_hash(
        "merge_pull_request",
        Some(&serde_json::json!({"a": 1, "b": 3})),
    );
    assert_ne!(a, c);
    let d = args_hash("push_files", Some(&serde_json::json!({"a": 1, "b": 2})));
    assert_ne!(a, d, "hash is pinned to the tool");
    let none = args_hash("t", None);
    let null = args_hash("t", Some(&serde_json::Value::Null));
    assert_eq!(none, null);
}

#[test]
fn approve_then_consume_is_single_use() {
    let (path, store) = open("consume", 900);
    let h = hash("merge_pull_request", serde_json::json!({"owner": "o"}));
    let id = pending_id(
        store
            .gate("bot-a", "merge_pull_request", &h, &[], Some("o/r"))
            .unwrap(),
    );

    // Before the operator approves, a retry stays pending.
    let again = store
        .gate("bot-a", "merge_pull_request", &h, &[], Some("o/r"))
        .unwrap();
    assert_eq!(pending_id(again), id);

    let approved = store.decide(&id, true).unwrap();
    assert_eq!(approved.status, ApprovalStatus::Approved);

    // The gate now says execute, still bound to the same approval id.
    match store
        .gate("bot-a", "merge_pull_request", &h, &[], Some("o/r"))
        .unwrap()
    {
        GateDecision::Approved { id: got } => assert_eq!(got, id),
        GateDecision::Pending { id, .. } => panic!("expected approved, got pending {}", id),
    }

    // Consumed by an identical invocation — exactly once.
    let consumed = store
        .consume(&id, "bot-a", "merge_pull_request", &h)
        .unwrap();
    assert_eq!(consumed.status, ApprovalStatus::Consumed);
    assert!(matches!(
        store.consume(&id, "bot-a", "merge_pull_request", &h),
        Err(ConsumeError::NotApproved)
    ));

    // A subsequent identical call must request approval again (new id).
    let next = pending_id(
        store
            .gate("bot-a", "merge_pull_request", &h, &[], Some("o/r"))
            .unwrap(),
    );
    assert_ne!(next, id);
    std::fs::remove_file(&path).ok();
}

#[test]
fn consume_rejects_mismatched_identity() {
    let (_path, store) = open("mismatch", 900);
    let h = hash("merge_pull_request", serde_json::json!({"owner": "o"}));
    let id = pending_id(
        store
            .gate("bot-a", "merge_pull_request", &h, &[], None)
            .unwrap(),
    );
    store.decide(&id, true).unwrap();

    assert!(matches!(
        store.consume(&id, "other-agent", "merge_pull_request", &h),
        Err(ConsumeError::NotApproved) | Err(ConsumeError::NotFound)
    ));
    assert!(matches!(
        store.consume(&id, "bot-a", "push_files", &h),
        Err(ConsumeError::NotApproved) | Err(ConsumeError::NotFound)
    ));
    let other_args = hash(
        "merge_pull_request",
        serde_json::json!({"owner": "different"}),
    );
    assert!(matches!(
        store.consume(&id, "bot-a", "merge_pull_request", &other_args),
        Err(ConsumeError::NotApproved) | Err(ConsumeError::NotFound)
    ));
    // Still approved — mismatched consumes did not burn it.
    assert!(store
        .consume(&id, "bot-a", "merge_pull_request", &h)
        .is_ok());
    std::fs::remove_file(&_path).ok();
}

#[test]
fn deny_is_terminal_and_unknown_id_404s() {
    let (path, store) = open("deny", 900);
    let h = hash("merge_pull_request", serde_json::json!({"owner": "o"}));
    let id = pending_id(
        store
            .gate("bot-a", "merge_pull_request", &h, &[], None)
            .unwrap(),
    );

    let denied = store.decide(&id, false).unwrap();
    assert_eq!(denied.status, ApprovalStatus::Denied);
    // Deny is terminal: a second decision conflicts, and the gate issues a
    // FRESH pending id for a retried call rather than resurrecting it.
    assert!(matches!(
        store.decide(&id, true),
        Err(DecideError::NotPending)
    ));
    let fresh = pending_id(
        store
            .gate("bot-a", "merge_pull_request", &h, &[], None)
            .unwrap(),
    );
    assert_ne!(fresh, id);

    assert!(matches!(
        store.decide("apv_nope", true),
        Err(DecideError::NotFound)
    ));
    assert!(matches!(
        store.consume("apv_nope", "bot-a", "merge_pull_request", &h),
        Err(ConsumeError::NotFound)
    ));
    std::fs::remove_file(&path).ok();
}

#[test]
fn ttl_bounds_pending_and_approved_records() {
    let (path, store) = open("ttl", 0); // ttl_secs = 0 → instant expiry
    let h = hash("merge_pull_request", serde_json::json!({"owner": "o"}));
    let id = pending_id(
        store
            .gate("bot-a", "merge_pull_request", &h, &[], None)
            .unwrap(),
    );
    assert!(matches!(
        store.decide(&id, true),
        Err(DecideError::NotPending)
    ));

    // Approved records are bounded by the same TTL: a 1s approval decided
    // immediately is unusable after it lapses.
    let (path2, store2) = open("ttl2", 1);
    let id2 = pending_id(
        store2
            .gate("bot-a", "merge_pull_request", &h, &[], None)
            .unwrap(),
    );
    store2.decide(&id2, true).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert!(matches!(
        store2.consume(&id2, "bot-a", "merge_pull_request", &h),
        Err(ConsumeError::NotApproved)
    ));
    std::fs::remove_file(&path).ok();
    std::fs::remove_file(&path2).ok();
}

#[test]
fn state_replays_from_the_audit_jsonl() {
    let (path, store) = open("replay", 900);
    let h = hash("merge_pull_request", serde_json::json!({"owner": "o"}));
    let id = pending_id(
        store
            .gate("bot-a", "merge_pull_request", &h, &[], Some("o/r"))
            .unwrap(),
    );
    store.decide(&id, true).unwrap();
    drop(store);

    // A restart rebuilds the approval state from the durable records: the
    // still-valid approval is consumable without a new request.
    let store = ApprovalStore::open(&path, 900).unwrap();
    match store
        .gate("bot-a", "merge_pull_request", &h, &[], Some("o/r"))
        .unwrap()
    {
        GateDecision::Approved { id: got } => assert_eq!(got, id),
        GateDecision::Pending { id, .. } => panic!("approval lost on replay: {}", id),
    }
    assert!(store
        .consume(&id, "bot-a", "merge_pull_request", &h)
        .is_ok());
    std::fs::remove_file(&path).ok();
}

#[test]
fn open_fails_loudly_on_bad_path() {
    let err = ApprovalStore::open("/nonexistent-dir/sub/approvals.jsonl", 900)
        .err()
        .unwrap();
    assert!(!err.is_empty());
}
