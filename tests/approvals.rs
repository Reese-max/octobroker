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
    assert!(lines[0]["expires_at_ms"].as_u64().unwrap() > 0);
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

#[test]
fn gate_dedup_is_scoped_to_agent_and_tool() {
    // One agent's approval must never be handed to a different agent, even
    // for a byte-identical call: the dedup key is (agent, tool, args hash).
    let (path, store) = open("dedup-scope", 900);
    let args = serde_json::json!({"owner": "o", "repo": "r", "pull_number": 7});
    let h = hash("merge_pull_request", args.clone());

    let id_a = pending_id(
        store
            .gate("bot-a", "merge_pull_request", &h, &[], Some("o/r"))
            .unwrap(),
    );
    let id_b = pending_id(
        store
            .gate("bot-b", "merge_pull_request", &h, &[], Some("o/r"))
            .unwrap(),
    );
    assert_ne!(id_a, id_b, "a second agent must get its own request");

    // Same agent, different tool → different request.
    let id_other_tool = pending_id(
        store
            .gate("bot-a", "push_files", &h, &[], Some("o/r"))
            .unwrap(),
    );
    assert_ne!(id_a, id_other_tool, "the tool is part of the dedup key");

    // bot-b cannot consume bot-a's approval, even after it is approved.
    store.decide(&id_a, true).unwrap();
    assert!(matches!(
        store.consume(&id_a, "bot-b", "merge_pull_request", &h),
        Err(ConsumeError::NotApproved) | Err(ConsumeError::NotFound)
    ));
    // bot-a still can.
    assert!(store
        .consume(&id_a, "bot-a", "merge_pull_request", &h)
        .is_ok());
    std::fs::remove_file(&path).ok();
}

#[test]
fn consumed_approval_stays_consumed_across_restart() {
    // Single-use must survive a restart: a consumed record replays as
    // consumed, so the same call needs a fresh approval instead of
    // re-arming on the durable log.
    let (path, store) = open("consume-restart", 900);
    let h = hash("merge_pull_request", serde_json::json!({"owner": "o"}));
    let id = pending_id(
        store
            .gate("bot-a", "merge_pull_request", &h, &[], Some("o/r"))
            .unwrap(),
    );
    store.decide(&id, true).unwrap();
    assert!(store
        .consume(&id, "bot-a", "merge_pull_request", &h)
        .is_ok());
    drop(store);

    let store = ApprovalStore::open(&path, 900).unwrap();
    assert_eq!(
        store.get(&id).map(|a| a.status),
        Some(ApprovalStatus::Consumed),
        "a consumed approval must not replay as approved"
    );
    // The retry must go back through the human gate with a NEW id.
    let fresh = pending_id(
        store
            .gate("bot-a", "merge_pull_request", &h, &[], Some("o/r"))
            .unwrap(),
    );
    assert_ne!(fresh, id);
    assert!(store
        .consume(&id, "bot-a", "merge_pull_request", &h)
        .is_err());
    std::fs::remove_file(&path).ok();
}

#[test]
fn replay_refuses_a_corrupt_log_rather_than_weakening_state() {
    // A torn tail (crash between write_all and the next append) merges two
    // records into one unparseable line. Skipping it silently would drop a
    // `denied` decision and resurrect the call as approvable.
    let (path, store) = open("corrupt", 900);
    let h = hash("merge_pull_request", serde_json::json!({"owner": "o"}));
    let id = pending_id(
        store
            .gate("bot-a", "merge_pull_request", &h, &[], Some("o/r"))
            .unwrap(),
    );
    store.decide(&id, false).unwrap();
    drop(store);

    // Keep the request record, tear the decision record mid-write.
    let mut lines: Vec<String> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let torn = lines.pop().unwrap();
    let truncated: String = torn.chars().take(torn.len() / 2).collect();
    lines.push(truncated);
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();

    let err = ApprovalStore::open(&path, 900).err().expect(
        "a corrupt approval log must fail loudly at startup instead of replaying weaker state",
    );
    assert!(err.contains("cannot replay approval log"), "{}", err);
    std::fs::remove_file(&path).ok();
}

#[test]
fn replay_tolerates_blank_lines() {
    // Blank separators are not corruption and must not brick startup.
    let (path, store) = open("blank", 900);
    let h = hash("merge_pull_request", serde_json::json!({"owner": "o"}));
    let id = pending_id(
        store
            .gate("bot-a", "merge_pull_request", &h, &[], Some("o/r"))
            .unwrap(),
    );
    store.decide(&id, true).unwrap();
    drop(store);

    let raw = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("\n{}\n\n", raw)).unwrap();
    let store = ApprovalStore::open(&path, 900).unwrap();
    match store
        .gate("bot-a", "merge_pull_request", &h, &[], Some("o/r"))
        .unwrap()
    {
        GateDecision::Approved { id: got } => assert_eq!(got, id),
        GateDecision::Pending { id, .. } => panic!("approval lost across blank lines: {}", id),
    }
    std::fs::remove_file(&path).ok();
}

#[test]
fn open_fails_loudly_on_an_unreadable_log() {
    // An audit file the process cannot read means the forensic trail and the
    // live state have diverged — refuse to start rather than silently
    // reconstruct empty approval state.
    //
    // A directory is the root-proof fixture: `open(2)` on a directory
    // succeeds but every read fails with EISDIR, so the replay cannot
    // complete no matter who is running.
    let dir = std::env::temp_dir().join(format!(
        "octobroker-approvals-dir-{}-{}",
        "unreadable",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let err = ApprovalStore::open(dir.to_str().unwrap(), 900)
        .err()
        .expect("an unreadable log must abort the replay");
    assert!(
        err.contains("cannot replay approval log"),
        "the replay must be what fails, not the later append open: {}",
        err
    );
    std::fs::remove_dir(&dir).ok();

    // The unreadable-file variant is EACCES, which root ignores; skip only
    // when the fixture cannot express it.
    use std::os::unix::fs::PermissionsExt;
    let (path, _store) = open("unreadable", 900);
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o000);
    std::fs::set_permissions(&path, perms).unwrap();
    if std::fs::read_to_string(&path).is_err() {
        assert!(ApprovalStore::open(&path, 900)
            .err()
            .unwrap()
            .contains("cannot replay approval log"));
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).ok();
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_missing_log_opens_empty_rather_than_failing() {
    // The NotFound arm is the only "no log yet" case: no approvals have
    // ever been requested, which must not be confused with a broken log.
    let path = tmp_path("absent");
    std::fs::remove_file(&path).ok();
    let store = ApprovalStore::open(&path, 900).expect("a fresh path must open");
    assert!(store.list(None).is_empty());
    let h = hash("merge_pull_request", serde_json::json!({"owner": "o"}));
    let id = pending_id(
        store
            .gate("bot-a", "merge_pull_request", &h, &[], None)
            .unwrap(),
    );
    assert!(id.starts_with("apv_"));
    std::fs::remove_file(&path).ok();
}

#[test]
fn terminal_records_stay_visible_so_the_api_contract_holds() {
    // Eviction is bounded, not unconditional: a denied approval must keep
    // answering NotPending (409) on re-decision and keep showing up under
    // ?status=denied, and a consumed one must stay visible. Only the oldest
    // records go once the bound is passed (see the next test).
    let (path, store) = open("terminal-visible", 900);
    let mut ids = Vec::new();
    for round in 0..25u64 {
        let h = hash(
            "merge_pull_request",
            serde_json::json!({"owner": "o", "n": round}),
        );
        let id = pending_id(
            store
                .gate("bot-a", "merge_pull_request", &h, &[], Some("o/r"))
                .unwrap(),
        );
        store.decide(&id, round % 2 == 0).unwrap();
        ids.push(id);
    }
    assert_eq!(
        store.list(None).len(),
        25,
        "nothing is evicted under the bound"
    );
    let denied: Vec<String> = ids
        .iter()
        .filter(|id| store.get(id).map(|a| a.status) == Some(ApprovalStatus::Denied))
        .cloned()
        .collect();
    assert_eq!(denied.len(), 12);
    // A denial is still answerable — NotPending, never NotFound, so the
    // management API can keep returning 409 instead of 404.
    for id in &denied {
        assert!(
            matches!(store.decide(id, true), Err(DecideError::NotPending)),
            "{} lost its terminal state",
            id
        );
    }
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_working_set_is_bounded_under_a_request_flood() {
    // A flood of distinct requests must not grow the working set without
    // limit. Eviction is oldest-first and fail-closed: the newest record
    // always survives, and a dropped one only costs the agent a re-request.
    let (path, store) = open("bounded", 900);
    let store = store.with_max_records(8);
    for round in 0..40u64 {
        let h = hash(
            "merge_pull_request",
            serde_json::json!({"owner": "o", "n": round}),
        );
        store
            .gate("bot-a", "merge_pull_request", &h, &[], Some("o/r"))
            .unwrap();
    }
    let live = store.list(None);
    assert!(
        live.len() <= 8,
        "working set grew past its bound: {}",
        live.len()
    );
    let newest = hash(
        "merge_pull_request",
        serde_json::json!({"owner": "o", "n": 39}),
    );
    // The most recent request is still servable — eviction drops the oldest.
    match store
        .gate("bot-a", "merge_pull_request", &newest, &[], Some("o/r"))
        .unwrap()
    {
        GateDecision::Pending { id, .. } => assert!(store.get(&id).is_some()),
        GateDecision::Approved { id } => panic!("unexpected approval {}", id),
    }
    // The durable trail is untouched by eviction.
    let lines = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        lines
            .lines()
            .filter(|l| l.contains("approval_request"))
            .count(),
        40
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn dedup_wins_over_eviction_even_at_the_smallest_bound() {
    // Eviction runs AFTER the dedup lookup. If it ran first, a bound of 1
    // would evict the very record the retry is looking for: the approval id
    // would churn on every poll and the operator's approve would 404.
    let (path, store) = open("dedup-vs-evict", 900);
    let store = store.with_max_records(1);
    let h = hash("merge_pull_request", serde_json::json!({"owner": "o"}));
    let id = pending_id(
        store
            .gate("bot-a", "merge_pull_request", &h, &[], Some("o/r"))
            .unwrap(),
    );
    for _ in 0..5 {
        assert_eq!(
            pending_id(
                store
                    .gate("bot-a", "merge_pull_request", &h, &[], Some("o/r"))
                    .unwrap()
            ),
            id,
            "the same request must keep its approval id"
        );
    }
    // It is still decidable.
    assert_eq!(
        store.decide(&id, true).unwrap().status,
        ApprovalStatus::Approved
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn eviction_drops_terminal_records_before_live_ones() {
    // Past the bound, a denial is worth less to an operator than a live
    // pending request — even when the denial is the newer of the two.
    let (path, store) = open("terminal-first", 900);
    let store = store.with_max_records(2);
    let live_h = hash("merge_pull_request", serde_json::json!({"owner": "live"}));
    let live_id = pending_id(
        store
            .gate("bot-a", "merge_pull_request", &live_h, &[], None)
            .unwrap(),
    );
    let denied_h = hash("merge_pull_request", serde_json::json!({"owner": "denied"}));
    let denied_id = pending_id(
        store
            .gate("bot-a", "merge_pull_request", &denied_h, &[], None)
            .unwrap(),
    );
    store.decide(&denied_id, false).unwrap();
    assert_eq!(store.list(None).len(), 2);

    // A third, distinct request forces one eviction.
    let third_h = hash("merge_pull_request", serde_json::json!({"owner": "third"}));
    store
        .gate("bot-a", "merge_pull_request", &third_h, &[], None)
        .unwrap();
    assert_eq!(store.list(None).len(), 2);
    assert!(
        store.get(&denied_id).is_none(),
        "the terminal denial should be the one evicted"
    );
    assert_eq!(
        store.get(&live_id).map(|a| a.status),
        Some(ApprovalStatus::Pending),
        "a live pending request must outlive a denial"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn approval_timestamps_are_unix_milliseconds() {
    // One unit across the record: expires_at_ms - created_ts_ms is the real
    // window. Mixing seconds and milliseconds silently corrupts operator
    // arithmetic on the endpoint that unblocks a high-risk write.
    let (path, store) = open("units", 900);
    let h = hash("merge_pull_request", serde_json::json!({"owner": "o"}));
    let id = pending_id(
        store
            .gate("bot-a", "merge_pull_request", &h, &[], Some("o/r"))
            .unwrap(),
    );
    store.decide(&id, true).unwrap();
    store
        .consume(&id, "bot-a", "merge_pull_request", &h)
        .unwrap();

    let a = store.get(&id).unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    // Sanity: a plausible millisecond clock, not a second clock.
    assert!(a.created_ts_ms > 1_000_000_000_000, "{}", a.created_ts_ms);
    assert!(a.created_ts_ms <= now_ms + 5_000);
    assert_eq!(a.expires_at_ms - a.created_ts_ms, 900 * 1000);
    assert!(a.decided_ts_ms.unwrap() >= a.created_ts_ms);
    assert!(a.consumed_ts_ms.unwrap() >= a.decided_ts_ms.unwrap());

    let lines: Vec<serde_json::Value> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(
        lines[0].get("expires_at_ms").is_some(),
        "the durable record names its unit"
    );
    assert!(lines[0].get("expires_at").is_none());
    std::fs::remove_file(&path).ok();
}
