//! Durable human-approval store for the `tools_approval` policy tier (#51).
//!
//! A `tools/call` on an approval-tier tool does not execute immediately:
//! the proxy records a durable `approval_request` in the SAME fail-closed
//! audit JSONL used for write calls and returns a structured tool error
//! carrying the approval id. An operator decides via the `/approvals`
//! management API (operator auth is separate from agent keys); a
//! re-invocation with an identical (agent, tool, arguments hash) then
//! consumes the approval exactly once at the point of no return.
//!
//! Properties:
//! - Durable: every lifecycle transition (`approval_request`,
//!   `approval_decision`, `approval_consume`) is appended + fsync'd BEFORE
//!   the in-memory state changes, and startup rebuilds state by replaying
//!   the JSONL — a restart never silently drops a pending or approved call.
//! - Fail-closed: if a record cannot be persisted the operation reports an
//!   error and the caller must not proceed (same contract as the write
//!   audit preflight).
//! - Single-use, TTL-bounded, pinned to (agent, tool, args hash): the hash
//!   is SHA-256 over the tool name plus the canonical JSON serialization
//!   of the arguments (serde_json maps are BTreeMaps, so key order never
//!   matters but every value does).
//! - Privacy: argument VALUES never leave the process — records carry the
//!   hash plus argument key names only.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

/// SHA-256 binding of a call to its exact tool + arguments.
/// Canonical JSON (sorted keys via serde_json's BTreeMap) means logically
/// identical arguments hash identically regardless of key order.
pub fn args_hash(tool: &str, arguments: Option<&serde_json::Value>) -> String {
    let canonical = serde_json::to_string(&arguments.cloned().unwrap_or(serde_json::Value::Null))
        .unwrap_or_default();
    let mut h = Sha256::new();
    h.update(tool.as_bytes());
    h.update(b"\n");
    h.update(canonical.as_bytes());
    let digest = h.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Consumed,
}

impl ApprovalStatus {
    fn as_str(&self) -> &'static str {
        match self {
            ApprovalStatus::Pending => "pending",
            ApprovalStatus::Approved => "approved",
            ApprovalStatus::Denied => "denied",
            ApprovalStatus::Consumed => "consumed",
        }
    }
}

/// One approval lifecycle, rebuilt from the durable JSONL records.
#[derive(Debug, Clone)]
pub struct Approval {
    pub id: String,
    pub agent: String,
    pub tool: String,
    pub args_hash: String,
    pub repo: Option<String>,
    /// Argument key NAMES only — values are never stored.
    pub arg_keys: Vec<String>,
    pub status: ApprovalStatus,
    /// Creation time, unix milliseconds (matches audit `ts`).
    pub created_ts: u64,
    /// Absolute expiry, unix seconds (matches GitHub token expiries).
    pub expires_at: u64,
    pub decided_ts: Option<u64>,
    pub consumed_ts: Option<u64>,
}

impl Approval {
    /// Status with lazy expiry applied: a pending or approved record past
    /// `expires_at` reports "expired" without needing a sweeper task.
    pub fn effective_status(&self, now: u64) -> &'static str {
        match self.status {
            ApprovalStatus::Pending | ApprovalStatus::Approved if self.expires_at <= now => {
                "expired"
            }
            other => other.as_str(),
        }
    }

    fn is_live(&self, now: u64) -> bool {
        matches!(
            self.status,
            ApprovalStatus::Pending | ApprovalStatus::Approved
        ) && self.expires_at > now
    }
}

/// Result of the proxy-side gate for an approval-tier call.
#[derive(Debug)]
pub enum GateDecision {
    /// The call must not execute yet; the agent gets this id (either an
    /// existing live request — deduped — or a freshly recorded one).
    Pending { id: String, expires_at: u64 },
    /// An operator approved this exact (agent, tool, args hash); the call
    /// may proceed and must `consume` this id at the point of no return.
    Approved { id: String },
}

#[derive(Debug)]
pub enum DecideError {
    NotFound,
    /// Already decided, consumed, or expired — decisions are single-shot.
    NotPending,
    Persist(String),
}

#[derive(Debug)]
pub enum ConsumeError {
    NotFound,
    /// Not approved, already consumed, expired, or bound to a different
    /// (agent, tool, args hash).
    NotApproved,
    Persist(String),
}

impl std::fmt::Display for DecideError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecideError::NotFound => write!(f, "unknown approval"),
            DecideError::NotPending => write!(f, "approval already decided or expired"),
            DecideError::Persist(e) => write!(f, "{}", e),
        }
    }
}

impl std::fmt::Display for ConsumeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsumeError::NotFound => write!(f, "unknown approval"),
            ConsumeError::NotApproved => write!(f, "approval is not usable for this call"),
            ConsumeError::Persist(e) => write!(f, "{}", e),
        }
    }
}

struct Inner {
    file: File,
    records: HashMap<String, Approval>,
    /// Process-local nonce so approval ids are unique without an RNG dep.
    counter: u64,
}

/// Append-only durable approval log; lives on the SAME file as the write
/// audit JSONL so operators have one forensic trail. Independent append
/// handle (O_APPEND writes are atomic at this size) — no coordination with
/// the AuditSink needed.
pub struct ApprovalStore {
    inner: Mutex<Inner>,
    path: String,
    ttl_secs: u64,
}

impl ApprovalStore {
    /// Opens (creates) the JSONL file, first replaying any existing
    /// `approval_*` records so in-flight approvals survive restarts.
    /// `ttl_secs` bounds pending AND approved records identically.
    pub fn open(path: &str, ttl_secs: u64) -> Result<Self, String> {
        let mut records: HashMap<String, Approval> = HashMap::new();
        if let Ok(existing) = File::open(path) {
            for line in BufReader::new(existing).lines() {
                let Ok(line) = line else { break };
                let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
                    continue; // foreign records (write audits) are not ours
                };
                match v.get("phase").and_then(|p| p.as_str()) {
                    Some("approval_request") => {
                        let Some(id) = v.get("id").and_then(|i| i.as_str()) else {
                            continue;
                        };
                        records.insert(
                            id.to_string(),
                            Approval {
                                id: id.to_string(),
                                agent: v["agent"].as_str().unwrap_or_default().to_string(),
                                tool: v["tool"].as_str().unwrap_or_default().to_string(),
                                args_hash: v["args_hash"].as_str().unwrap_or_default().to_string(),
                                repo: v.get("repo").and_then(|r| r.as_str()).map(str::to_string),
                                arg_keys: v["arg_keys"]
                                    .as_array()
                                    .map(|a| {
                                        a.iter()
                                            .filter_map(|k| k.as_str().map(str::to_string))
                                            .collect()
                                    })
                                    .unwrap_or_default(),
                                status: ApprovalStatus::Pending,
                                created_ts: v["ts"].as_u64().unwrap_or_default(),
                                expires_at: v["expires_at"].as_u64().unwrap_or_default(),
                                decided_ts: None,
                                consumed_ts: None,
                            },
                        );
                    }
                    Some("approval_decision") => {
                        let Some(id) = v.get("id").and_then(|i| i.as_str()) else {
                            continue;
                        };
                        if let Some(a) = records.get_mut(id) {
                            if a.status == ApprovalStatus::Pending {
                                a.status = match v["decision"].as_str() {
                                    Some("approved") => ApprovalStatus::Approved,
                                    _ => ApprovalStatus::Denied,
                                };
                                a.decided_ts = v["ts"].as_u64();
                            }
                        }
                    }
                    Some("approval_consume") => {
                        let Some(id) = v.get("id").and_then(|i| i.as_str()) else {
                            continue;
                        };
                        if let Some(a) = records.get_mut(id) {
                            if a.status == ApprovalStatus::Approved {
                                a.status = ApprovalStatus::Consumed;
                                a.consumed_ts = v["ts"].as_u64();
                            }
                        }
                    }
                    _ => continue,
                }
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("cannot open audit log {}: {}", path, e))?;
        Ok(Self {
            inner: Mutex::new(Inner {
                file,
                records,
                counter: 0,
            }),
            path: path.to_string(),
            ttl_secs,
        })
    }

    /// Proxy-side gate. Returns the live request for this exact call
    /// (deduped), an approved record, or records a new durable pending
    /// request. A persistence failure is an Err — the call must be
    /// rejected (fail-closed, no unaudited approval requests).
    pub fn gate(
        &self,
        agent: &str,
        tool: &str,
        args_hash: &str,
        arg_keys: &[String],
        repo: Option<&str>,
    ) -> Result<GateDecision, String> {
        let now = unix_now_secs();
        let mut inner = self.inner.lock().unwrap();
        if let Some(a) = inner.records.values().find(|a| {
            a.agent == agent && a.tool == tool && a.args_hash == args_hash && a.is_live(now)
        }) {
            return Ok(match a.status {
                ApprovalStatus::Approved => GateDecision::Approved { id: a.id.clone() },
                _ => GateDecision::Pending {
                    id: a.id.clone(),
                    expires_at: a.expires_at,
                },
            });
        }

        let expires_at = now + self.ttl_secs;
        let approval = Approval {
            id: self.next_id(&mut inner),
            agent: agent.to_string(),
            tool: tool.to_string(),
            args_hash: args_hash.to_string(),
            repo: repo.map(str::to_string),
            arg_keys: arg_keys.to_vec(),
            status: ApprovalStatus::Pending,
            created_ts: unix_now_ms(),
            expires_at,
            decided_ts: None,
            consumed_ts: None,
        };
        self.append(
            &mut inner,
            serde_json::json!({
                "ts": approval.created_ts,
                "phase": "approval_request",
                "id": approval.id,
                "agent": approval.agent,
                "tool": approval.tool,
                "repo": approval.repo,
                "arg_keys": approval.arg_keys,
                "args_hash": approval.args_hash,
                "status": "pending",
                "expires_at": approval.expires_at,
            }),
        )?;
        let id = approval.id.clone();
        inner.records.insert(id.clone(), approval);
        Ok(GateDecision::Pending { id, expires_at })
    }

    /// Operator decision via the management API. Single-shot: only a live
    /// pending record may transition.
    pub fn decide(&self, id: &str, approved: bool) -> Result<Approval, DecideError> {
        let now = unix_now_secs();
        let mut inner = self.inner.lock().unwrap();
        {
            let a = inner.records.get(id).ok_or(DecideError::NotFound)?;
            if a.status != ApprovalStatus::Pending || !a.is_live(now) {
                return Err(DecideError::NotPending);
            }
        }
        let ts = unix_now_ms();
        self.append(
            &mut inner,
            serde_json::json!({
                "ts": ts,
                "phase": "approval_decision",
                "id": id,
                "decision": if approved { "approved" } else { "denied" },
            }),
        )
        .map_err(DecideError::Persist)?;
        let a = inner.records.get_mut(id).unwrap();
        a.status = if approved {
            ApprovalStatus::Approved
        } else {
            ApprovalStatus::Denied
        };
        a.decided_ts = Some(ts);
        Ok(a.clone())
    }

    /// Single-use consume at the point of no return. The id, agent, tool,
    /// and args hash must match an approved, unexpired record; the durable
    /// consume record lands before the in-memory transition.
    pub fn consume(
        &self,
        id: &str,
        agent: &str,
        tool: &str,
        args_hash: &str,
    ) -> Result<Approval, ConsumeError> {
        let now = unix_now_secs();
        let mut inner = self.inner.lock().unwrap();
        {
            let a = inner.records.get(id).ok_or(ConsumeError::NotFound)?;
            if a.agent != agent || a.tool != tool || a.args_hash != args_hash {
                return Err(ConsumeError::NotApproved);
            }
            if a.status != ApprovalStatus::Approved || !a.is_live(now) {
                return Err(ConsumeError::NotApproved);
            }
        }
        let ts = unix_now_ms();
        self.append(
            &mut inner,
            serde_json::json!({
                "ts": ts,
                "phase": "approval_consume",
                "id": id,
                "agent": agent,
                "tool": tool,
                "args_hash": args_hash,
            }),
        )
        .map_err(ConsumeError::Persist)?;
        let a = inner.records.get_mut(id).unwrap();
        a.status = ApprovalStatus::Consumed;
        a.consumed_ts = Some(ts);
        Ok(a.clone())
    }

    /// All known approvals, or only those whose EFFECTIVE status (lazy
    /// expiry applied) equals `status`.
    pub fn list(&self, status: Option<&str>) -> Vec<Approval> {
        let now = unix_now_secs();
        let inner = self.inner.lock().unwrap();
        let mut out: Vec<Approval> = inner
            .records
            .values()
            .filter(|a| status.map(|s| a.effective_status(now) == s).unwrap_or(true))
            .cloned()
            .collect();
        out.sort_by_key(|a| a.created_ts);
        out
    }

    pub fn get(&self, id: &str) -> Option<Approval> {
        self.inner.lock().unwrap().records.get(id).cloned()
    }

    fn next_id(&self, inner: &mut Inner) -> String {
        loop {
            inner.counter += 1;
            let seed = format!("{}:{}:{}", std::process::id(), inner.counter, unix_now_ms());
            let digest = Sha256::digest(seed.as_bytes());
            let id = format!(
                "apv_{:016x}",
                u64::from_be_bytes(digest[..8].try_into().unwrap())
            );
            if !inner.records.contains_key(&id) {
                return id;
            }
        }
    }

    /// Append one JSONL record and fsync. Same small blocking write as the
    /// audit sink — approval events are rare and records are <1 KB.
    fn append(&self, inner: &mut Inner, record: serde_json::Value) -> Result<(), String> {
        let mut line = record.to_string();
        line.push('\n');
        inner
            .file
            .write_all(line.as_bytes())
            .and_then(|_| inner.file.sync_data())
            .map_err(|e| format!("audit append failed ({}): {}", self.path, e))
    }
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
