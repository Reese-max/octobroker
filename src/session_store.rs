//! MCP session pin storage, with an optional cross-replica journal
//! (Phase 3 horizontal scaling, #18).
//!
//! Session pinning is the one piece of per-session state that cannot simply be
//! recomputed: an MCP session must keep using the exact credential that
//! created it, bound to the agent that initialized it. In a single replica that
//! is an in-process map. With more than one replica behind a load balancer the
//! map has to be either shared or the balancer has to provide session affinity
//! — otherwise a request routed to the wrong replica is answered "unknown
//! session" and the agent's session dies mid-conversation.
//!
//! Two backends:
//!
//! - [`PinStore::memory`] — single replica (default). Unchanged Phase 1/2
//!   behaviour, nothing on disk.
//! - [`PinStore::shared`] — an append-only JSONL journal on a volume shared by
//!   every replica, fronted by a per-process map. A pin written by one replica
//!   is visible to all of them.
//!
//! ## Failure mode, and the deliberate trade-off in the journal
//!
//! **The journal never stores token material.** A pin is recorded as a
//! non-secret [`PinRecord`] projection:
//!
//! - `Pat` pins carry only the pool identity id, so they rehydrate exactly on
//!   any replica.
//! - `App` / `MultiApp` pins carry only the installation's expiry. GitHub App
//!   installation tokens are short-lived bearer secrets and are minted fresh
//!   per upstream session; replaying an old token on a different replica would
//!   be a credential-at-rest problem for no benefit, since the upstream session
//!   itself is created with that token. Instead a replica that cannot resolve
//!   the pin locally **terminates** it (the caller sees the existing
//!   "session not found" 404 and re-initializes). That keeps App-backed
//!   sessions on a single replica, which is exactly what load-balancer session
//!   affinity provides — hence `shared` mode documents affinity as *required*
//!   for App-backed credentials and *optional* for the PAT path.
//!
//! Insert is **fail-closed**: the journal record is appended and fsynced
//! before the local map is updated, so a replica never serves a session it
//! could not make durable for its peers. A replica that comes up empty
//! (restart, lost volume) therefore terminates sessions rather than silently
//! re-pinning them to a different credential — re-pinning would attribute an
//! agent's writes to a credential it never initialized with.
//!
//! Free of `crate::` references so `tests/phase3_operational.rs` can include
//! it directly.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

/// Default pin TTL, matching `[mcp] session_ttl_secs`.
pub const DEFAULT_PIN_TTL_SECS: u64 = 3_600;

// ---------------------------------------------------------------------------
// Pin types
// ---------------------------------------------------------------------------

/// What a pinned MCP session is bound to: the exact credential serving it,
/// and (in agent mode) the agent that initialized it. A session presented by a
/// different agent is rejected; a session whose credential has expired is
/// terminated — sessions cannot outlive their credential.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionPin {
    /// None = session created in Phase 1 network-trust mode (no agents).
    pub agent_id: Option<String>,
    pub cred: PinnedCred,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum PinnedCred {
    /// Pooled PAT, referenced by identity id (revoked by pool removal).
    Pat { identity_id: String },
    /// GitHub App installation token, pinned by value: the session keeps
    /// using the token it started with (still valid upstream even after the
    /// provider refreshes) and dies at that token's expiry.
    App { token: String, expires_at: u64 },
    /// Multi-installation mode: one pinned credential and one upstream session
    /// per owner, all created eagerly at `initialize`.
    MultiApp {
        /// owner (lowercase) → pinned per-installation route.
        routes: HashMap<String, AppRoute>,
        /// Owner whose upstream session ID doubles as the downstream session ID.
        primary: String,
    },
}

/// One installation's pinned credential + upstream session in multi mode.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppRoute {
    pub token: String,
    pub expires_at: u64,
    /// Upstream session ID for this installation (None when the upstream did
    /// not assign one — such routes are used statelessly).
    pub upstream_session: Option<String>,
}

/// Non-secret projection of a [`SessionPin`], as written to the shared journal.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PinRecord {
    pub agent_id: Option<String>,
    pub cred: PinCredRecord,
    /// Absolute expiry of the pin itself (credential expiry or session TTL).
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum PinCredRecord {
    /// Fully resolvable on any replica: the pool is configured identically
    /// everywhere, and the identity id is not a secret.
    Pat { identity_id: String },
    /// Token material deliberately withheld.
    App { expires_at: u64 },
    /// Token material deliberately withheld; owners recorded so the journal
    /// still shows which installations the session covered.
    MultiApp { owners: Vec<String>, primary: String },
}

/// Why a journal record could not be turned back into a usable pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnresolvablePin {
    pub reason: &'static str,
}

impl SessionPin {
    /// Project to the non-secret journal record. `credential_expires_at` bounds
    /// the pin by the credential's own lifetime; the store then applies the
    /// session TTL on top.
    pub fn to_record(&self, credential_expires_at: Option<u64>, now_epoch_secs: u64) -> PinRecord {
        let cred = match &self.cred {
            PinnedCred::Pat { identity_id } => PinCredRecord::Pat {
                identity_id: identity_id.clone(),
            },
            PinnedCred::App { expires_at, .. } => PinCredRecord::App {
                expires_at: *expires_at,
            },
            PinnedCred::MultiApp { routes, primary } => {
                let mut owners: Vec<String> = routes.keys().cloned().collect();
                owners.sort();
                PinCredRecord::MultiApp {
                    owners,
                    primary: primary.clone(),
                }
            }
        };
        PinRecord {
            agent_id: self.agent_id.clone(),
            cred,
            expires_at: credential_expires_at
                .unwrap_or(u64::MAX)
                .min(now_epoch_secs.saturating_add(DEFAULT_PIN_TTL_SECS)),
        }
    }

    /// Rebuild a pin from a journal record. Only `Pat` records rehydrate: an
    /// `App`/`MultiApp` record carries no token, so it must terminate the
    /// session rather than rebind it to a different credential.
    pub fn from_record(record: &PinRecord) -> Result<SessionPin, UnresolvablePin> {
        let cred = match &record.cred {
            PinCredRecord::Pat { identity_id } => PinnedCred::Pat {
                identity_id: identity_id.clone(),
            },
            PinCredRecord::App { .. } => {
                return Err(UnresolvablePin {
                    reason: "installation token is not journalled",
                })
            }
            PinCredRecord::MultiApp { .. } => {
                return Err(UnresolvablePin {
                    reason: "multi-installation tokens are not journalled",
                })
            }
        };
        Ok(SessionPin {
            agent_id: record.agent_id.clone(),
            cred,
        })
    }
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// One journal record. The `op` tag is what distinguishes a pin from a
/// tombstone — without it the two shapes are ambiguous on the wire.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum JournalOp {
    Put {
        session: String,
        record: PinRecord,
    },
    /// Deletion marker: session bindings never carry a credential, so the
    /// journal stores only that the pin was gone. Tombstones are therefore
    /// never a disclosure risk.
    Drop { session: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JournalLine {
    replica: String,
    ts: u64,
    #[serde(flatten)]
    op: JournalOp,
}

/// One local cache entry.
///
/// `Held` is the only variant that can carry installation-token material, and
/// it never leaves this process. `Journal` entries were learned from the
/// shared journal and therefore hold only the redacted [`PinRecord`].
#[derive(Clone, Debug)]
enum Entry {
    Held { pin: SessionPin, expires_at: u64 },
    Journal { record: PinRecord, expires_at: u64 },
}

impl Entry {
    fn expires_at(&self) -> u64 {
        match self {
            Entry::Held { expires_at, .. } | Entry::Journal { expires_at, .. } => *expires_at,
        }
    }

    /// The pin this entry can serve, if any. A journal entry whose credential
    /// was not journalled resolves to nothing and terminates the session.
    fn resolve(&self) -> Option<SessionPin> {
        match self {
            Entry::Held { pin, .. } => Some(pin.clone()),
            Entry::Journal { record, .. } => SessionPin::from_record(record).ok(),
        }
    }
}

/// Expiry of a pin: bounded by its credential AND by the idle session TTL,
/// measured from the moment it was written.
fn pin_expiry(pin: &SessionPin, ttl_secs: u64, now_epoch_secs: u64) -> u64 {
    credential_expiry(pin)
        .unwrap_or(u64::MAX)
        .min(now_epoch_secs.saturating_add(ttl_secs))
}

/// Expiry of a journal entry, anchored on the writer's timestamp so every
/// replica agrees on when the pin dies.
fn journal_entry(record: &PinRecord, ttl_secs: u64, written_at: u64) -> Entry {
    Entry::Journal {
        expires_at: record
            .expires_at
            .min(written_at.saturating_add(ttl_secs)),
        record: record.clone(),
    }
}

#[derive(Debug)]
pub struct PinStoreError {
    pub message: String,
}

impl fmt::Display for PinStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl PinStoreError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Session pin storage for the MCP proxy.
pub enum PinStore {
    Memory(MemoryPins),
    Shared(SharedPins),
}

impl PinStore {
    /// Single-replica store: nothing leaves the process.
    pub fn memory(ttl_secs: u64) -> Self {
        PinStore::Memory(MemoryPins::new(ttl_secs))
    }

    /// Cross-replica store backed by an append-only journal on shared storage.
    /// Fails at construction when the journal cannot be opened, so a
    /// misconfigured deployment does not boot and then silently terminate every
    /// session.
    pub fn shared(journal_path: &str, ttl_secs: u64, replica_id: &str) -> Result<Self, PinStoreError> {
        Ok(PinStore::Shared(SharedPins::open(journal_path, ttl_secs, replica_id)?))
    }

    /// `memory` or `shared`, for logs and `/stats`.
    pub fn mode(&self) -> &'static str {
        match self {
            PinStore::Memory(_) => "memory",
            PinStore::Shared(_) => "shared",
        }
    }

    pub fn get(&self, session_id: &str, now_epoch_secs: u64) -> Option<SessionPin> {
        match self {
            PinStore::Memory(store) => store.get(session_id, now_epoch_secs),
            PinStore::Shared(store) => store.get(session_id, now_epoch_secs),
        }
    }

    pub fn insert(
        &self,
        session_id: &str,
        pin: SessionPin,
        now_epoch_secs: u64,
    ) -> Result<(), PinStoreError> {
        match self {
            PinStore::Memory(store) => store.insert(session_id, pin, now_epoch_secs),
            PinStore::Shared(store) => store.insert(session_id, pin, now_epoch_secs),
        }
    }

    pub fn invalidate(&self, session_id: &str, now_epoch_secs: u64) -> Result<(), PinStoreError> {
        match self {
            PinStore::Memory(store) => store.invalidate(session_id, now_epoch_secs),
            PinStore::Shared(store) => store.invalidate(session_id, now_epoch_secs),
        }
    }

    pub fn len(&self, now_epoch_secs: u64) -> usize {
        match self {
            PinStore::Memory(store) => store.len(now_epoch_secs),
            PinStore::Shared(store) => store.len(now_epoch_secs),
        }
    }

    pub fn is_empty(&self, now_epoch_secs: u64) -> bool {
        self.len(now_epoch_secs) == 0
    }
}

/// Single-replica pin map: the full pin (including any installation token)
/// lives in this process's memory only, exactly as in Phase 1/2.
pub struct MemoryPins {
    ttl_secs: u64,
    entries: Mutex<HashMap<String, Entry>>,
}

impl MemoryPins {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            ttl_secs: ttl_secs.max(1),
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn get(&self, session_id: &str, now_epoch_secs: u64) -> Option<SessionPin> {
        let mut entries = self.lock();
        let entry = entries.get(session_id).cloned()?;
        if entry.expires_at() <= now_epoch_secs {
            entries.remove(session_id);
            return None;
        }
        entry.resolve()
    }

    pub fn insert(
        &self,
        session_id: &str,
        pin: SessionPin,
        now_epoch_secs: u64,
    ) -> Result<(), PinStoreError> {
        self.lock().insert(
            session_id.to_string(),
            Entry::Held {
                expires_at: pin_expiry(&pin, self.ttl_secs, now_epoch_secs),
                pin,
            },
        );
        Ok(())
    }

    pub fn invalidate(&self, session_id: &str, _now_epoch_secs: u64) -> Result<(), PinStoreError> {
        self.lock().remove(session_id);
        Ok(())
    }

    pub fn len(&self, now_epoch_secs: u64) -> usize {
        let mut entries = self.lock();
        entries.retain(|_, entry| entry.expires_at() > now_epoch_secs);
        entries.len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Cross-replica pin map with an append-only journal.
pub struct SharedPins {
    ttl_secs: u64,
    replica_id: String,
    journal_path: String,
    /// Byte offset up to which this replica has already consumed the journal.
    read_offset: Mutex<u64>,
    entries: Mutex<HashMap<String, Entry>>,
}

impl SharedPins {
    pub fn open(
        journal_path: &str,
        ttl_secs: u64,
        replica_id: &str,
    ) -> Result<Self, PinStoreError> {
        // Open once at startup so an unusable path aborts boot rather than
        // terminating every session later.
        open_journal(journal_path)
            .map_err(|e| PinStoreError::new(format!("cannot open session journal {journal_path}: {e}")))?;
        let store = Self {
            ttl_secs: ttl_secs.max(1),
            replica_id: replica_id.to_string(),
            journal_path: journal_path.to_string(),
            read_offset: Mutex::new(0),
            entries: Mutex::new(HashMap::new()),
        };
        store.rehydrate();
        Ok(store)
    }

    /// Consume journal records this replica has not seen yet. Runs at startup
    /// (so a restarted replica still honours sessions established earlier) and
    /// on a local miss (so a pin written by a peer becomes visible).
    fn rehydrate(&self) {
        let mut offset = self
            .read_offset
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Cheap common case: nobody appended since we last looked (a stat, not a
        // read). A shrink (journal replaced/truncated) forces a full re-read.
        let len = std::fs::metadata(&self.journal_path).map(|m| m.len()).unwrap_or(0);
        if len == *offset || len < *offset {
            if len < *offset {
                *offset = 0;
                self.entries
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clear();
            } else {
                return;
            }
        }
        let Ok(contents) = std::fs::read(&self.journal_path) else {
            return;
        };
        if contents.len() as u64 <= *offset {
            return;
        }
        let tail = &contents[*offset as usize..];
        // A crash mid-append can leave a partial final line; only consume bytes
        // up to the last newline so a torn record is re-read after the writer
        // completes it.
        let Some(last_newline) = tail.iter().rposition(|b| *b == b'\n') else {
            return;
        };
        let complete = &tail[..=last_newline];
        let consumed = complete.len();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for line in std::str::from_utf8(complete).unwrap_or("").lines() {
            let Ok(parsed) = serde_json::from_str::<JournalLine>(line) else {
                // A corrupt line is skipped, never fatal: one bad record must
                // not take every other session down.
                continue;
            };
            match parsed.op {
                JournalOp::Put { session, record } => {
                    // Never downgrade a pin this replica is holding in full.
                    if !matches!(entries.get(&session), Some(Entry::Held { .. })) {
                        entries.insert(session, journal_entry(&record, self.ttl_secs, parsed.ts));
                    }
                }
                JournalOp::Drop { session } => {
                    entries.remove(&session);
                }
            }
        }
        drop(entries);
        *offset += consumed as u64;
    }

    /// Look up a pin, first pulling in any journal records written since the
    /// last read. The refresh is unconditional: a peer may have *dropped* the
    /// session since we cached it, and serving our stale copy would resurrect a
    /// terminated session.
    pub fn get(&self, session_id: &str, now_epoch_secs: u64) -> Option<SessionPin> {
        self.rehydrate();
        self.lookup(session_id, now_epoch_secs)
    }

    fn lookup(&self, session_id: &str, now_epoch_secs: u64) -> Option<SessionPin> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(entry) = entries.get(session_id).cloned() else {
            return None;
        };
        if entry.expires_at() <= now_epoch_secs {
            entries.remove(session_id);
            return None;
        }
        match entry.resolve() {
            Some(pin) => Some(pin),
            None => {
                // A peer created this session with an App installation token
                // we do not hold. Terminate it rather than guess a credential
                // — the client re-initializes here (and, in shared mode, load
                // balancer affinity keeps it on the replica that has the pin).
                entries.remove(session_id);
                None
            }
        }
    }

    pub fn insert(
        &self,
        session_id: &str,
        pin: SessionPin,
        now_epoch_secs: u64,
    ) -> Result<(), PinStoreError> {
        let record = pin.to_record(credential_expiry(&pin), now_epoch_secs);
        self.append(
            &JournalOp::Put {
                session: session_id.to_string(),
                record,
            },
            now_epoch_secs,
        )?;
        // The full pin is kept in this process; only the redacted record went to
        // the journal.
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                session_id.to_string(),
                Entry::Held {
                    expires_at: pin_expiry(&pin, self.ttl_secs, now_epoch_secs),
                    pin,
                },
            );
        Ok(())
    }

    pub fn invalidate(&self, session_id: &str, now_epoch_secs: u64) -> Result<(), PinStoreError> {
        self.append(
            &JournalOp::Drop {
                session: session_id.to_string(),
            },
            now_epoch_secs,
        )?;
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(session_id);
        Ok(())
    }

    pub fn len(&self, now_epoch_secs: u64) -> usize {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.retain(|_, entry| entry.expires_at() > now_epoch_secs);
        entries.len()
    }

    /// Append one line and fsync it, reopening the journal each time so a
    /// rotated or replaced file is picked up. Failure is returned to the caller
    /// so the write path can fail closed.
    fn append(&self, op: &JournalOp, now_epoch_secs: u64) -> Result<(), PinStoreError> {
        let line = JournalLine {
            replica: self.replica_id.clone(),
            ts: now_epoch_secs,
            op: op.clone(),
        };
        let mut encoded = serde_json::to_string(&line)
            .map_err(|e| PinStoreError::new(format!("session journal encode failed: {e}")))?;
        encoded.push('\n');
        let mut journal = open_journal(&self.journal_path).map_err(|e| {
            PinStoreError::new(format!(
                "session journal write failed ({}): {}",
                self.journal_path, e
            ))
        })?;
        journal
            .write_all(encoded.as_bytes())
            .and_then(|_| journal.sync_data())
            .map_err(|e| {
                PinStoreError::new(format!(
                    "session journal write failed ({}): {}",
                    self.journal_path, e
                ))
            })
    }
}

fn open_journal(path: &str) -> Result<std::fs::File, String> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())
}

/// Absolute credential expiry, when the pinned credential has one.
fn credential_expiry(pin: &SessionPin) -> Option<u64> {
    match &pin.cred {
        PinnedCred::Pat { .. } => None,
        PinnedCred::App { expires_at, .. } => Some(*expires_at),
        PinnedCred::MultiApp { routes, .. } => routes.values().map(|r| r.expires_at).min(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_780_000_000;

    fn temp_journal(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!(
            "octobroker-pins-unit-{}-{}-{}",
            std::process::id(),
            name,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("pins.jsonl").to_str().unwrap().to_string()
    }

    fn pat_pin() -> SessionPin {
        SessionPin {
            agent_id: Some("bot-a".into()),
            cred: PinnedCred::Pat {
                identity_id: "pat-1".into(),
            },
        }
    }

    #[test]
    fn test_entry_expiry_is_bounded_by_the_ttl_and_the_credential() {
        let pat = pat_pin();
        assert_eq!(pin_expiry(&pat, 60, NOW), NOW + 60);
        // A credential that expires sooner still wins.
        let app = SessionPin {
            agent_id: None,
            cred: PinnedCred::App {
                token: "ghs_x".into(),
                expires_at: NOW + 5,
            },
        };
        assert_eq!(pin_expiry(&app, 60, NOW), NOW + 5);
        assert_eq!(pin_expiry(&app, 600, NOW), NOW + 5, "the credential still bounds it");
    }

    #[test]
    fn test_shared_store_keeps_the_full_pin_on_its_own_replica() {
        // Journal records redact installation tokens, but the replica that
        // created the session still holds it in memory.
        let path = temp_journal("held");
        let a = PinStore::shared(&path, 3_600, "replica-a").unwrap();
        let pin = SessionPin {
            agent_id: Some("bot-a".into()),
            cred: PinnedCred::App {
                token: "ghs_HELD".into(),
                expires_at: NOW + 3_600,
            },
        };
        a.insert("s1", pin.clone(), NOW).unwrap();
        assert_eq!(a.get("s1", NOW + 1), Some(pin));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_app_pin_expires_with_its_credential() {
        let store = PinStore::memory(3_600);
        store
            .insert(
                "s1",
                SessionPin {
                    agent_id: None,
                    cred: PinnedCred::App {
                        token: "ghs_x".into(),
                        expires_at: NOW + 10,
                    },
                },
                NOW,
            )
            .unwrap();
        assert!(store.get("s1", NOW + 9).is_some());
        assert!(store.get("s1", NOW + 11).is_none());
    }

    #[test]
    fn test_shared_rehydrate_picks_up_another_replicas_writes() {
        let path = temp_journal("rehydrate");
        let a = PinStore::shared(&path, 3_600, "replica-a").unwrap();
        a.insert("s1", pat_pin(), NOW).unwrap();
        // A replica that boots after the write still sees the session.
        let c = PinStore::shared(&path, 3_600, "replica-c").unwrap();
        assert!(c.get("s1", NOW).is_some());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_shared_insert_is_fail_closed_on_journal_failure() {
        let path = temp_journal("failclosed");
        let a = PinStore::shared(&path, 3_600, "replica-a").unwrap();
        a.insert("s1", pat_pin(), NOW).unwrap();
        // Unmount the journal behind the store's back: the directory holding it
        // disappears, so the next append cannot succeed.
        let dir = std::path::Path::new(&path).parent().unwrap().to_path_buf();
        std::fs::remove_dir_all(&dir).unwrap();
        let err = a.insert("s2", pat_pin(), NOW).unwrap_err();
        assert!(
            err.message.contains("session journal write failed"),
            "unexpected error: {}",
            err.message
        );
        // The failed pin must not be visible locally either.
        assert!(a.get("s2", NOW).is_none());
    }

    #[test]
    fn test_shared_store_skips_a_torn_journal_line() {
        let path = temp_journal("torn");
        {
            let a = PinStore::shared(&path, 3_600, "replica-a").unwrap();
            a.insert("s1", pat_pin(), NOW).unwrap();
        }
        // A crash mid-append leaves a partial final record.
        let mut contents = std::fs::read_to_string(&path).unwrap();
        contents.push_str("{\"replica\":\"replica-a\",\"ts\":1,\"op\":\"put\",\"sess");
        std::fs::write(&path, contents).unwrap();
        let b = PinStore::shared(&path, 3_600, "replica-b").unwrap();
        assert!(b.get("s1", NOW).is_some(), "a torn tail line must not lose earlier pins");
        // The torn record is re-read once the writer completes it.
        let mut completed = std::fs::read_to_string(&path).unwrap();
        completed.push_str("ion\":\"s2\",\"record\":null}\n");
        std::fs::write(&path, completed).unwrap();
        let c = PinStore::shared(&path, 3_600, "replica-c").unwrap();
        assert!(c.get("s1", NOW).is_some());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_memory_store_reports_mode_and_size() {
        let store = PinStore::memory(60);
        assert_eq!(store.mode(), "memory");
        assert!(store.is_empty(NOW));
        store.insert("s1", pat_pin(), NOW).unwrap();
        assert_eq!(store.len(NOW), 1);
        assert!(!store.is_empty(NOW));
    }

    #[test]
    fn test_multi_app_pin_record_lists_owners_without_tokens() {
        let mut routes = HashMap::new();
        routes.insert(
            "oablab".to_string(),
            AppRoute {
                token: "ghs_SECRET".into(),
                expires_at: NOW + 100,
                upstream_session: Some("up-1".into()),
            },
        );
        let record = SessionPin {
            agent_id: Some("bot-a".into()),
            cred: PinnedCred::MultiApp {
                routes,
                primary: "oablab".into(),
            },
        }
        .to_record(Some(NOW + 100), NOW);
        let encoded = serde_json::to_string(&record).unwrap();
        assert!(!encoded.contains("ghs_SECRET"));
        assert!(!encoded.contains("up-1"));
        assert_eq!(
            record.cred,
            PinCredRecord::MultiApp {
                owners: vec!["oablab".to_string()],
                primary: "oablab".to_string(),
            }
        );
        assert!(SessionPin::from_record(&record).is_err());
    }

    #[test]
    fn test_pat_record_roundtrips() {
        let record = pat_pin().to_record(None, NOW);
        assert_eq!(SessionPin::from_record(&record).unwrap(), pat_pin());
    }
}