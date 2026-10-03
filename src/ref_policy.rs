//! Ref-level push policy for git credentials (#49).
//!
//! `/git-credential` mints a **repository**-scoped App token, so GitHub
//! enforces the repository boundary. Inside that repository, though, the
//! token can push to *any* ref — including the default branch. Octobroker
//! does not proxy the git smart-HTTP protocol (that is explicitly not this
//! project's model: "GitHub enforces the boundary"), so the ref-level
//! boundary is GitHub's own branch protection or ruleset. This module is
//! the broker-side half of that: the decision about whether GitHub's
//! answers actually *prove* a protection exists on the default branch.
//!
//! It is deliberately pure — no network, no config, no clock — so the whole
//! decision table is exercised directly by `tests/ref_policy.rs`. Reading
//! GitHub lives in `app_token::AppTokenProvider::default_branch_protected`;
//! enforcement lives in the `/git-credential` handler.

/// Verdict on a repository's default-branch protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// GitHub reports an enforcing protection on the default branch. The
    /// `protected` flag covers classic branch protection *and* repository /
    /// organization rulesets.
    Protected,
    /// No protection, or nothing that proves one. Callers must deny —
    /// this is the fail-closed arm.
    Unprotected,
}

/// The default branch GitHub reports for a repository
/// (`GET /repos/{owner}/{repo}`). `None` when the response carries no
/// usable name: a repository whose default branch we cannot name is never
/// treated as protected, and we never guess a branch name.
pub fn default_branch(repo: &serde_json::Value) -> Option<&str> {
    let branch = repo.get("default_branch")?.as_str()?.trim();
    if branch.is_empty() {
        None
    } else {
        Some(branch)
    }
}

/// Whether a `GET /repos/{owner}/{repo}/branches/{branch}` response proves
/// the branch is protected. Only an explicit `true` counts — a missing,
/// null or non-boolean field must never read as protection.
pub fn branch_protected(branch: &serde_json::Value) -> bool {
    branch.get("protected").and_then(|v| v.as_bool()) == Some(true)
}

/// Verdict for one issuance attempt, from the two GitHub reads that answer
/// it. `repo` and `branch` are `None` when the corresponding read failed or
/// could not be parsed: a broker that proved nothing has not proved
/// protection, so the answer is `Unprotected`.
///
/// `branch` must be the response for the default branch named by `repo`, and
/// its `name` is compared against it. That closes the gap where a redirect
/// (GitHub answers `301 Moved permanently` for a renamed repo, and the HTTP
/// client follows redirects) would otherwise let the verdict describe a
/// different ref than the current default branch.
///
/// A name mismatch is deliberately indistinguishable from an open branch in
/// the verdict — both deny, and both are recorded as
/// `unprotected_default_branch`. A branch that moved between the two reads
/// is a rare race, and reporting it as "could not verify" would suggest a
/// transient GitHub problem when the repository may be fine.
pub fn default_branch_protected(
    repo: Option<&serde_json::Value>,
    branch: Option<&serde_json::Value>,
) -> Protection {
    let protected = match (repo.and_then(default_branch), branch) {
        (Some(default), Some(branch)) => {
            branch.get("name").and_then(|v| v.as_str()) == Some(default) && branch_protected(branch)
        }
        _ => false,
    };
    if protected {
        Protection::Protected
    } else {
        Protection::Unprotected
    }
}
