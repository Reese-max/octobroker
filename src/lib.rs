//! Library target for the octobroker binary package.
//!
//! Exists so `tests/` integration tests can exercise self-contained
//! modules through a stable public surface. Only modules that are
//! dependency-free of the binary's internals (AppState, handlers) are
//! exported here — the binary keeps its own module tree in `main.rs`.
pub mod approvals;
