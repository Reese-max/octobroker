# octobroker Design

> Living distillation of [RFC #15](https://github.com/openabdev/octobroker/issues/15)
> (Revision 2) and the [Phase 0 spike findings](https://github.com/openabdev/octobroker/issues/22),
> as actually shipped. For onboarding, see [getting-started.md](getting-started.md).

## Problem

AI coding agents need GitHub access. Every conventional approach puts a
GitHub credential inside the agent's environment:

| Approach | Weakness |
|----------|----------|
| PAT in the container | Long-lived, exfiltratable, org-wide blast radius, attribution collapses to the PAT owner |
| Token vending machine | Agent still holds a live token for its lifetime; misusable within scope |
| Per-agent fine-grained PATs | Management burden; still long-lived; single-org |

octobroker's position: **the agent never holds any GitHub credential.** It holds
at most an octobroker API key — revocable centrally, bounded by policy, useless
against GitHub directly.

## Architecture

octobroker is a **credential-swapping reverse proxy with a default-deny policy
engine**, sitting between agents and two GitHub surfaces:

- **MCP** (`/mcp`) -> GitHub's hosted MCP server (`api.githubcopilot.com/mcp/`), with a
  narrowly scoped octobroker-owned review-tool exception. Upstream schemas remain
  proxied verbatim; `octobroker_*` tools are explicit, default-deny, App-backed,
  repository-bound, and fail-closed audited. octobroker does not expose arbitrary
  GraphQL or a general custom-tool registry.
- **REST/GraphQL** (`/{path}`, `/graphql`) → `api.github.com`, with PAT
  pooling (budget-aware selection) and in-memory read caching. GraphQL
  mutations pass through with the client's own token (full attribution).

### Request path (MCP)

```
agent → [authn: X-Octobroker-Key or X-Octobroker-Iam] → [per-agent quota]
      → [session binding] → [tool allowlist]
      → [write classification] → [repo allowlist (deny-if-unresolvable)]
      → [in-flight cap] → [fail-closed audit] → [upstream circuit breaker]
      → forward with scoped token
      → [buffer+parse write outcomes] → audit result
      → [metrics: request/deny/latency/session/circuit]
```

Every layer is independent; a request must clear all of them.

## Credential model

**GitHub App installation tokens are the primary credential** (the PAT pool
remains for REST reads and legacy setups). Decided in Phase 0 after the
PAT-pooling compliance concern (GitHub ToS §H rate-limit aggregation) was
raised in review:

- Minted by octobroker from the App private key (RS256 JWT → installation
  token), cached, auto-refreshed 5 minutes before the 1-hour expiry.
- **Scoped at mint**: an agent whose repo allowlist is exact entries under
  one owner gets tokens minted with the API's `repositories` parameter —
  GitHub itself enforces the repo boundary, independent of octobroker's
  argument parsing (which remains as defense-in-depth). One credential per
  policy envelope.
- **Writes never run on PATs** — enforced by startup validation, not
  convention.

### Agent authentication

Two credential mechanisms, configured per agent (Phase 3, #18):

- **`X-Octobroker-Key`** shared key(s), supporting `env:`/`aws:`/`k8s:`
  secret references and dual-key rotation.
- **`X-Octobroker-Iam`** — secretless: the client presigns
  `sts:GetCallerIdentity` (SigV4) with its ambient AWS credentials and
  sends the URL. The server verifies the proof's shape (TLS endpoint, ≤60s
  `X-Amz-Expires`, `host` signed header only, `UNSIGNED-PAYLOAD`,
  allowlisted `sts.<region>.amazonaws.com` / global `sts.amazonaws.com`
  hosts), executes it, extracts the caller ARN, and matches it against the
  agent's `iam_principals` (exact ARN, `prefix*`, or bare 12-digit account
  id; assumed-role ARNs canonicalize to the role ARN). When the key header
  is present it is the only mechanism tried — a bad key never silently
  downgrades to the IAM path. On the client, `obk mcp` resolves ambient
  credentials via the default AWS provider chain (env / ECS task role /
  EKS IRSA / instance metadata) and re-signs per request, so proofs never
  age out in flight. The agent never holds a GitHub credential.

## Session model

Sessions (`Mcp-Session-Id`) are pinned to `(credential, agent)` at
`initialize`:

- Identity never rotates mid-session; an unknown/expired session gets 404
  (per MCP spec) and the client re-initializes transparently.
- A session presented by a different agent — even with a valid key — gets
  403 (binding violation).
- A session cannot outlive its credential: expired App-token pins terminate
  the session. Provider refreshes don't disturb in-flight sessions.
- **octobroker's pin cache is the sole session authority.** Phase 0 measured the
  hosted endpoint's own session semantics as fail-open: upstream DELETE is a
  no-op (the session remains usable), and unknown sessions get 400 not 404.
  Nothing about session validity is delegated upstream.
- Pins are in-process memory → **horizontal scaling requires load-balancer
  affinity** (sticky on `Mcp-Session-Id`, or source-IP hash for pre-session
  `initialize`). Without affinity a second replica cannot resolve a
  session created on the first: requests return 404 and the client
  re-initializes — correct but chatty; a client unlucky enough to flap
  between replicas re-initializes on every hop. Shared session state
  (external store) is deliberately deferred — the pin cache interface is
  the seam if it ever becomes necessary.
- Config change = restart = all sessions revoked (the current revocation
  story). Clients are expected to re-initialize on 404 — `obk mcp` does so
  automatically.

## Policy model

Per-agent, default-deny, enforced at the proxy and mirrored upstream:

```toml
[[mcp.agents]]
id    = "my-bot"
keys  = ["env:KEY_CURRENT", "env:KEY_NEXT"]   # rotation: both valid
tools = ["issue_read", "create_issue"]        # exact names, default-deny
repos = ["my-org/repo-a", "my-org/*"]         # exact or owner wildcard
```

- The tool allowlist is injected upstream as **`X-MCP-Tools`** (exact
  per-tool filtering, discovered and verified in Phase 0). We deliberately
  do NOT use `X-MCP-Toolsets` for enforcement: Phase 0 found invalid
  toolset names are silently ignored — fail-open.
- All client-supplied `X-MCP-*` headers are stripped; the upstream header
  set is built from scratch (a client cannot widen its own permissions).
- Repo authorization is deny-if-unresolvable: a repo-restricted agent's
  call whose arguments name no repository is rejected.
- Write classification is rule-based and conservative: only
  `get_*`/`list_*`/`search_*`/`*_read` names are reads; **everything else,
  including unknown names, is a write**.

## Write gate

`enable_writes = true` requires — validated at boot, or the process refuses
to start:

1. `[[mcp.agents]]` (writes never exist in network-trust mode)
2. `[mcp.github_app]` (writes never run on PATs)
3. `[mcp.audit]` (writes are never unaudited)

The audit trail is **fail-closed**: a pre-flight JSONL record is fsync'd
before the call is forwarded; if it cannot be persisted, the write is
rejected (503) without side effects. The result record captures the **MCP
tool outcome** — `result.isError` arrives inside HTTP 200/SSE, so transport
status alone is never treated as success. Argument values are never logged
(key names + resolved repo only). octobroker never auto-retries a forwarded
call; ambiguous outcomes are recorded as undeterminable and surfaced to the
caller.

## Operational hardening (Phase 3)

- **Per-agent quotas**: token bucket per agent (`rate_limit_rpm`,
  `default_rate_limit_rpm` fallback; `0` = unlimited). Excess → `429` +
  `Retry-After` in seconds, before any policy work — a noisy agent cannot
  consume upstream budget.
- **Upstream circuit breaker**: consecutive upstream transport errors and
  5xx responses trip the breaker (`failure_threshold`, default 5). While
  open, calls fail fast with `503` + `Retry-After: <cooldown_secs>`; after
  the cooldown one half-open probe decides close-vs-extend. 4xx responses
  do not count (the upstream is alive — the failure is contractual, not
  sickness). No call is ever auto-retried by the proxy — *especially*
  writes; the shim retries only provably idempotent methods.
- **Timeouts**: POST is bounded by `upstream_timeout_secs` (default 120).
  GET streams stay unbounded (long-lived resumable responses); DELETE has
  its own short timeout.
- **Metrics**: `GET /metrics` exposes Prometheus text — request counters
  by `{agent, method, tool, result}`, denial counters by `{agent, reason}`
  (authn/tool/repo/write/session/quota/circuit classes), upstream call
  counts + latency histogram by result class, live session gauge, and a
  `octobroker_mcp_circuit_open` gauge. A scrape with `denied_total` rising
  faster than `requests_total` is the "someone is banging on a closed
  door" signal; `circuit_open == 1` is the upstream-outage page.
- **Cache authorization**: the REST response cache is never consulted on
  the MCP path — MCP responses carry session- and agent-scoped content
  keyed by no cacheable identity tuple. The `test_mcp_responses_never_cached`
  probe pins this down: if MCP caching is ever added, the cache key must
  include agent + session identity or it is an authorization bypass.

## Known constraints & non-goals

- **Session pins are in-process** (MCP): scale out only behind
  affinity-aware load balancing; see Session model.
- **No rate-limit headers on the hosted MCP endpoint** (Phase 0 finding) —
  the per-agent quota is therefore the only noisy-neighbor defense on the
  MCP path.
- **GitHub-side write attribution is the App identity**, not the individual
  agent. The octobroker audit log is the per-agent ledger; GraphQL mutation
  passthrough remains the right path when GitHub-side per-human attribution
  matters.
- **Contract-drift risk**: the hosted MCP surface (tool names, headers like
  `X-MCP-Tools`) is partially undocumented. A daily e2e canary exercises
  the full flow — including real App-token minting — against the live
  endpoint.
- Phase 3 (#18) shipped: SigV4/STS secretless agent auth via `obk mcp`,
  per-agent quotas, upstream circuit breaker, `/metrics`, upstream
  contract probes (timeout / mid-stream disconnect / credential expiry /
  no-cache). Remaining: shared session state for affinity-free scaling is
  a deliberate deferral (see Session model).

## Decision log

| Decision | Where | Why |
|----------|-------|-----|
| Proxy official schemas, define no tools | RFC Rev 1 | Zero schema maintenance; GitHub owns the surface |
| GitHub App primary, PAT pool legacy | RFC Rev 2 / #22 | ToS compliance, short-lived creds, scoped mint |
| `X-MCP-Tools` not `X-MCP-Toolsets` | #22 finding F | Toolsets fail open on invalid names |
| octobroker is session authority | #22 finding I | Upstream DELETE is a no-op |
| 404 on unknown session, never rotate identity | #20 review | MCP spec; no silent actor switching |
| Buffer + parse write responses | #17 review | `isError` inside HTTP 200; audit must record tool outcome |
| Scoped installation tokens per policy envelope | #17 review | GitHub enforces the repo boundary, not just our parser |
| Writes: App + audit + agents required in code | #17 review | Hard rules, not documented hopes |
| `octobroker_*` review tools as a narrow MCP exception | #44 / PR #45 | Fill upstream capability gaps without arbitrary GraphQL; preserve default-deny, repo binding, App credentials, and audit |
| SigV4 presigned STS as agent identity | #18 | Secretless agent authn; same primitive as aws-iam-authenticator; proof ≤60s, TLS, host-allowlisted |
| Affinity over shared session state | #18 | Pin cache is in-process; sticky LB is sufficient — no external store dependency yet |
