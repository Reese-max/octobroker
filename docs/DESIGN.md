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
agent → [authn: X-Octobroker-Key] → [session binding] → [tool allowlist]
      → [write classification] → [repo allowlist (deny-if-unresolvable)]
      → [in-flight cap] → [fail-closed audit] → forward with scoped token
      → [buffer+parse write outcomes] → audit result
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
- Pins are in-process memory → single replica while MCP is enabled; config
  change = restart = all sessions revoked (the current revocation story).

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

## Known constraints & non-goals

- **Single replica** (MCP): session pins, IAM exchange tokens, quota buckets
  and the circuit breaker are in-process. The Phase-3 (#18) operational
  model is **load-balancer session affinity** — replica loss drops that
  replica's pins; clients re-`initialize` on the next 404. See the Phase 3
  section below.
- **No rate-limit headers on the hosted MCP endpoint** (Phase 0 finding) —
  budget accounting stays REST-driven; agent-facing quotas (#18) are
  octobroker's own token buckets.
- **GitHub-side write attribution is the App identity**, not the individual
  agent. The octobroker audit log is the per-agent ledger; GraphQL mutation
  passthrough remains the right path when GitHub-side per-human attribution
  matters.
- **Contract-drift risk**: the hosted MCP surface (tool names, headers like
  `X-MCP-Tools`) is partially undocumented. A daily e2e canary exercises
  the full flow — including real App-token minting — against the live
  endpoint.

## Phase 3 — operational hardening (#18)

**SigV4 secretless auth.** `POST /mcp/iam-auth` implements the Vault
AWS-auth pattern: the client submits the wire components of a signed
`sts:GetCallerIdentity` POST; octobroker validates shape (method,
allowlisted endpoint URL, `AWS4-HMAC-SHA256` with `…/<region>/sts/aws4_request`
scope, `SignedHeaders` ⊆ the forwardable allowlist and covering `host`,
`x-amz-date`, `x-octobroker-server-id`), enforces the signed server-id value
and a ≤60s `X-Amz-Date` freshness window, then replays the request verbatim
to STS — **STS is the signature oracle**, octobroker never verifies
signatures itself. The returned ARN maps to an agent via `iam_arns`
(exact or trailing-`*` prefix, covering the `assumed-role/<role>/<session>`
form). Success mints a 256-bit `X-Octobroker-Iam-Token` (`iam_tokens` cache,
`token_ttl_secs`). `obk mcp` is the stdio shim: it resolves ambient
credentials via `aws-config` (ECS task role / EKS IRSA / env), signs the
proof, refreshes the token ~60s before expiry, tracks `mcp-session-id`, and
unframes SSE responses back to stdout.

**Quotas + breaker.** Per-agent token buckets (`requests_per_minute`,
global `agent_requests_per_minute` default) gate every `/mcp` verb;
exhaustion → `429` + `Retry-After`. The upstream circuit breaker counts
transport errors, 429s and 5xx (never 4xx — a caller problem); open →
`503` + `Retry-After` with zero upstream I/O, half-open probe after the
cooldown. It wraps both the single-route and the multi-app fan-out paths.
Upstream `Retry-After` headers are propagated downstream. `obk mcp` retries
only idempotent methods (`initialize`, `tools/list`, `ping`, …) with bounded
exponential backoff honoring `Retry-After`; `tools/call` is never retried —
a write's outcome is undeterminable once sent.

**Observability.** `GET /metrics` exposes Prometheus text:
per-agent request/deny counters (deny reasons: policy, auth, quota,
session, breaker, audit, inflight), upstream request/failure/stream-error
totals, a latency histogram, the breaker gauge, pinned-session gauge, and
IAM exchange counters. The same numbers sit under `"mcp"` in `GET /stats`.
No credential material, tool arguments, or raw JSON-RPC payloads ever reach
metrics — labels are configured agent ids and fixed enums only.

**Scaling model.** In-process state is deliberate: exporting session pins
(which hold live upstream credentials) to a shared store would widen the
credential trust boundary for a marginal availability gain. The supported
model is LB session affinity; replica loss → 404 → client re-`initialize`.
`idle_session_expiry_forces_reinitialize` (tests/phase3.rs) pins this
contract: the client-visible behavior of TTL expiry and replica loss is
identical.

**Upstream contract probes** (tests/phase3.rs, feeding the design):

| Probe | Behavior | Design consequence |
|-------|----------|--------------------|
| POST timeout | `post_timeout_secs` (default 120s) bounds initialize/tools/call → JSON-RPC 502 | prevents pinned tasks; timeout is configurable for probes |
| Mid-stream disconnect | truncated/aborted body surfaces as a client-visible transport error, counted as `upstream_stream_errors_total` | never a silent clean EOF on a partial frame; GET has no total timeout (resumption channel) |
| Credential/session expiry mid-flight | next request → 404 | client re-`initialize`; identical to replica-loss semantics |
| Upstream 429 | `Retry-After` propagated + counts toward breaker | client backoff honors the upstream's own signal |

**Cache authorization.** There is no MCP response cache — responses carry
per-agent `X-MCP-Tools` injections and session-bound state. Any future MCP
response cache MUST key entries by the full policy envelope (agent id +
resolved tool allowlist + repo scope); a response fetched under a more
privileged identity must never serve a less-privileged agent. The existing
REST cache is already identity-scoped and stays that way.

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
| SigV4 GetCallerIdentity proof exchange + `obk mcp` shim | #18 | Vault AWS-auth pattern: ambient IAM creds prove identity without shipping a static secret into the agent container; STS is the signature oracle |
| LB session affinity, not shared pin store | #18 | Pins hold live credentials; a shared store widens the trust boundary. Replica loss → 404 → re-init is already the MCP client contract |
| Token-bucket quota + upstream circuit breaker | #18 | Noisy-neighbor protection local to the proxy; fail-fast while upstream is wedged instead of pinning handler tasks |
| `/metrics` Prometheus exposition | #18 | Bounded labels (agent id, kind/reason enums) — dashboards + alerts without exporting payloads or credentials |
| No MCP response cache | #18 | Responses are per-agent (allowlist injection) + session-bound; the cache-authorization invariant is documented for any future cache |
