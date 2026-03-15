# better-auth-rs — Rust Implementation of Better Auth

This file is institutional memory for project-specific conventions that
are easy to miss by only reading the code.

Update this file when one of these changes:

- source-of-truth hierarchy or reference server version
- alignment phase definitions or completion status
- feedback loop infrastructure or what it compares
- coding conventions that future agents would otherwise keep only in
  their head
- Commands section (new scripts, changed workflows)

Do not add:

- one-off implementation notes or debugging findings
- change summaries or recent-refactor details
- facts that are obvious from the code, tests, or `Cargo.toml`
- per-endpoint alignment status (track that in tests, not prose)

## Goal

Bring better-auth-rs to 100% behavioral alignment with the canonical
TypeScript better-auth implementation. The Rust server must be a
transparent drop-in for the TS server: any client built against
better-auth (JS/TS) must work identically against better-auth-rs without
code changes. "Identically" means matching response shapes, status codes,
headers, cookies, error formats, and observable side effects for every
endpoint in the reference spec.

This is not a loose port or an "inspired by" project. The TypeScript
implementation is the spec. Where the OpenAPI schema and the TS runtime
behavior disagree, the TS runtime wins.

The behavioral target is the same capability as the TS implementation.
The Rust integration surface does not need to transliterate the TS
integration API. Public Rust interfaces should be idiomatic Rust while
preserving TS-compatible wire behavior for supported features.

Licensed under MIT OR Apache-2.0. The project uses Rust edition 2024.

## Source of Truth (in priority order)

1. **TypeScript better-auth runtime behavior** — the reference server in
   `compat-tests/reference-server/` is the oracle. Its behavior must stay
   aligned with the pinned reference version `better-auth@1.4.19`.
   When in doubt, send a request to both servers and observe what the TS
   server actually does.
2. **TypeScript better-auth source code** — use the local checkout at
   `/home/peron/dev/better-auth` to understand intent, edge cases, schema
   generation, and hook semantics that the OpenAPI spec does not capture
   when it is available. The portable reference harness itself must not
   depend on that checkout at runtime; it uses the published package
   pinned to `better-auth@1.4.19`.
3. **`better-auth.yaml` OpenAPI spec** — the structural contract for
   endpoints, request/response schemas, and field names.
4. **better-auth documentation** (https://www.better-auth.com/docs) —
   secondary reference for user-facing behavior.

## Capability and Consumer Policy

- **TS better-auth decides behavior** — runtime behavior and feature
  capability are anchored to the pinned reference version
  `better-auth@1.4.19`. Use the local checkout when available for source
  inspection, not as a runtime dependency of the compatibility harness.
- **Rust should be Rust-native** — builders, traits, extractors, router
  integration, hooks, and embedding APIs should follow Rust idioms
  rather than mirroring TS ergonomics mechanically.
- **Design for many consumers** — public Rust interfaces should be
  broadly usable across many applications, not specialized to a single
  product or demo.
- **`platform` is a reference consumer** — `/home/peron/dev/platform` is
  an important downstream non-demo adopter and pressure test for
  real-world usability. Treat it as an external compatibility signal,
  not as a project whose migration work can be planned or assumed here.
- **Do not optimize for the demo** — demos and compat harnesses are
  validation tools, not the product target.
- **PaaS surface coverage is required** — the interface list in
  `/home/peron/downloads/better-auth-paas-api-surface.md` must be
  fully covered across the roadmap. Remaining Better Auth capability can
  be scheduled after that checklist is complete.

If the TS source, the OpenAPI spec, and the docs contradict each other,
trust the TS source. If a TS behavior looks like a bug, match it anyway
and leave a `// NOTE: matches TS bug — <link>` comment; do not
"improve" the behavior.

Before writing any code, you MUST have:

- The reference server dependencies installed
  (`cd compat-tests/reference-server && bun install`).
- The `better-auth.yaml` spec in the workspace root.

If the local Better Auth checkout is available at
`/home/peron/dev/better-auth`, use it for source inspection. If it is
not available, the portable Bun reference harness remains the runtime
oracle.

## Commands

```bash
cargo fmt --check
cargo clippy --workspace                       # must produce zero warnings
cargo clippy --workspace --features axum       # also check with axum feature
cargo test --workspace --lib                   # library unit tests
cargo test --test wire_compat_smoke_tests -- --nocapture                    # thin raw wire-compat smoke suite
cargo test --features axum --test axum_integration_tests                    # feature-gated Axum HTTP integration
cargo test --test client_compat_tests phase0_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests phase1_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests full_client_compat -- --ignored --nocapture
./scripts/alignment-check.sh                   # full alignment pipeline (all 3 layers)
./scripts/alignment-check.sh --skip-build      # skip cargo build step
cargo tarpaulin --workspace --lib              # measure function coverage
cd compat-tests/client-tests && bun test tests/phase0
cd compat-tests/client-tests && bun test tests/phase1
bash compat-tests/client-tests/run-against-both.sh phase0
bash compat-tests/client-tests/run-against-both.sh phase1
```

### JavaScript tooling

**Bun** is the package manager (not npm). Use `bun install` to manage
dependencies. All JS projects use `bun.lock` (no `package-lock.json`).

**Bun** is the preferred runtime for compatibility infrastructure. The
portable TS reference harness should run under Bun and use `bun:sqlite`.
Use Node only when a specific upstream/tooling task still requires it.

## Feedback Loop

### Alignment check

The alignment check script is `scripts/alignment-check.sh`. It:

1. Builds the Rust workspace (fail fast on compile errors).
2. Runs the thin raw wire-compat smoke suite.
3. Runs the feature-gated Axum integration tests.
4. Runs the spec coverage report.
5. Runs the ignored Rust client-compat harness for both servers.
6. Prints a clear pass/fail summary.

Preflight: check that `bun` is available and that the Bun workspaces in
`compat-tests/reference-server/` and `compat-tests/client-tests/` have
been installed. Fail with an actionable error message if not.

### What the raw wire smoke tests compare

The thin raw wire-compat smoke tests (`tests/wire_compat_smoke_tests.rs`)
compare only the parts of the contract that `better-auth/client` cannot
prove well on its own:

- **Status codes** — must match exactly.
- **Cookie names and attributes** — `better-auth.session_token` and
  related cookies must have matching names, `Path`, `HttpOnly`,
  `SameSite`, and `Secure` attributes.
- **Header names** — `content-type`, redirect, and auth-related headers
  that the client layer does not normalize away should match.
- **Response body shape** — only for the retained smoke cases where the
  client cannot express the transport semantics cleanly.

Do NOT compare: exact values of IDs, tokens, timestamps, or hashes;
ordering of JSON keys; whitespace or formatting.

### Test structure

The broad happy-path endpoint matrices belong in the client-compat Bun
suite, not in the raw wire smoke layer. Keep the raw layer narrow and
focused on transport semantics and non-client-exercised surfaces.

### Three-layer testing strategy

1. **Unit/integration tests** (`cargo test --workspace --lib`) — Rust-only,
   in-process. Tests individual functions and modules without network I/O.

2. **Raw wire smoke tests** (`cargo test --test wire_compat_smoke_tests -- --nocapture`) —
   Small retained raw comparisons for cookie/header/null-session and
   other transport details the client layer cannot prove well.

3. **Client compatibility tests** (`cargo test --test client_compat_tests ... --ignored --nocapture`) —
   Uses the real `better-auth/client` SDK inside Bun to run the same
   scenario against both backends, compare client-visible results, and
   attach raw trace diffs for debugging. This is the primary
   compatibility system.

   - `compat-tests/client-tests/` — Bun test project with phase-scoped
     scenarios and a shared TS-vs-Rust diff harness
   - `compat-tests/reference-server/` — Bun-native TS reference server
     using `bun:sqlite` and the published `better-auth@1.4.19`
   - `compat-tests/rust-server/` — Minimal Axum server matching the
     reference server config exactly (same secret, same basePath)
   - `tests/client_compat_tests.rs` — ignored Rust tests that orchestrate
     both servers and invoke the Bun phase suites

   Port allocation:
   The ignored Rust client-compat tests allocate ephemeral localhost
   ports automatically. Ports `3100` and `3200` remain the default
   manual-debug ports for the convenience wrapper and ad hoc runs.

Use all three layers. Layer 1 catches logic bugs fast. Layer 2 catches
transport regressions the client does not expose well. Layer 3 is the
hard compatibility gate: any `better-auth/client` drift is
unacceptable. Raw response-shape drift should still be minimized, but it
is best-effort unless it is client-visible or otherwise clearly
consumer-relevant.

## How to Work

### Workflow

1. Stay in the current phase until it has zero alignment diffs.
2. Break capability work into the smallest phase that can be finished
   cleanly. If a feature family mixes nearly-done endpoints with cold
   or obviously unfinished endpoints, split the family instead of
   keeping it bundled together.
3. Prefer finishing already-implemented or already-tested endpoints
   before starting colder surfaces.
4. Then pick the next uncovered capability from
   `/home/peron/downloads/better-auth-paas-api-surface.md`.
5. Use `/home/peron/dev/platform` only as a downstream compatibility
   reference for prioritization and sanity checks; do not plan work that
   assumes control over changes in that repo.
6. Read the TS source for that capability to understand the full
   behavior, including edge cases and error paths.
7. Implement or fix the Rust version.
8. Run the dual-server test for that capability whenever possible.
9. Iterate until the diff is clean.
10. Commit.

Do not batch multiple endpoint fixes into one commit. Each endpoint or
behavior fix is its own commit.

### Phase Completion Rule

A phase is only valid if it is self-contained: every endpoint and
behavior in that phase must be end-to-end testable using only the
capabilities from that phase and the phases before it.

A phase is only complete when all of the following are true:

1. Every endpoint or behavior in the phase has meaningful Rust-side
   tests at the right layer.
2. Every endpoint or behavior in the phase has dual-server TS
   comparison coverage whenever a reference-server comparison is
   possible.

Do not use a generic "remaining capability" phase. When a new TS feature
family becomes in scope, add a new explicit phase with its own
self-contained test plan.

### Alignment phases

**Phase 0 — Core auth flow:**
`/sign-up/email`, `/sign-in/email`, `/get-session`, `/sign-out`,
`/ok`, `/error`

**Phase 1 — Session and password management:**
`/list-sessions`, `/revoke-session`, `/revoke-sessions`,
`/revoke-other-sessions`, `/refresh-token`, `/get-access-token`,
`/request-password-reset`, `/reset-password`, `/change-password`

**Phase 2 — User self-service and verification:**
`/update-user`, `/delete-user`, `/delete-user/callback`,
`/change-email`, `/send-verification-email`, `/verify-email`,
`/set-password`

Phase 2 is self-contained on top of Phases 0 and 1. Completion requires
direct end-to-end coverage for each endpoint in this group.

**Phase 3 — Social-linked account surface:**
`/sign-in/social`, `/callback`, `/link-social`, `/list-accounts`,
`/unlink-account`

Phase 3 is self-contained on top of Phases 0, 1, and 2. Completion
requires dual-server coverage for the GitHub/mock-OAuth flows in this
group, including callback behavior.

**Phase 4 — Machine auth and API-key CRUD:**
Bearer behavior, `/api-key/create`, `/api-key/list`, `/api-key/get`,
`/api-key/update`, `/api-key/delete`, `/api-key/verify`

Phase 4 is self-contained on top of Phases 0 and 1. Completion requires
both endpoint tests and end-to-end request-path tests using
`Authorization: Bearer` and `x-api-key`.

**Phase 5 — Organization core:**
`/organization/create`, `/organization/check-slug`,
`/organization/update`, `/organization/delete`,
`/organization/get-full-organization`, `/organization/set-active`,
`/organization/list`, `/organization/list-members`,
`/organization/get-active-member`,
`/organization/get-active-member-role`,
`/organization/update-member-role`,
`/organization/remove-member`, `/organization/leave`,
`/organization/invite-member`,
`/organization/accept-invitation`,
`/organization/reject-invitation`,
`/organization/cancel-invitation`,
`/organization/get-invitation`,
`/organization/list-invitations`,
`/organization/list-user-invitations`,
`/organization/has-permission`

Phase 5 comes before colder surfaces because organization CRUD,
membership, and invitation flows already have meaningful local coverage.

**Phase 6 — Admin core:**
`/admin/list-users`, `/admin/create-user`, `/admin/remove-user`,
`/admin/set-user-password`, `/admin/set-role`,
`/admin/has-permission`

Phase 6 finishes the admin endpoints with the strongest current local
coverage before moving to less-proven admin flows.

**Phase 7 — Passkey surface:**
All `/passkey/*` endpoints.

Phase 7 is still relatively early because passkey option generation,
management, and error-shape paths are already implemented and tested.

**Phase 8 — Organization advanced:**
`/organization/create-team`, `/organization/remove-team`,
`/organization/update-team`, `/organization/list-teams`,
`/organization/set-active-team`, `/organization/list-user-teams`,
`/organization/list-team-members`,
`/organization/add-team-member`,
`/organization/remove-team-member`,
`/organization/create-role`, `/organization/delete-role`,
`/organization/list-roles`, `/organization/get-role`,
`/organization/update-role`

Phase 8 depends on Phase 5 and is otherwise self-contained.

**Phase 9 — Admin extended support flows:**
`/admin/get-user`, `/admin/update-user`, `/admin/ban-user`,
`/admin/unban-user`, `/admin/impersonate-user`,
`/admin/stop-impersonating`, `/admin/list-user-sessions`,
`/admin/revoke-user-session`, `/admin/revoke-user-sessions`

Phase 9 depends on Phase 6 and is otherwise self-contained.

**Phase 10 — Two-factor authentication:**
All `/two-factor/*` endpoints.

Phase 10 is intentionally isolated because the 2FA surface has its own
state machine and needs dedicated end-to-end coverage.

**Phase 11 — Cold account and token surfaces:**
`/verify-password`, `/update-session`, `/account-info`, `/token`

Phase 11 is reserved for the smaller cold surfaces that are not yet
proven enough to bundle into the earlier hot-path phases. Complete this
phase only once each endpoint has its own direct end-to-end test
coverage and, where possible, dual-server comparison coverage.

Work the phases in order. Do not start Phase N+1 until Phase N has zero
alignment diffs.

## Coding Standards

### Structure

Keep public APIs minimal. Structure code around durable boundaries, not
short-term convenience. Prefer less code when clarity is preserved.
Avoid duplicate logic by relying on types, validated interfaces, and
existing guarantees.

Recommended file size is under 500 lines. Hard limit is 1000 lines; if
reached, break the file down.

### Naming

All JSON field names in responses MUST be camelCase. Rust struct fields
use snake_case with `#[serde(rename_all = "camelCase")]`. Never emit
snake_case in a JSON response.

### Dependencies

Prefer mature dependencies over bespoke code when they simplify the
design. Remove dependencies that constrain the design. Use `cargo add` /
`cargo remove` for dependency changes so package names and versions come
from current registry data, not memory. Hand-edit `Cargo.toml` only for
details Cargo cannot express.

### Idioms

If translating an idea from the TypeScript source, rewrite it in Rust
idioms instead of transliterating the TypeScript pattern.

### Error Handling

Use `thiserror` for library errors, `anyhow` in binary/CLI layers.
Handle every `Result` — never silently discard.

Match the TS error behavior by default. If the TS server returns
`{ "code": "USER_NOT_FOUND" }` with status 404, the Rust server should
do the same. Do not invent error codes or change status codes. The only
acceptable exception is a documented, client-inert best-effort
response-shape drift; status-code drift is never acceptable.

`AuthError::to_auth_response()` converts errors to `AuthResponse`.
Do not name inherent methods `into_response` — that collides with
Axum's `IntoResponse` trait when the `axum` feature is enabled.

### Cookie Handling

Cookie behavior is a core part of the auth contract. The session token
cookie name, attributes, and lifecycle must match the TS implementation.
Read `packages/better-auth/src/cookies/` in the TS source carefully.

### Documentation

Doc comments on every public item — no exceptions. `cargo doc` must
produce clean, navigable documentation with no missing-docs warnings.
When behavior or a public API changes, update related comments and docs
in the same change.

### Testing

Coverage should be judged by behavior and risk, not by a raw percentage
target. Broad, meaningful coverage is encouraged when it improves
confidence. Add tests for new behavior and regressions. Every change
that affects meaningful logic (branching, transformations, error
handling, compatibility-critical flows) should have tests at the right
layer. Prefer tests that exercise real behavior over low-value tests for
code that can only break if the language, runtime, or a dependency
breaks. When test layers disagree, treat `better-auth/client` drift as a
release blocker, fix unclassified dual-server wire drift by default, and
allow only documented, client-inert best-effort wire drift to remain.

### Git

Use conventional commits (`feat:`, `fix:`, `refactor:`, `test:`,
`docs:`, `chore:`). Commit frequently and autonomously instead of
batching large changes. Each commit must pass `cargo fmt --check`,
`cargo clippy` (zero warnings), and `cargo test`.

### Refactoring

If an abstraction is wrong, refactor or rewrite it instead of layering
fixes on top. Large-scale rewrites and breaking changes are encouraged
when they are the right fix. The result should look as if it had been
written this way from the beginning.

### Lint Policy

Zero warnings. Both `cargo clippy --workspace` and
`cargo clippy --workspace --features axum` must produce zero warnings.

Do not use `#[allow(...)]`. Use `#[expect(...)]` with a `reason` field
only when suppression is genuinely justified. If a lint fires, fix the
code.

### Performance

Performance matters, especially on hot paths and user-visible auth
flows. Prefer simple designs, avoid obvious regressions, and measure
when a change is performance-sensitive or the tradeoff is unclear.
Benchmarks are encouraged when they meaningfully guide or protect the
design, but they are not required for every hot path. Any known
performance regression must be explained to the human before
committing.

### Workarounds

Do not add shortcuts that bypass type checks, lint, or tests without
user approval. Do not add environment-specific workarounds without user
approval. Keep the implementation direct and clean.

## Reference Server Version Tracking

The reference server is pinned to `better-auth@1.4.19`. When upgrading:

1. Update `compat-tests/reference-server/package.json`.
2. Run `bun install`.
3. Re-run the full alignment check.
4. Update `better-auth.yaml` from the new version's OpenAPI output.
5. Fix any new mismatches.
6. Commit the version bump and all fixes together.

Do not upgrade the reference version until the current version has zero
alignment diffs.
