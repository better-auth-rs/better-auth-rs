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

Licensed under MIT OR Apache-2.0. The project uses Rust edition 2024.

## Source of Truth (in priority order)

1. **TypeScript better-auth runtime behavior** — the reference server in
   `compat-tests/reference-server/` is the oracle. When in doubt, send
   a request to both servers and observe what the TS server actually does.
2. **TypeScript better-auth source code** — read it to understand intent,
   edge cases, and error handling that the OpenAPI spec does not capture.
   The pinned version is `better-auth@1.4.19`.
3. **`better-auth.yaml` OpenAPI spec** — the structural contract for
   endpoints, request/response schemas, and field names.
4. **better-auth documentation** (https://www.better-auth.com/docs) —
   secondary reference for user-facing behavior.

If the TS source, the OpenAPI spec, and the docs contradict each other,
trust the TS source. If a TS behavior looks like a bug, match it anyway
and leave a `// NOTE: matches TS bug — <link>` comment; do not
"improve" the behavior.

Before writing any code, you MUST have:

- The TS better-auth source (cloned locally or available to read).
- The reference server dependencies installed
  (`cd compat-tests/reference-server && bun install`).
- The `better-auth.yaml` spec in the workspace root.

If any of these are missing, stop and ask.

## Commands

```bash
cargo fmt --check
cargo clippy --workspace
cargo test --workspace --lib                   # library unit tests
cargo test --test dual_server_tests            # dual-server comparison (needs ref server)
./scripts/alignment-check.sh                   # full alignment pipeline (all 3 layers)
./scripts/alignment-check.sh --skip-build      # skip cargo build step
cd compat-tests/client-tests && bun test:ts    # client tests against TS only
cd compat-tests/client-tests && bun test:rust  # client tests against Rust only
bash compat-tests/client-tests/run-against-both.sh  # client tests against both
```

### JavaScript runtime

All JS/TS tooling in this project uses **Bun** (not npm/node). Use
`bun install`, `bun run`, `bun test` for all JS operations. The
reference server and client test projects both use `bun.lock`.

## Feedback Loop

Your first task before touching any endpoint code is to build the
alignment testing infrastructure. This is the most important thing in
the project — without it, nothing else matters.

### Infrastructure (implemented)

The alignment check script is `scripts/alignment-check.sh`. It:

1. Builds the Rust workspace (fail fast on compile errors).
2. Starts the TS reference server (`compat-tests/reference-server/`)
   on port 3100 as a background process.
3. Runs the dual-server comparison tests against both servers.
4. Runs the spec coverage report.
5. Prints a clear pass/fail summary.
6. Cleans up the reference server process on exit (including on
   failure or Ctrl-C).

Preflight: check that `node` is available and that
`compat-tests/reference-server/node_modules` exists. Fail with an
actionable error message if not.

### What the dual-server tests compare (implemented)

The dual-server tests (`tests/dual_server_tests.rs`) compare all of:

- **Status codes** — must match exactly.
- **Response body shape** — field names, nesting, types (string vs
  number vs boolean vs null). Dynamic values (IDs, tokens, timestamps)
  are compared by type, not value.
- **Cookie names and attributes** — `better-auth.session_token` and
  related cookies must have matching names, `Path`, `HttpOnly`,
  `SameSite`, and `Secure` attributes.
- **Error format** — error responses must match the TS shape exactly,
  whatever that shape is (discover it by sending bad requests to the TS
  server, do not guess).
- **Header names** — `content-type` and auth-related headers should
  match.

Do NOT compare: exact values of IDs, tokens, timestamps, or hashes;
ordering of JSON keys; whitespace or formatting.

### Test structure

Every endpoint must have a dual-server comparison test that sends at
least: a happy-path request, a request with missing required fields, a
request with invalid input, and a request with/without auth as
appropriate.

Tests must actually hit both servers. If the reference server is not
available, skip with a diagnostic. Never let a skipped test pass
silently in CI when the reference server should be running.

### Validation

Once the infrastructure is built, run the alignment check on the
Phase 0 endpoints (`/ok`, `/error`, `/sign-up/email`, `/sign-in/email`,
`/get-session`, `/sign-out`). This will produce the first real alignment
report. Commit the infrastructure, then start fixing mismatches.

### Three-layer testing strategy

1. **Unit/integration tests** (`cargo test --workspace --lib`) — Rust-only,
   in-process. Tests individual functions and modules without network I/O.

2. **Dual-server shape comparison** (`cargo test --test dual_server_tests`) —
   Raw HTTP requests sent to both the Rust server (in-process) and the
   TS reference server (port 3100). Compares status codes, response
   bodies, cookies, headers, and error shapes structurally.

3. **Client integration tests** (`compat-tests/client-tests/`) — Uses the
   real `better-auth/client` JavaScript SDK (`createAuthClient`) to
   exercise both backends. This proves that a real app using the
   better-auth client can switch between TS and Rust at zero cost.
   The client handles cookies, session state, and error parsing — bugs
   in any of these are invisible to raw HTTP comparison.

   - `compat-tests/client-tests/` — Bun test project with the client SDK
   - `compat-tests/rust-server/` — Minimal Axum server matching the
     reference server config exactly (same secret, same basePath)
   - `compat-tests/client-tests/run-against-both.sh` — Starts both
     servers and runs the same test suite against each

   Port allocation:
   | Server | Port | Purpose |
   |--------|------|---------|
   | TS reference | 3100 | Canonical TS better-auth |
   | Rust compat | 3200 | Rust server for client tests |

Use all three layers. Layer 1 catches logic bugs fast. Layer 2 catches
structural mismatches. Layer 3 catches client-visible integration bugs.

## How to Work

### Workflow

1. Pick the next unaligned endpoint or behavior from the alignment
   report.
2. Read the TS source for that endpoint to understand the full behavior,
   including edge cases and error paths.
3. Implement or fix the Rust version.
4. Run the dual-server test for that endpoint.
5. Iterate until the diff is clean.
6. Commit.

Do not batch multiple endpoint fixes into one commit. Each endpoint or
behavior fix is its own commit.

### Alignment phases

**Phase 0 — Core auth flow:**
`/sign-up/email`, `/sign-in/email`, `/get-session`, `/sign-out`,
`/ok`, `/error`

**Phase 1 — Session and password management:**
`/list-sessions`, `/revoke-session`, `/revoke-sessions`,
`/revoke-other-sessions`, `/refresh-token`, `/get-access-token`,
`/forget-password`, `/reset-password`, `/change-password`

**Phase 2 — User and account management:**
`/update-user`, `/delete-user`, `/change-email`,
`/verify-email`, `/send-verification-email`,
`/link-social`, `/unlink-account`, `/list-accounts`

**Phase 3 — Plugins (admin, 2FA, passkey, API key, organization):**
All `/admin/*`, `/two-factor/*`, `/passkey/*`, `/api-key/*`,
`/organization/*` endpoints.

**Phase 4 — OAuth and social:**
`/sign-in/social`, `/callback`, social provider flows.

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

Match the TS error behavior exactly. If the TS server returns
`{ "code": "USER_NOT_FOUND" }` with status 404, the Rust server must
do the same. Do not invent error codes or change status codes.

### Cookie Handling

Cookie behavior is a core part of the auth contract. The session token
cookie name, attributes, and lifecycle must match the TS implementation.
Read `packages/better-auth/src/cookies/` in the TS source carefully.

### Documentation

Doc comments on every public item. `cargo doc` should produce useful,
navigable documentation. When behavior or a public API changes, update
related comments and docs in the same change.

### Testing

**100% function coverage is required.** Every public and internal
function must be exercised by at least one test. Add tests for new
behavior and regressions. Only test code that has meaningful logic
(branching, transformations, error handling). Do not test code that
can only break if the language, runtime, or a dependency breaks.

### Git

Use conventional commits (`feat:`, `fix:`, `refactor:`, `test:`,
`docs:`, `chore:`). Commit frequently and autonomously instead of
batching large changes. Each commit must pass `cargo fmt --check`,
`cargo clippy`, and `cargo test`.

Create a branch (`<type>/<description>`) for substantial or risky
changes. Direct commits to `main` are acceptable for low-risk work.

### Refactoring

If an abstraction is wrong, refactor or rewrite it instead of layering
fixes on top. Large-scale rewrites and breaking changes are encouraged
when they are the right fix. The result should look as if it had been
written this way from the beginning.

### Lint Policy

The workspace has a strict Clippy and rustc lint configuration. Follow
it. Do not add `#[allow(...)]` or `#[expect(...)]` attributes to silence
lints without a genuine justification in the `reason` field. If a lint
fires, fix the code — do not suppress the lint to make progress faster.

### Performance

Hot paths must have benchmarks. Any performance regression must be
explained to the human before committing.

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
