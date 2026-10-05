# Contributing

This project targets strict 1:1 wire-level compatibility with the
canonical TypeScript Better Auth implementation. The TypeScript runtime
is the spec.

The primary compatibility contract is behavior exercised by the official
`better-auth/client` SDK and the TypeScript reference server. Routes,
payloads, headers, cookies, redirects, status codes, and error behavior
must match upstream.

Rust does not need to mirror the TypeScript embedding interface. Public
Rust APIs should follow native Rust ecosystem conventions for the
integrations we support. Axum + SeaORM is the current Rust integration
surface, but it is not itself the compatibility contract.

## Source of Truth

When sources disagree, trust them in this order:

1. Runtime behavior of the TypeScript reference server in
   `compat-tests/reference-server/`
2. TypeScript source in a local checkout of `better-auth@1.7.6` when
   available
3. Generated upstream OpenAPI profiles from the pinned published package
4. Better Auth documentation

The pinned reference version is `better-auth@1.7.6`.

## Non-Negotiables

- No extra public route, wire behavior, or client-observable capability
  beyond upstream TS
- No missing upstream route or behavior
- No legacy Rust-only migration shims or compatibility paths
- Rust-native integration APIs are allowed when they preserve the same
  client-observable contract
- If TS looks buggy, match it anyway and document that choice in code
- If a test conflicts with verified upstream behavior, update the test and
  implementation to match upstream

## Before You Change Code

Install [devenv](https://devenv.sh/getting-started/). The committed
`devenv.lock` pins Rust, Bun, Node.js, pnpm, and native build dependencies.

Run tools through the development shell:

```bash
devenv shell -- bun install --cwd compat-tests/reference-server --frozen-lockfile
devenv shell -- bun install --cwd compat-tests/client-tests --frozen-lockfile
```

Inspect upstream behavior in the installed `better-auth@1.7.6` and
`@better-auth/api-key@1.7.6` packages or the matching upstream tag.

## Workflow

1. Read the relevant phase in [ROADMAP.md](ROADMAP.md)
2. Compare Rust behavior against the TS reference server
3. Implement the smallest self-contained fix that removes the diff
4. Add or update tests in the same change
5. Do not batch unrelated endpoint fixes into one commit

Use any downstream compatibility target only as a downstream signal, not
as the source of truth.

## Docs OpenAPI

The docs site consumes a committed schema artifact at `docs/better-auth.json`.
That file should reflect the Rust runtime, not an upstream TypeScript export.

When the documented v1 route surface changes, regenerate the docs OpenAPI
artifacts with:

```bash
devenv shell -- pnpm --dir docs install --frozen-lockfile
devenv shell -- cargo run --bin generate_docs_openapi --features seaorm2
devenv shell -- pnpm --dir docs exec biome format --write better-auth.json
devenv shell -- bun run --cwd docs scripts/generate-openapi.mts
```

## Testing Strategy

There are three layers:

1. Rust unit/integration tests and the generated public consumer: `cargo test --workspace --features axum,seaorm2,redis-cache` and `./scripts/consumer-check.sh`
2. Raw wire smoke tests:
   `cargo test --test wire_compat_smoke_tests -- --nocapture`
3. Dual-server client compatibility tests using the real
   `better-auth/client` SDK:
   `cargo test --test client_compat_tests phase0_client_compat -- --ignored --nocapture`

The client-compat layer is the hard gate and the primary compatibility
contract. For more detail, see
[compat-tests/README.md](compat-tests/README.md).

## Required Checks

During development, select the affected test targets or compatibility profiles. Reuse passing focused checks while the relevant source, fixtures, configuration, and dependencies remain unchanged. Use GitHub Actions for complete acceptance. Push a checkpoint commit to a `codex/` branch to start CI without opening a pull request. Require a successful CI run for the same commit before merging into `master`.

The CI job provides PostgreSQL and runs the existing live database tests through the consumer runner. MySQL acceptance remains separate work. To run the same complete check locally when needed, use:

```bash
devenv test
```

Local checks and CI use `scripts/check.sh`. The script installs locked compatibility dependencies, checks formatting and Clippy, runs workspace tests with Axum, SeaORM, and Redis features, checks the alternative Rustls configuration, builds Rustdoc, and tests a freshly generated schema in an independent consumer. The dual-server suite compares all supported phases against the pinned TypeScript runtime.

Choose the affected package, target, or profile for a focused check. Run the selected command through `devenv shell --`, for example:

```bash
devenv shell -- cargo fmt --all -- --check
devenv shell -- cargo clippy -p better-auth-api --locked -- -D warnings
devenv shell -- cargo test -p better-auth-api --locked plugins::oauth
devenv shell -- cargo test --locked --features axum --test axum_integration_tests
devenv shell -- ./scripts/consumer-check.sh --lib tests::ids
devenv shell -- env COMPAT_TEST_PROFILE=request-oauth-memory cargo test --locked --test client_compat_tests configuration_client_compat -- --ignored --nocapture
```

During development, select the affected consumer target with `./scripts/consumer-check.sh --lib <filter>` or `./scripts/consumer-check.sh --test <target>`. Argument-bearing runs check consumer formatting and run the selected Cargo tests. The unfiltered command also runs all-target Clippy, the cross-runtime contract, and configured live PostgreSQL tests. These focused checks do not replace successful CI acceptance before merging into `master`.

The consumer script generates fresh schemas on every run. Identical generated files retain stable include paths and modification times under the ignored consumer `target/generated-schemas` directory. This preserves Cargo build results when the generated source does not change.

Prefix Bun test paths with `./` or use absolute paths. Bun treats unprefixed arguments as substring filters and searches the working directory recursively. Explicit paths avoid scanning unrelated build output. For example, run `devenv shell -- bun test ./compat-tests/reference-server/contracts/social-line.test.ts` for the Social LINE contract.
