# SeaQuery source and local patch

This directory contains `sea-query` version `1.0.0-rc.31`, licensed under MIT OR Apache-2.0. Preserve `LICENSE-MIT` and `LICENSE-APACHE` when distributing this source.

- Archive: <https://static.crates.io/crates/sea-query/sea-query-1.0.0-rc.31.crate>
- Archive SHA-256: `58decdaaaf2a698170af2fa1b2e8f7b43a970e7768bf18aebaab113bada46354`
- Repository: <https://github.com/SeaQL/sea-query>
- Commit: `94d7e90cf1b770b34dfa8dbf8b353baebca22f81`
- Repository path: root

The archive SHA-256 matches the application's original registry lockfile entry. Every registry source file was checked against the archive before applying the patch. `Cargo.toml` is the published normalized manifest. `Cargo.toml.orig` and `.cargo_vcs_info.json` retain upstream source metadata; do not activate the workspace or relative dependency paths in `Cargo.toml.orig`.

The patch adds `Value::PostgresUnspecifiedText(Option<String>)` for PostgreSQL OID 0 text parameters. Existing AST traversal preserves each parameter occurrence through casts, predicates, repeated expressions, and query cloning. Null conversion, dummy values, equality, and hashing preserve the variant. PostgreSQL diagnostic rendering uses the existing string quoting. Other query builders, JSON model conversion, and array type inference reject this protocol value.

Modified source paths:

- `src/value.rs`
- `src/value/hashable_value.rs`
- `src/value/with_json.rs`
- `src/backend/query_builder.rs`
- `src/backend/postgres/query.rs`
- `src/backend/mysql/query.rs`
- `src/backend/sqlite/query.rs`
- `src/token.rs` (equivalent test-literal representation)
- `src/prepare.rs`
- `src/prepare/protocol_tests.rs` (added)

The package retains all source, tests, benchmarks, documentation assets, and license files. Packaging excludes `.cargo-ok`, `Cargo.lock`, `.github`, `build-tools`, `rust-toolchain.toml`, `rustfmt.toml`, and `.gitignore`. The application owns dependency resolution, CI, and the development toolchain. The tokenizer test at `src/token.rs` uses an escaped string literal instead of a multiline raw literal. The input bytes, including the meaningful space before the newline, are identical to the upstream input. Packaging makes no other formatting changes.

Remove this patch when an upstream release preserves a dedicated PostgreSQL unspecified-type text parameter through the AST and supports its diagnostic rendering. Before removal, verify the protocol tests with the upstream release and confirm that all application manifest roots resolve the same dependency family. The binder must preserve the parameter's protocol mode at execution.
