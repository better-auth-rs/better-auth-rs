# SeaQuery SQLx source and local patch

This directory contains `sea-query-sqlx` version `0.8.0-rc.14`, licensed under MIT OR Apache-2.0. Preserve `LICENSE-MIT` and `LICENSE-APACHE` when distributing this source.

- Archive: <https://static.crates.io/crates/sea-query-sqlx/sea-query-sqlx-0.8.0-rc.14.crate>
- Archive SHA-256: `e4377164b09a11bb692dec6966eb0e6908d63d768defef0be689b39e02cf8544`
- Repository: <https://github.com/SeaQL/sea-query>
- Commit: `cf2e79ad21ce2279d3cba9c6d155f2f0fb919c82`
- Repository path: `sea-query-sqlx`

The archive SHA-256 matches the application's original registry lockfile entry. Every registry source file was checked against the archive before applying the patch. `Cargo.toml` is the published normalized manifest. `Cargo.toml.orig` and `.cargo_vcs_info.json` retain upstream source metadata; do not activate the workspace or relative dependency paths in `Cargo.toml.orig`.

The published archive omits the repository's license files. Both license files were copied from the exact source commit:

- MIT: <https://raw.githubusercontent.com/SeaQL/sea-query/cf2e79ad21ce2279d3cba9c6d155f2f0fb919c82/LICENSE-MIT>
- Apache-2.0: <https://raw.githubusercontent.com/SeaQL/sea-query/cf2e79ad21ce2279d3cba9c6d155f2f0fb919c82/LICENSE-APACHE>

The patch adds `SqlxValues::try_into_pg_arguments`. This shared conversion propagates native encoding errors and binds `PostgresUnspecifiedText` with `PgArguments::add_text`. Array conversion validates the declared type and propagates element errors. Scalar and array unsigned overflow errors retain their original error types. The existing `IntoArguments` implementation delegates to the shared conversion and panics on failure; callers that require error propagation must pass the fallible result to SQLx 0.8.6's `sqlx::__query_with_result` re-export. The patch requires that pinned SQLx version. MySQL, SQLite, and Any reject the PostgreSQL carrier.

Modified source paths:

- `src/sqlx_postgres.rs`
- `src/sqlx_postgres/tests.rs` (added)
- `src/sqlx_mysql.rs`
- `src/sqlx_sqlite.rs`
- `src/sqlx_any.rs`

The package retains all source and added tests. Packaging excludes `.cargo-ok` and `Cargo.lock`. The application owns dependency resolution and CI. The patch does not add support for undeclared SeaQuery `with-jiff` or `postgres-range` integrations.

Remove this patch when an upstream release provides a shared fallible PostgreSQL binder with equivalent unspecified-type text support and native conversion behavior. Before removal, verify encoding failures, array conversion, mixed protocol modes, transactions, and parameter order against the upstream release. Confirm that all application manifest roots resolve the same patched or upstream dependency family.
