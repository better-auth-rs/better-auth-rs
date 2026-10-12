# SeaORM PostgreSQL argument patch

This directory contains the published `sea-orm` 2.0.0-rc.37 source from commit `d2990b3b6e8fde8ae4b000866571fbc2afb5cf5c`. The crates.io archive SHA-256 is `4b846dc1c7fefbea372c03765ff08307d68894bbad8c73b66176dcd53a3ee131`. The original MIT and Apache licenses are included.

The shared PostgreSQL query constructor in `src/driver/sqlx_postgres.rs` uses `SqlxValues::try_into_pg_arguments` and `sqlx::__query_with_result`. SQLx 0.8.6 exposes the fallible constructor through this hidden re-export; the patch requires the pinned SQLx version. Encoding errors reach the existing executor without executing an incomplete parameter set. Pool, stream, and transaction callers retain their existing connections and ownership. No new pool, connection accessor, SQL parser, or statement rewrite is introduced.

All application dependency roots must select this package together with the vendored SeaQuery, SeaQuery SQLx binder, and SQLx PostgreSQL packages. Cargo patches do not propagate to downstream workspace roots. Remove the coordinated patches when upstream releases provide the same protocol and error boundaries and the strict driver contracts pass.


Packaging omits upstream development controls, agent guidance, contribution guidance, demo applications, and standalone issue reproducers: `Cargo.lock`, `.github/`, `build-tools/`, `rust-toolchain.toml`, `rustfmt.toml`, `.gitignore`, `CLAUDE.md`, `CONTRIBUTING.md`, `examples/`, and `issues/`. All Rust source, declared Cargo test targets, test assets, manifests, and licenses remain. The library and Cargo test targets do not load files from the omitted directories.
