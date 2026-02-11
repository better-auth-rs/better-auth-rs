# Examples

## Single-file examples

These live in the workspace and are run via `cargo run --example`.

| Example | Command | Description |
|---------|---------|-------------|
| `basic_usage` | `cargo run --example basic_usage` | In-memory adapter with all plugins. No database required. |
| `axum_server` | `cargo run --example axum_server --features axum` | Full Axum web server with auth middleware, CORS, and session validation. |
| `postgres_usage` | `cargo run --example postgres_usage --features sqlx-postgres` | PostgreSQL via `SqlxAdapter`. Requires `DATABASE_URL`. |
| `custom_entities` | `cargo run --example custom_entities --features derive` | Custom entity structs with `Auth*`/`Memory*` derive macros and extra fields. |

## Standalone projects

These are separate Cargo projects (excluded from the workspace) under `examples/`. Run with `cargo run -p <name>`.

### `sqlx-custom-entities`

Custom entity types with PostgreSQL via raw SQLx. Each struct has extra application-specific columns (billing plan, Stripe ID, etc.) with manual `FromRow` implementations.

```bash
createdb better_auth_example
export DATABASE_URL="postgresql://user:pass@localhost:5432/better_auth_example"
psql "$DATABASE_URL" -f examples/sqlx-custom-entities/migrations/001_init.sql
cargo run -p sqlx-custom-entities
```

### `sea-orm-migration`

Sea-ORM + better-auth sharing the same PostgreSQL connection pool. Schema migrations are written in Rust using `sea-orm-migration` instead of raw SQL. Entity models derive both `DeriveEntityModel` (Sea-ORM) and `Auth*` (better-auth).

```bash
createdb better_auth_example
export DATABASE_URL="postgresql://user:pass@localhost:5432/better_auth_example"
cargo run -p sea-orm-migration-example
```
