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

These are separate Cargo projects (excluded from the workspace) under `examples/`. Run them with `cargo run --manifest-path <path-to-Cargo.toml>`.

### `sqlx-custom-entities`

Custom entity types with PostgreSQL via raw SQLx. Each struct has extra application-specific columns (billing plan, Stripe ID, etc.) with manual `FromRow` implementations.

```bash
createdb better_auth_example
export DATABASE_URL="postgresql://user:pass@localhost:5432/better_auth_example"
psql "$DATABASE_URL" -f examples/sqlx-custom-entities/migrations/001_init.sql
cargo run --manifest-path examples/sqlx-custom-entities/Cargo.toml
```

### `sea-orm-migration`

Sea-ORM + better-auth sharing the same PostgreSQL connection pool. Schema migrations are written in Rust using `sea-orm-migration` instead of raw SQL. Entity models derive both `DeriveEntityModel` (Sea-ORM) and `Auth*` (better-auth).

```bash
createdb better_auth_example
export DATABASE_URL="postgresql://user:pass@localhost:5432/better_auth_example"
cargo run --manifest-path examples/sea-orm-migration/Cargo.toml
```

### `fullstack`

Full-stack integration example using the [better-auth](https://www.better-auth.com/) **frontend SDK** (Next.js / React) with a **better-auth-rs** (Rust / Axum) backend. Demonstrates email/password sign-up, sign-in, cookie-based sessions, and protected routes.

```bash
# Terminal 1 — start the Rust backend (port 3001)
cargo run --manifest-path examples/fullstack/backend/Cargo.toml

# Terminal 2 — start the Next.js frontend (port 3000)
cd examples/fullstack/frontend
npm install
npm run dev
```

See [`examples/fullstack/README.md`](fullstack/README.md) for full details.
