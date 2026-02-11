# SQLx Custom Entities

A complete Axum web server demonstrating custom entity types with PostgreSQL via raw SQLx.

Each entity struct has extra application-specific columns (billing plan, Stripe ID, etc.) that are stored in PostgreSQL and automatically populated via `SELECT * ... RETURNING *`.

## Key Concepts

- Custom structs with `Auth*` derive macros for better-auth trait implementations
- Manual `sqlx::FromRow` implementations for fields that need special deserialization (e.g. `JSONB`, `InvitationStatus`)
- `SqlxAdapter` parameterized with all custom entity types

## Setup

```bash
createdb better_auth_example
export DATABASE_URL="postgresql://user:pass@localhost:5432/better_auth_example"
psql "$DATABASE_URL" -f examples/sqlx-custom-entities/migrations/001_init.sql
cargo run -p sqlx-custom-entities
```

## Project Structure

```
sqlx-custom-entities/
├── Cargo.toml
├── migrations/
│   └── 001_init.sql        # Raw SQL schema with custom columns
└── src/
    ├── main.rs              # Axum server with /api/me endpoint
    └── entities.rs          # Custom entity structs + FromRow + Auth* derives
```
