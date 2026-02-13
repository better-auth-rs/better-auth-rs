# Sea-ORM Migration

Demonstrates how to use better-auth alongside Sea-ORM in the same application, with schema migrations managed by `sea-orm-migration` (Rust code, not raw SQL).

## Key Concepts

- Sea-ORM `DatabaseConnection` and better-auth `SqlxAdapter` sharing the same PostgreSQL connection pool
- Entity models derive both `DeriveEntityModel` (Sea-ORM) and `Auth*` (better-auth)
- `#[auth(from_row)]` generates `sqlx::FromRow` implementations automatically from Sea-ORM models
- Schema migrations written in Rust via `sea-orm-migration` with `MigratorTrait`

## Setup

```bash
createdb better_auth_example
export DATABASE_URL="postgresql://user:pass@localhost:5432/better_auth_example"
cargo run --manifest-path examples/sea-orm-migration/Cargo.toml
```

Migrations are applied automatically on startup via `Migrator::up()`.

## Project Structure

```
sea-orm-migration/
├── Cargo.toml
└── src/
    ├── main.rs              # Axum server with /api/me and /api/users-by-plan
    ├── auth_entities.rs     # Type aliases re-exporting Sea-ORM models for better-auth
    ├── entities/            # Sea-ORM entity models (DeriveEntityModel + Auth*)
    │   ├── mod.rs
    │   ├── user.rs
    │   ├── session.rs
    │   ├── account.rs
    │   ├── organization.rs
    │   ├── member.rs
    │   ├── invitation.rs
    │   └── verification.rs
    └── migration/           # Rust-based schema migrations
        ├── mod.rs           # Migrator implementing MigratorTrait
        └── m20240101_000001_init.rs  # Initial schema (7 tables + indexes)
```
