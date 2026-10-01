# Examples

## Single-file examples

These live in the workspace and are run via `cargo run --example`.

| Example | Command | Description |
|---------|---------|-------------|
| `axum_server` | `cargo run --example axum_server --features axum` | Full Axum server using app-owned auth entities and an explicit `AppAuthSchema`. |
| `postgres_usage` | `cargo run --example postgres_usage` | PostgreSQL example for an existing app-owned schema with numeric user IDs and seeded legacy users. Requires `DATABASE_URL`. |

The default password hasher uses upstream-compatible scrypt. `postgres_usage` explicitly configures `Argon2PasswordHasher` to authenticate its seeded legacy Argon2 credentials. The selected hasher also handles new passwords in that example; it does not migrate hashes or fall back between formats.

## Standalone projects

These are separate Cargo projects (excluded from the workspace) under `examples/`. Run them with `cargo run --manifest-path <path-to-Cargo.toml>`.

### `fullstack`

Full-stack integration example using the [better-auth](https://www.better-auth.com/) **frontend SDK** (Next.js / React) with a **better-auth-rs** (Rust / Axum) backend. Demonstrates email/password sign-up, sign-in, cookie-based sessions, and protected routes.

```bash
# Terminal 1 — start the Rust backend (port 3001)
cargo run --manifest-path examples/fullstack/backend/Cargo.toml

# Terminal 2 — start the Next.js frontend (port 3000)
cd examples/fullstack/frontend
bun install
bun run dev
```

See [`examples/fullstack/README.md`](fullstack/README.md) for full details.
