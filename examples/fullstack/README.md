# Fullstack Example: better-auth + better-auth-rs

A complete integration example that demonstrates using the
[better-auth](https://www.better-auth.com/) **frontend SDK** (TypeScript/React)
with a **better-auth-rs** (Rust/Axum) backend.

## Architecture

```
┌──────────────────────────┐         ┌──────────────────────────┐
│  Frontend (Next.js)      │  HTTP   │  Backend (Axum)          │
│                          │ ──────► │                          │
│  better-auth/react       │         │  better-auth-rs          │
│  Port 3000               │         │  Port 3001               │
│                          │         │                          │
│  - Sign Up page          │         │  POST /api/auth/sign-up  │
│  - Passkey sign-in       │         │  POST /api/auth/sign-in  │
│  - Dashboard (protected) │         │  GET  /api/auth/get-session │
│  - Session management    │         │  GET  /api/auth/passkey/* │
└──────────────────────────┘         └──────────────────────────┘
```

## Features

- **Email/password sign-up & sign-in** — powered by `EmailPasswordPlugin`
- **Passkey registration & sign-in** — powered by `PasskeyPlugin` and `@better-auth/passkey`
- **Cookie-based sessions** — session token set via `Set-Cookie`, validated on
  every request by `SessionManagementPlugin`
- **React hooks** — `useSession()` from `better-auth/react` for reactive session
  state
- **Protected routes** — dashboard redirects to sign-in when unauthenticated
- **Passkey management UI** — register and remove passkeys from Settings

## Prerequisites

- **Rust** (latest stable, edition 2021)
- **Bun** >= 1.0

## Quick Start

### 1. Start the backend

```bash
cd backend
cargo run
```

The Axum server starts on **http://localhost:3001**. It uses a local SQLite
database file (`better-auth-fullstack.db`) by default, so no external database
server is needed.

### 2. Start the frontend

```bash
cd frontend
bun install
bun run dev
```

The Next.js dev server starts on **http://localhost:3000**.

### 3. Try it out

1. Open http://localhost:3000
2. Click **Create Account** and fill in the sign-up form
3. You are redirected to the **Dashboard** showing your session data
4. Open **Settings** and register a passkey
5. Click **Sign Out** and then **Sign In with Passkey**

## Configuration

### Backend

The backend configuration is in `backend/src/main.rs`. Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `base_url` | `http://localhost:3001` | Backend URL |
| `password_min_length` | `8` | Minimum password length |
| `trusted_origins` | `http://localhost:3000` | Frontend origin allowed by CSRF/origin checks |
| Auth route prefix | `/api/auth` | Matches better-auth's default `basePath` |

### Frontend

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `NEXT_PUBLIC_AUTH_URL` | `http://localhost:3001` | Backend URL |

The auth client is configured in `frontend/src/lib/auth-client.ts` with
`basePath: "/api/auth"` to match the backend route prefix.

## Project Structure

```
fullstack/
├── README.md
├── backend/
│   ├── Cargo.toml
│   └── src/
│       ├── auth_schema.rs   # App auth tables, including passkeys
│       └── main.rs          # Axum server with better-auth-rs
└── frontend/
    ├── bun.lock
    ├── package.json
    ├── next.config.mjs
    ├── tsconfig.json
    ├── .env                  # NEXT_PUBLIC_AUTH_URL
    ├── .env.example
    └── src/
        ├── lib/
        │   └── auth-client.ts   # better-auth + passkey client setup
        └── app/
            ├── layout.tsx
            ├── globals.css
            ├── page.tsx          # Home page
            ├── sign-up/
            │   └── page.tsx      # Sign-up form
            ├── sign-in/
            │   └── page.tsx      # Email/password + passkey sign-in
            ├── settings/
            │   └── page.tsx      # Profile, password, and passkey management
            └── dashboard/
                └── page.tsx      # Protected dashboard
```
