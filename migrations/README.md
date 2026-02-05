# Better Auth Database Migrations

This directory contains migration scripts for Better Auth PostgreSQL database.

## Quick Start

### 1. Install sqlx-cli

```bash
cargo install sqlx-cli --no-default-features --features postgres
```

### 2. Set Environment Variables

```bash
export DATABASE_URL="postgresql://username:password@localhost:5432/better_auth"
```

### 3. Create Database

```bash
sqlx database create
```

### 4. Run Migrations

```bash
sqlx migrate run
```

## Manual Migration Execution

If you don't use sqlx-cli, you can also execute SQL scripts manually:

```bash
psql $DATABASE_URL -f migrations/001_initial.sql
```

## Database Schema

### Users Table
- `id` - User unique identifier
- `email` - User email (unique)
- `name` - User display name
- `image` - User avatar URL
- `email_verified` - Email verification status
- `created_at` - Creation time
- `updated_at` - Update time (automatically maintained)
- `metadata` - Extended data in JSON format

### Sessions Table
- `id` - Session unique identifier
- `user_id` - Associated user ID
- `token` - Session token
- `expires_at` - Expiration time
- `created_at` - Creation time
- `ip_address` - Client IP address
- `user_agent` - Client user agent
- `active` - Whether session is active

### Accounts Table (OAuth)
- `id` - Account unique identifier
- `user_id` - Associated user ID
- `provider` - OAuth provider (e.g. google, github)
- `provider_account_id` - Provider's account ID
- `access_token` - Access token
- `refresh_token` - Refresh token
- `expires_at` - Token expiration time
- `token_type` - Token type
- `scope` - Authorization scope
- `created_at` - Creation time

### Organization Table (Multi-tenant)
- `id` - Organization unique identifier
- `name` - Organization display name
- `slug` - URL-friendly unique identifier
- `logo` - Organization logo URL
- `metadata` - Extended data in JSON format
- `created_at` - Creation time
- `updated_at` - Update time

### Member Table (Organization membership)
- `id` - Member unique identifier
- `organization_id` - Associated organization ID
- `user_id` - Associated user ID
- `role` - Member role (owner, admin, member, or custom)
- `created_at` - Creation time

### Invitation Table (Organization invitations)
- `id` - Invitation unique identifier
- `organization_id` - Associated organization ID
- `email` - Invitee email address
- `role` - Role to assign upon acceptance
- `status` - Invitation status (pending, accepted, rejected, canceled)
- `inviter_id` - User ID who sent the invitation
- `expires_at` - Invitation expiration time
- `created_at` - Creation time

## Sea-ORM Migrations

For programmatic migration management, use the `better-auth-migration` crate:

```rust
use better_auth_migration::{Migrator, MigratorTrait};
use sea_orm::Database;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = Database::connect("postgresql://user:pass@localhost/better_auth").await?;
    Migrator::up(&db, None).await?;
    Ok(())
}
```

Or use `sea-orm-cli`:

```bash
cargo install sea-orm-cli
DATABASE_URL="postgresql://user:pass@localhost/better_auth" \
  sea-orm-cli migrate up -d crates/better-auth-migration
```

## Index Optimization

The script includes indexes for common queries:
- User email queries
- Session token queries
- User session queries
- OAuth account queries
- Organization slug queries
- Member by organization queries
- Member by user queries
- Invitation by organization queries
- Invitation by email queries

## Maintenance Functions

### Clean Up Expired Sessions

```sql
SELECT cleanup_expired_sessions();
```

### View Active Sessions

```sql
SELECT * FROM active_sessions;
```

## Development Environment Setup

For development environment, you can use Docker to quickly start PostgreSQL:

```bash
docker run --name better-auth-postgres \
  -e POSTGRES_DB=better_auth \
  -e POSTGRES_USER=better_auth \
  -e POSTGRES_PASSWORD=password \
  -p 5432:5432 \
  -d postgres:15
```

Then set environment variables:

```bash
export DATABASE_URL="postgresql://better_auth:password@localhost:5432/better_auth"
``` 