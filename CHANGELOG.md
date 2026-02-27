# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
## [0.8.0](https://github.com/better-auth-rs/better-auth-rs/compare/v0.7.0...v0.8.0) - 2026-02-27

### Bug Fixes

- mermaid theme re-render and openapi script error handling ([#40](https://github.com/better-auth-rs/better-auth-rs/pull/40))

- enforce disabled paths before hooks and sanitize virtual session input ([#43](https://github.com/better-auth-rs/better-auth-rs/pull/43))


### CI

- auto-delete release-plz branches on PR close


### Documentation

- add better-auth v1.4.19 compatibility badge to README and release notes ([#31](https://github.com/better-auth-rs/better-auth-rs/pull/31))

- add Phase 1-2 documentation with Mermaid diagrams and OpenAPI integration ([#28](https://github.com/better-auth-rs/better-auth-rs/pull/28))


### Features

- enhance EmailPassword and PasswordManagement plugins ([#35](https://github.com/better-auth-rs/better-auth-rs/pull/35))

- add core config options (app_name, base_path, trusted_origins, disabled_paths) ([#33](https://github.com/better-auth-rs/better-auth-rs/pull/33))

- database hooks for account/verification + advanced config ([#37](https://github.com/better-auth-rs/better-auth-rs/pull/37))

- add Account and OAuth advanced options ([#32](https://github.com/better-auth-rs/better-auth-rs/pull/32))

- enhance config + refactor: consolidate utils into core/src/utils ([#30](https://github.com/better-auth-rs/better-auth-rs/pull/30))

- add UserManagementPlugin + refactor DRY violations across plugins ([#34](https://github.com/better-auth-rs/better-auth-rs/pull/34))

- implement full API Key plugin with verify, rate limiting, and session emulation ([#38](https://github.com/better-auth-rs/better-auth-rs/pull/38))

- add cookie_cache config, is_session_fresh(), and adapter updated_at fix ([#29](https://github.com/better-auth-rs/better-auth-rs/pull/29))


### Refactoring

- use better-auth built-in migrations instead of manual table creation ([#41](https://github.com/better-auth-rs/better-auth-rs/pull/41))

- eliminate DRY violations across test files ([#42](https://github.com/better-auth-rs/better-auth-rs/pull/42))


### Style

- cargo fmt


### Tests

- Improve test framework: unified harness, CI coverage, schema validation fixes ([#25](https://github.com/better-auth-rs/better-auth-rs/pull/25))

## [0.7.0](https://github.com/better-auth-rs/better-auth-rs/compare/v0.6.2...v0.7.0) - 2026-02-25

### Bug Fixes

- remove duplicate error handling and fix README edition (Copilot review) ([#24](https://github.com/better-auth-rs/better-auth-rs/pull/24))

- replace hardcoded SQL column names with Auth*Meta trait methods in SqlxAdapter ([#23](https://github.com/better-auth-rs/better-auth-rs/pull/23))


### Features

- implement Admin plugin with 13 endpoints ([#16](https://github.com/better-auth-rs/better-auth-rs/pull/16))

- add spec-driven compatibility testing framework and fix CI ([#17](https://github.com/better-auth-rs/better-auth-rs/pull/17))

- expand compat coverage with Organization/Passkey tests and fix /ok endpoint ([#19](https://github.com/better-auth-rs/better-auth-rs/pull/19))

- implement AdminPlugin Phase 1 with 6 admin endpoints ([#20](https://github.com/better-auth-rs/better-auth-rs/pull/20))

- add fullstack integration example (better-auth frontend + better-auth-rs backend) ([#21](https://github.com/better-auth-rs/better-auth-rs/pull/21))


### phase0

- unify routes, add capabilities, hooks, and tests


### phase1

- jwt validation and email verification flow

- oauth provider config and verification responses

- oauth token exchange and userinfo

## [0.6.2](https://github.com/better-auth-rs/better-auth-rs/compare/v0.6.1...v0.6.2) - 2026-02-13

### Bug Fixes

- transparent logo, version refs, example response parsing, and account update mappings


### Chores

- set release title format to Better Auth Rust v{{version}}


### Documentation

- rebrand to Better Auth in Rust, add orange theme, and misc fixes


### Features

- add Axum session extractors and update docs

- add OpenAPI sync and plugin-level alignment reporting tools


### Tests

- add comprehensive passkey endpoint test coverage

## [0.6.1](https://github.com/better-auth-rs/better-auth-rs/compare/v0.6.0...v0.6.1) - 2026-02-12

### Bug Fixes

- clippy issues affecting CI

## [0.6.0](https://github.com/better-auth-rs/better-auth-rs/compare/v0.5.0...v0.6.0) - 2026-02-12

### Features

- add API Key management plugin with full CRUD endpoints

## [0.5.0](https://github.com/better-auth-rs/better-auth-rs/compare/v0.4.0...v0.5.0) - 2026-02-12

### Bug Fixes

- align response shapes with original better-auth OpenAPI spec


### Chores

- release v0.4.0 ([#8](https://github.com/better-auth-rs/better-auth-rs/pull/8))


### Features

- add OAuth social login and two-factor authentication


## [0.4.0](https://github.com/better-auth-rs/better-auth-rs/compare/v0.3.0...v0.4.0) - 2026-02-11

### Features

- add `#[auth(from_row)]` derive macro for automatic sqlx::FromRow generation from Sea-ORM models
- add Sea-ORM integration example with custom entities and shared connection pool

### Refactoring

- split DatabaseAdapter into focused sub-traits (UserOps, SessionOps, AccountOps, etc.)
- split large files into modules and remove separator comments
- convert sea-orm example to use sea-orm-migration instead of raw SQL

### Documentation

- add comprehensive README.md to examples/ directory
- add detailed READMEs to sqlx-custom-entities and sea-orm-migration examples
- update main README with v0.4.0 version and new examples

## [0.3.0](https://github.com/better-auth-rs/better-auth-rs/compare/v0.2.0...v0.3.0) - 2026-02-10

### Documentation

- update database docs for generic adapters and custom entity types


### Features

- add Memory* derive macros and generic MemoryDatabaseAdapter

- make SqlxAdapter generic over entity types


### Refactoring

- remove unused crates and rename workspace directories

## [0.2.0](https://github.com/better-auth-rs/better-auth-rs/compare/v0.0.1-alpha.2...v0.2.0) - 2026-02-10

### Bug Fixes

- use workspace dependencies for publishing and add missing metadata

- resolve CI failures from formatting and clippy warnings


### CI

- add GitHub Actions workflow and fix all clippy/fmt warnings

- add release-plz workflow and changelog config

- use GitHub App token and unified versioning for release-plz


### Chores

- cleanup directory


### Documentation

- update examples with new auth features and endpoints

- add Fumadocs documentation site with 18 pages

- update README and configure release-plz git identity


### Features

- add user/entity/session

- restructure into workspace with middleware, validation, hooks, and OpenAPI

- add email provider abstraction and wire into verification plugin

- add cookie auth, set-password, change-email, and user management endpoints

- add Organization plugin with RBAC, member management, and invitations

- generify entity types with associated types and derive macros


### Refactoring

- unify database migrations to sea-orm-migration and update examples


### license

- switch to MIT+Apache dual license


### Added

- **Organization Plugin** - Full multi-tenant organization support with RBAC
  - Organization CRUD operations (create, update, delete, list)
  - Member management (invite, accept/reject, remove, update role)
  - Invitation system with expiration and status tracking
  - Role-Based Access Control (RBAC) with configurable permissions
  - Default roles: `owner`, `admin`, `member`
  - Active organization support in sessions
  - 19 new API endpoints under `/organization/*`

- **Database Schema** - New tables for organization support
  - `organization` table with name, slug, logo, metadata
  - `member` table linking users to organizations with roles
  - `invitation` table for pending invitations with status and expiration
  - Plain SQL migration files in `migrations/`

- **DatabaseAdapter Extensions**
  - 17 new methods for organization, member, and invitation operations
  - Full implementation for `MemoryDatabaseAdapter` and `SqlxAdapter`
  - Session active organization support

### Changed

- Session model now includes `active_organization_id` field
