# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
## [1.0.0-alpha.2](https://github.com/better-auth-rs/better-auth-rs/compare/v0.10.0...v1.0.0-alpha.2) - 2026-08-15

### Bug Fixes

- resolve AuthEntity crate paths for examples and integration tests

- delete_expired_api_keys as single DB query, fix schema default

- re-derive request_count from locked row inside transaction

- check window expiry inside rate-limit transaction

- remove verify and delete-all-expired HTTP routes

- reject expiresIn null when disable_custom_expires_time is set

- remove clippy indexing warning

- harden auth cleanup flow

- use try_seconds for impersonation session duration

- address review follow-ups

- address review feedback

- prevent concurrent redemption

- make device decisions atomic

- atomic rate-limit check, deterministic list ordering

- propagate list-users DB errors, fix MemoryStore unban clearing

- stop discarding session-refresh errors

- update tests and examples for schema-generic APIs

- validate verify-email callbackURL and skip-serialize AccountView.password

- sanitize error page XSS and respect disable_origin_check in redirects

- align wire behavior with TS reference for phase 5

- start field, list ordering, server-only enforcement

- empty update check, nullable expiresIn on update

- correct phase 0-5 audit coverage

- tighten phase 6 audit follow-ups

- honor creator role in member guards

- replace rust,ignore code fences with rust for Shiki compat

- restore phase 6 parity

- move openapi route to private test path

- align phase 0-9 client contract

- align phase 0 compat surface

- normalize lookup and avoid double verify

- enforce invariants on writes

- narrow username follow-ups

- align error page test with actual TS template

- align docs and examples with compat surface

- generate openapi schema from rust runtime

- clear cookies with Max-Age=0 and no Expires

- bound request body reads

- break the publish-blocking dependency cycles


### Build

- include seaorm crates in release-plz


### CI

- run CI on the v1 branch

- build the compat server before the alignment checks


### Chores

- satisfy clippy and rustdoc on stable 1.97

- bump workspace to 0.10.0

- refresh workspace dependencies

- bump version to 1.0.0-alpha.1

- release v1.0.0-alpha.1 ([#76](https://github.com/better-auth-rs/better-auth-rs/pull/76))


### Documentation

- clarify compatibility contract

- update snippets for explicit schema

- add context for schema snippets

- update for CLI, optional plugin fields, and seaorm2 feature

- insert Phase 4 for device authorization grant

- update plugin docs and roadmap for phase 5

- align ts public route plan

- remove local path assumptions

- drop public organization add-member route

- rebalance later phase plan

- move passkey and admin earlier

- move two-factor ahead of jwt

- promote admin stateful flows to phase 10

- warn that v1 is in alpha


### Features

- require root feature path

- allow extra fields in AuthEntity derive

- align Rust auth surface with TS better-auth through Phase 3 (social OAuth) ([#54](https://github.com/better-auth-rs/better-auth-rs/pull/54))

- add wire response views

- add wire module files

- add feature-gated root integration

- add `better-auth-rs generate` command

- allow extra fields in AuthEntity derive

- add TLS backend feature flags for reqwest

- implement phase 4 device flow

- align phase 6 compat behavior

- implement stage 7 account followups

- align phase 8 contract

- add passkey fullstack flow

- align phase 9 contract

- implement /is-username-available endpoint

- align phase 10 stateful flows

- align phase 11 and 12 flows

- finish phase 12 alignment


### Refactoring

- make plugin fields optional in AuthEntity derive

- accept auth traits in core helpers

- use generic session helper path

- genericize send-email helpers

- load schema user from session

- relax session helper inputs

- use schema session in auth helper

- genericize verify-email session input

- use wire session views

- use wire response views

- use wire user views

- use wire auth views

- use wire user view

- use wire auth views

- use wire user views

- use wire session view

- repair fallout from dto export removal

- remove #[cfg(test)] hacks, extract rate limiting

- type account-info provider errors

- use wire callback views

- return schema models for account and verification

- split plugin types from common types

- consolidate plugin entity views into core wire module

- move all counter mutations into transactional store method

- adopt app-owned auth schema

- remove legacy bundled surface

- use schema models in runtime flow

- delete dead internal scaffolding

- make database hooks schema-aware

- hide legacy auth dto structs

- remove legacy auth dto internals

- support app-owned legacy schemas

- split seaorm integration crate

- migrate tests and harnesses

- finalize green split rollout

- remove transition aliases

- polish integration surface

- align password storage with TS account model

- demonstrate minimal core-only entity schema

- AST-based schema generation with shared field registry


### Tests

- prune low-value unit coverage

- add upstream markers to is-username-available tests

- validate axum example source

- update harness for schema-native auth


### wip

- drop legacy dto re-exports

## [1.0.0-alpha.1](https://github.com/better-auth-rs/better-auth-rs/compare/v0.10.0...v1.0.0-alpha.1) - 2026-08-15

### Bug Fixes

- resolve AuthEntity crate paths for examples and integration tests

- delete_expired_api_keys as single DB query, fix schema default

- re-derive request_count from locked row inside transaction

- check window expiry inside rate-limit transaction

- transparent logo, version refs, example response parsing, and account update mappings

- replace hardcoded SQL column names with Auth*Meta trait methods in SqlxAdapter ([#23](https://github.com/better-auth-rs/better-auth-rs/pull/23))

- resolve cargo fmt and clippy warnings

- remove verify and delete-all-expired HTTP routes

- reject expiresIn null when disable_custom_expires_time is set

- remove clippy indexing warning

- harden auth cleanup flow

- use try_seconds for impersonation session duration

- address review follow-ups

- address review feedback

- prevent concurrent redemption

- make device decisions atomic

- atomic rate-limit check, deterministic list ordering

- propagate list-users DB errors, fix MemoryStore unban clearing

- stop discarding session-refresh errors

- update tests and examples for schema-generic APIs

- validate verify-email callbackURL and skip-serialize AccountView.password

- sanitize error page XSS and respect disable_origin_check in redirects

- align wire behavior with TS reference for phase 5

- start field, list ordering, server-only enforcement

- empty update check, nullable expiresIn on update

- correct phase 0-5 audit coverage

- tighten phase 6 audit follow-ups

- honor creator role in member guards

- replace rust,ignore code fences with rust for Shiki compat

- restore phase 6 parity

- move openapi route to private test path

- align phase 0-9 client contract

- align phase 0 compat surface

- normalize lookup and avoid double verify

- enforce invariants on writes

- narrow username follow-ups

- align error page test with actual TS template

- align docs and examples with compat surface

- generate openapi schema from rust runtime

- clear cookies with Max-Age=0 and no Expires

- bound request body reads


### Build

- include seaorm crates in release-plz


### CI

- run CI on the v1 branch

- build the compat server before the alignment checks


### Chores

- satisfy clippy and rustdoc on stable 1.97

- bump workspace to 0.10.0

- refresh workspace dependencies

- bump version to 1.0.0-alpha.1


### Documentation

- clarify compatibility contract

- update snippets for explicit schema

- add context for schema snippets

- update for CLI, optional plugin fields, and seaorm2 feature

- insert Phase 4 for device authorization grant

- update plugin docs and roadmap for phase 5

- align ts public route plan

- remove local path assumptions

- drop public organization add-member route

- rebalance later phase plan

- move passkey and admin earlier

- move two-factor ahead of jwt

- promote admin stateful flows to phase 10

- warn that v1 is in alpha


### Features

- require root feature path

- allow extra fields in AuthEntity derive

- add #[auth(from_row)] derive macro and Sea-ORM example

- implement passkey plugin and harden verification flow

- add PluginConfig derive macro

- align Rust auth surface with TS better-auth through Phase 3 (social OAuth) ([#54](https://github.com/better-auth-rs/better-auth-rs/pull/54))

- add wire response views

- add wire module files

- add feature-gated root integration

- add `better-auth-rs generate` command

- allow extra fields in AuthEntity derive

- add TLS backend feature flags for reqwest

- implement phase 4 device flow

- align phase 6 compat behavior

- implement stage 7 account followups

- align phase 8 contract

- add passkey fullstack flow

- align phase 9 contract

- implement /is-username-available endpoint

- align phase 10 stateful flows

- align phase 11 and 12 flows

- finish phase 12 alignment


### Refactoring

- make plugin fields optional in AuthEntity derive

- remove unused crates and rename workspace directories

- split DatabaseAdapter into sub-traits and clean up architecture

- split large files into modules and

- accept auth traits in core helpers

- use generic session helper path

- genericize send-email helpers

- load schema user from session

- relax session helper inputs

- use schema session in auth helper

- genericize verify-email session input

- use wire session views

- use wire response views

- use wire user views

- use wire auth views

- use wire user view

- use wire auth views

- use wire user views

- use wire session view

- repair fallout from dto export removal

- remove #[cfg(test)] hacks, extract rate limiting

- type account-info provider errors

- use wire callback views

- return schema models for account and verification

- split plugin types from common types

- consolidate plugin entity views into core wire module

- move all counter mutations into transactional store method

- adopt app-owned auth schema

- remove legacy bundled surface

- use schema models in runtime flow

- delete dead internal scaffolding

- make database hooks schema-aware

- hide legacy auth dto structs

- remove legacy auth dto internals

- support app-owned legacy schemas

- split seaorm integration crate

- migrate tests and harnesses

- finalize green split rollout

- remove transition aliases

- polish integration surface

- align password storage with TS account model

- demonstrate minimal core-only entity schema

- AST-based schema generation with shared field registry


### Tests

- prune low-value unit coverage

- add upstream markers to is-username-available tests

- validate axum example source

- update harness for schema-native auth


### wip

- drop legacy dto re-exports

## [0.9.0](https://github.com/better-auth-rs/better-auth-rs/compare/v0.8.0...v0.9.0) - 2026-03-11

### Bug Fixes

- add missing AuthSession import for axum handler

- resolve cargo fmt and clippy warnings

- log 500 errors before sanitizing response message

- fix/csrf example and docs ([#48](https://github.com/better-auth-rs/better-auth-rs/pull/48))

- add missing semicolon in security.mdx code example

- align delete-user spec with unified status field

- match upstream spec field names for success vs status


### Build

- add axum feature flag, SessionManager Clone, and AuthError IntoResponse


### CI

- add workflow to auto-sync upstream OpenAPI schema


### Documentation

- streamline README to be guide-oriented

- bump version to 0.8 in README


### Features

- add PluginConfig derive macro

- add Pending2faToken axum extractor

- add impl_auth_plugin! macro for route deduplication


### Refactoring

- migrate to core-function pattern with native axum extractors

- migrate to core-function pattern with native axum extractors

- extract core functions and add axum handlers

- extract core functions and add axum handlers

- extract core functions and add axum handlers

- extract core functions and add axum handlers

- extract core functions and add axum handlers

- extract core functions and add axum handlers

- extract core functions and add axum handlers

- extract core functions and add axum handlers

- extract core functions and add axum handlers

- update cookie_utils calls for new signature

- extract core functions for session-based handlers

- extract callback core and rewrite axum handler

- extract core functions for pending-2fa handlers

- rewrite axum handlers with native extractors

- extract core functions from handler methods

- rewrite axum handlers with native extractors

- split into directory module

- split into directory module

- split into directory module

- split into directory module

- split into directory module

- unify request body parsing to validate_request_body

- apply impl_auth_plugin! to larger plugins

- unify success response to StatusResponse

- apply PluginConfig derive to simple plugins

- apply PluginConfig derive to plugins with skip fields

- decouple cookie_utils from AuthContext, add AuthState helpers and Pending2faToken extractor

- centralize SessionManager creation in AuthContext

- add AuthUser::password_hash() default method

- apply impl_auth_plugin! to simple plugins

- remove DeleteUserResponse, unify to StatusMessageResponse


### Style

- apply cargo fmt to all migrated plugins

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
