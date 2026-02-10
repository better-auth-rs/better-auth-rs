# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
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
  - Sea-ORM migration support via `better-auth-migration` crate

- **DatabaseAdapter Extensions**
  - 17 new methods for organization, member, and invitation operations
  - Full implementation for `MemoryDatabaseAdapter` and `SqlxAdapter`
  - Session active organization support

### Changed

- `better-auth-entity` now exports Organization, Member, and Invitation entities
- Session model now includes `active_organization_id` field
