# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
## [1.0.0-alpha.4](https://github.com/better-auth-rs/better-auth-rs/compare/v1.0.0-alpha.3...v1.0.0-alpha.4) - 2026-10-20

### Bug Fixes

- merge identical schema field conversions

- consume the wallet insert statement builder

- remove unused JWK clock import

- delete locked MySQL rows by primary key

- resolve native value integration lints

- remove redundant connection trait import

- align Organization filter values and fixture references

- match upstream Microsoft photo URL encoding

- complete API and SQL value boundaries

- retain validated role selector strings

- remove redundant ID comparison borrow

- exclude invalid dates from scalar sets

- preserve native Serial user and session ownership

- preserve explicit User ID projection

- store Account and Verification Serial primary IDs

- retain mapped session owner updates

- include native User fields in cache ordering

- enforce session and plugin persistence invariants

- generate complete usable auth schemas

- repair async Redis feature integration

- align session and credential security with upstream

- align lookup and invitation lifecycle

- support RP-initiated logout

- close parity gaps and enforce upstream contracts

- preserve transport URLs for proxy origin resolution

- align field projections and cookie lifetimes

- preserve cookie errors and joined field order

- align live organization reads and fractional lifetimes

- align duration configuration and cookie field presence

- preserve fractional TOTP periods and URI values

- align explicit cookie expiration and cleanup

- preserve plugin duration precision and device intervals

- align organization references and lockout timing

- align empty aliases and device persistence behavior

- resolve empty model names to upstream defaults

- align Memory field representations

- align Memory JSON and user queries

- align nullable user queries and OpenAPI fields

- align User projection and declaration order

- align SQLite output and generated schemas

- preserve scalar fields and runtime model declarations

- align SQLite JSON fields and OpenAPI model ordering

- align SQLite verification schema and empty field mappings

- align SQLite user, account, JWK, and rate-limit schemas

- align native SQLite session and organization schemas

- align SQLite timestamps, teams, and invitations

- align provider contracts and move acceptance to CI

- update async-trait for current Clippy

- align OAuth options and pin the CI environment

- align PostgreSQL and MySQL User and Account columns

- support non-exhaustive database backends

- preserve native MySQL timestamp defaults

- align server Verification columns

- order endpoint keys before assigning IDs

- align server JWK columns

- align RateLimit metadata and server columns

- align server Member columns

- align server OrganizationRole text storage

- align server team and counter storage

- align fresh server session storage

- include privately attached verification options

- preserve session presence and catalog identity

- retain MySQL team member date precision

- align native WalletAddress catalogs and storage

- update backup codes by loaded record ID

- use native user email unique constraints

- read memory display fields at projection time

- return the active internal user schema on redemption

- resolve logical models before table aliases

- align mapped display field policies

- resolve empty Device scope aliases consistently

- align unknown reference errors and scan order

- honor API Key and derived physical column aliases

- validate selected join reference fields

- preserve schema history across operation boundaries

- preserve driver JSON and inferred postgres operands

- generate IDs in adapter field order

- assign serial ID at memory insertion

- complete runtime conversion boundaries

- migrate runtime value consumers

- retain native session option values

- serialize the complete TimeClip date range

- preserve native endpoint and session values

- pair native Memory predicates and transaction guards

- retain native values in hook contexts

- pair native Device query values across databases

- complete root JSON and test boundaries

- bound error layout and consumer conversions

- unify native number JSON projections

- collect test compilation failures through cargo build

- migrate plugin output observations to native values

- migrate typed models to native field contracts

- migrate lifecycle and compatibility value boundaries

- migrate Device and plugin native observations

- retain SQL contract observations with native values

- migrate user query and join native values

- retain SQL null and encoded JSON parameters

- preserve native JSON driver input and output behavior

- restore field omission and public SQL model conversions

- export native SQL conversion through the facade

- preserve native Serial IDs for sessions and auxiliary records

- preserve native wallet owner references

- dispatch focused stages through the check runner

- preserve native serial IDs for credential models

- align native serial boundaries and live session output

- preserve native serial team member owners

- retain ordered adapter ID policies across callbacks

- bind session IDs at their schema position

- preserve awaited session adapter lookup

- align session ID binding and adapter continuation

- preserve organization SQL output representation

- honor creation ID slots and forced session IDs

- apply defaults before creation hooks

- bind transformed fields before omission

- resolve initial defaults with input precedence

- align native creation hooks and secondary writes

- preserve dynamic display values through cache reads

- project Account IDs in Memory joins

- accept Enum display field declarations

- consume optional storage guard result

- retain sort bounds and independent Session timestamps

- preserve object conversion errors at comparison boundaries

- migrate runtime field and date observations

- inspect nested runtime request objects

- isolate list contracts and import JSON macro

- expose factory API and repair focused test setup

- execute schema-selected member user joins

- reconstruct native joined user fields before output

- generate native API Key table and column names

- execute selected Account and User relationships through sign-in

- preserve native API Key date precision

- expose relationship and session result types

- preserve native identities during Admin admission

- resolve cache signing keys before subject validation

- preserve upstream attribute serialization order

- preserve native User updates and callback errors

- align native schema catalog and nullable flags

- resolve focused schema and cookie lint failures

- preserve User updates after cache refresh failures

- preserve native cache values and User field order

- preserve array-owner verification delivery errors

- retain active User plugin fields in joins

- preserve unique field declarations

- preserve native pure-secondary Session fields and User lookups

- align fractional JWT expiration and verification errors

- separate JWT validation from business payload parsing

- align Session projection and API Key metadata creation

- align Cookie mutation and shared chunk ordering

- complete Session bounds and defer nullish name coercion

- align fractional OAuth token expiry and hook presence

- preserve numeric cookie name enumeration order

- preserve selected session user relationships

- match upstream TOTP NaN period defaults

- align OAuth proxy non-finite age limits

- compare Memory API Key names without eager coercion

- align Device reference sets and empty SQL predicates

- preserve Device reference query operands

- bound field projection future types

- validate Device membership before adapter conversion

- align TOTP counter wrapping and verification windows

- preserve omitted fields in Memory User joins

- align credential hashing deadlines and polling guards

- preserve stable Member ordering and independent Session timestamps

- preserve API Key signed-zero sort ties

- align Session schema projection and SQL date predicates

- remove unused Session import after module split

- compare stored Member JSON and align invitation date transforms

- align API Key usage date binding and precision


### CI

- capture new provider fixtures in GitHub Actions

- isolate independent provider captures

- preserve dependency build caches after failed checks

- expose focused stages and capture Google contracts

- capture Generic profile result contracts

- capture PostgreSQL and MySQL schemas

- capture Device request validation contracts

- select captured provider option contracts

- capture ordinary upstream Device grant flows

- capture upstream Device grant OpenAPI metadata

- capture issuer and schema contracts together

- validate the issuer and schema slices

- capture endpoint order and JWK columns

- validate endpoint order and JWK schemas

- capture Social refresh request context

- check refresh callback consumers

- capture RateLimit metadata and server columns

- capture verifier context and Member columns

- capture OrganizationRole text storage

- reuse focused build caches and skip unused database services

- collect independent workspace compilation failures

- record resources during consumer diagnosis

- separate Rust dependency caches by check stage

- accumulate Rust cache artifacts across focused runs

- preserve running acceptance jobs

- reuse stage caches across Cargo manifest changes

- focus Account User HTTP contract acceptance

- add focused OAuth duration checks with shared cache

- collect failures across independent acceptance stages

- batch selected configuration profiles

- keep batch concurrency names within GitHub limits


### Chores

- add reproducible devenv environment

- unify verification and document working setup

- configure tooling and repair frontend checks


### Documentation

- record RateLimit CI acceptance

- record passkey and backup-code acceptance

- separate open capabilities from acceptance gaps

- record non-JSON query fidelity requirements

- record terminal consumer runner failure

- specify manual column conversion boundaries

- record complete generated consumer acceptance

- refresh active alignment acceptance status

- distinguish accepted alignment from historical failures

- record focused compatibility acceptance checkpoint

- record Device and telemetry acceptance

- record credential timing acceptance

- record Memory numeric sorting acceptance

- record API Key date and Organization acceptance


### Features

- align machine credentials with better-auth 1.7.6

- add typed server operations

- align generic OAuth and OIDC with upstream

- implement remaining upstream HTTP routes

- integrate organization, user fields, JWT and proxy alignment

- expose resolved provider availability

- align lifecycle hooks and typed field schemas

- align typed built-in field policies

- align upstream storage, callbacks, and schemas

- align session, factor, and callback behavior

- align upstream security and callback behavior

- align upstream runtime and storage behavior

- align JWT callbacks and request runtime

- align error routing and lifecycle contracts

- align adapter fields and request validation

- align logging hooks and adapter tracing

- align endpoint inputs and adapter behavior

- align transaction effects and notification dispatch

- align native endpoint validation and credential hooks

- align adapter projections and initialization options

- await field policies and align initialization metadata

- align upstream field and provider execution

- align plugin field policies and OAuth profiles

- align provider flows and profile field semantics

- add Atlassian Reddit Salesforce and Kakao providers

- add Zoom and preserve model declarations

- add Twitter and VK and preserve verification fields

- add Cognito and WeChat provider flows

- apply scope field policies at adapter boundaries

- add Facebook Paybin and PayPal providers

- align native join and live row projections

- add transactional device code redemption

- align device fields and memory serial references

- align JWK and wallet field policies

- add provider options and profile result contracts

- validate configured request fields before dispatch

- add typed grant authorization and redemption policy

- align grant OpenAPI metadata

- align GitLab issuer endpoints

- document declared request schemas

- pass request context to refresh callbacks

- pass request context to custom token verifiers

- align fresh DeviceCode database schemas

- support native upstream credential storage

- align native storage and nullable enrollment behavior

- align additional fields and callback persistence

- support declared ownership equality with transaction guards

- support native scope ownership equality

- expose typed endpoint context to ID token verifiers

- support declared additional field policies

- align plugin fields and schema reference checks

- align ownership membership predicates

- align ownership comparison operators

- bind serial ownership references consistently

- preserve runtime field values before JSON conversion

- export shared runtime field values from facade

- support JSON plugin fields and fallible field factories

- align numeric API Key names and shared Passkey columns

- align Session and Device schema reference boundaries

- register custom models for schema reference resolution

- align telemetry Docker detection

- align Linux release and WSL telemetry

- align Linux CPU and memory telemetry

- generate and renew Sign in with Apple client secrets

- add typed Admin permission checks for application code


### Refactoring

- name the synchronous body callback type

- trim unused member join metadata

- preserve runtime values across adapters


### Style

- order Session imports


### Tests

- decode Apple callback form before direct dispatch

- verify native credentials after database reopen

- register TwoFactor schema in enrollment fixture

- keep TimeClip checks compatible with strict lints

- import native invitation expiration values

- compare factory failures at the same read boundary

- verify integer query limits on PostgreSQL

- run MySQL schema preflight in CI

- capture server team and counter storage

- capture server session storage

- capture DeviceCode database catalogs

- capture WalletAddress catalogs and storage

- capture TwoFactor and Passkey catalogs

- retain creation-order checks with nullable dates

- isolate upstream captures and fix provider inputs

- import verified provider and isolated schema fixtures

- capture nullable SQL storage behavior

- preserve legacy assertions and fresh session setup

- pair generated storage with upstream SQL observations

- capture additional field policy lifecycle

- capture lock callback and null guard boundaries

- capture ownership and transaction predicates

- parse fixed fixture dates explicitly

- capture native scope ownership predicates

- capture live display field projection

- capture ordinary additional field policies

- preserve captured additional field contracts

- retain rejection coverage for native credentials

- capture additional fields across guarded usage writes

- reject both credential identifier aliases

- preserve legacy boolean fixture type

- capture live API key fields and join references

- capture model aliases in schema joins

- capture plugin output conversion capabilities

- capture logical model precedence in joins

- capture mapped Passkey display fields

- preserve contract assertions under Clippy

- retain join assertions with fallible setup

- capture unknown joins and Device set predicates

- capture native reference scan order

- gate ownership sets and reference errors

- capture field mappings and device query operators

- correct primary field and portable date fixtures

- collect JSON field maps through iterators

- collect all backend failures in one run

- capture persistent join schema history

- isolate fixtures and preserve fallible assertions

- remove inactive lint expectations

- capture user ID generation callback order

- isolate API key name mapping helpers

- separate runtime ID policies from physical schema

- satisfy history contract lint checks

- capture non-JSON ownership across transactions

- retain complete upstream transaction value contracts

- capture transaction value aliases and merge equality

- import runtime configuration trait

- capture serial creation across nested callbacks

- retain nested serial creation observations

- retain native field values in fixtures

- migrate remaining public fixture inputs

- cover Serial ownership and join regression paths

- capture Serial primary IDs and native JSON drivers

- collect Serial regression failures in one CI run

- import verified Serial and JSON driver captures

- pair Serial creation with complete upstream observations

- align legacy assertions with native field contracts

- include native JSON in full database acceptance

- propagate fixture errors through focused checks

- capture remaining session and auxiliary Serial IDs

- add focused Serial primary ID acceptance

- check plugin fixtures without unchecked setup panics

- capture explicit adapter ID slot behavior

- pair complete adapter ID slot observations

- match the Session User projection boundary

- reject unstable upstream fixture captures

- preserve deterministic native capture values

- import replay-verified ID fixtures

- retain forced-ID contract assertions under Clippy

- capture ordered creation ID aliases

- fix ID contract imports and lint expectations

- retain full ID fixture and consistent user input

- keep session ID fixtures within timestamp range

- capture undefined reference ID aliases

- install hooks through the runtime adapter

- provide the required SQL owner name

- split generated schema compilation targets

- preserve numeric input and assert JSON output

- capture native JSON display fields across adapters

- record JSON display contracts and capture memory sorting

- capture schema-selected member user joins

- record schema-selected member user join evidence

- cover member join aliases and native limit boundaries

- import user store operations for factory regressions

- lint complete join regression coverage

- capture selected Account and User relations

- retain verified Account and User relation oracle

- capture authentication consumers of selected relations

- retain verified relation authentication boundary

- pair selected Account and User sign-in boundaries

- capture OAuth array-owner profile overrides

- fix native session contract observation types

- retain verified OAuth profile override observations

- retain expanded native API Key catalog observations

- capture User cache refresh failure boundaries

- preserve upstream transaction initialization diagnostics

- capture native User refresh cache values

- correct secondary store and JSON macro imports

- capture array-owner OAuth email verification boundaries

- attach verification policy to paired provider

- capture remaining field and secondary storage contracts

- initialize Two Factor hooks and accept JSON display policies

- retain captured contracts and sample email token durations

- keep focused auth and telemetry checks warning free

- gate paired display and secondary contracts in focused CI

- pair numeric name ordering and retain contract assertions

- capture Cookie mutation and schema reference boundaries

- document synchronous Cookie contract assertions

- fix Session Device and Cookie contract lint

- pair Email payload failures and wire focused contracts

- observe every OAuth database lifecycle hook

- preserve contracts with checked JSON lookups

- compare Device owner reads at the same projection layer

- preserve explicit null OAuth Session seed metadata

- bind OAuth update timestamps before normalization

- capture remaining cookie session and duration boundaries

- gate session and non-finite option alignment

- restore shared upstream schemas after captures

- document strict TOTP fixture indexing

- capture Device reference candidate sets on four backends

- clone Device candidate slices directly

- preserve real telemetry initialization observations

- capture raw Device reference value binding

- check Device fixture guard access

- capture default Device reference operands

- capture Device scalar membership rejection

- capture TOTP counter conversion boundaries

- distinguish Number and integer TOTP windows

- collect independent compatibility profile failures

- document deliberate harness aborts

- capture credential hashing and polling boundaries

- use established credential timing lint targets

- capture stable Member sort order

- capture API Key numeric sort ties

- capture API Key usage date boundaries

- remove unused async contract lint expectation


### merge

- integrate OIDC with proxy and identity routes

- integrate provider availability from master

## [1.0.0-alpha.3](https://github.com/better-auth-rs/better-auth-rs/compare/v1.0.0-alpha.2...v1.0.0-alpha.3) - 2026-09-26

### Bug Fixes

- upgrade jsonwebtoken past CVE-2026-25537 and drop proc-macro-error2 ([#109](https://github.com/better-auth-rs/better-auth-rs/pull/109))

- skip the semver check for the crates with exclusive TLS features ([#111](https://github.com/better-auth-rs/better-auth-rs/pull/111))


### CI

- drop debug info and stop triggering on the deleted v1 branch


### Chores

- leave the alpha.3 version bump to release-plz ([#110](https://github.com/better-auth-rs/better-auth-rs/pull/110))


### Documentation

- prepare the 1.0.0-alpha.3 release ([#108](https://github.com/better-auth-rs/better-auth-rs/pull/108))


### Features

- align with better-auth 1.6.29 ([#101](https://github.com/better-auth-rs/better-auth-rs/pull/101))


### Breaking changes

- **API keys are owned by a reference, not a user.** `apikey.user_id` is now
  `reference_id`, a `config_id` column is added, and the foreign key to
  `users` is gone: a reference may be an organization id. App-owned schemas
  must apply the equivalent change; `AuthApiKey::user_id` became
  `reference_id` plus `config_id`, and `ApiKeyStore::list_api_keys_by_user`
  became `list_api_keys_by_reference`. The bundled migrator upgrades
  existing installations in place; SQLite rebuilds the table because it
  cannot drop the constraint.
- **`GET /api-key/list` returns a paginated envelope** (`{ apiKeys, total,
  limit, offset }`) instead of a bare array, with `configId`, `limit`,
  `offset`, `sortBy` and `sortDirection` query parameters.
- **Error responses carry `code` only where upstream defines one.**
  `ErrorCodeMessageResponse::code` is `Option<String>`; ad-hoc messages
  omit the field, and codes such as `INVALID_CALLBACK_URL` now match
  upstream's constants rather than being derived from the message.
- **Implicit account linking requires a verified local email** by default
  (`account_linking.require_local_email_verified`); a callback that would
  have linked to an unverified local account now redirects with
  `account_not_linked`.
- `RolePermissions` (organization plugin) gained an `api_key` field, so
  struct literals must name it or use `..Default::default()`.

### Security

- Device authorization no longer approves or denies a code no signed-in
  session has claimed.
- `/organization/list-user-invitations` requires a verified email
  (`EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION`).

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
