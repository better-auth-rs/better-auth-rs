# Alignment Roadmap

This project targets strict 1:1 behavioral alignment with the
[TypeScript better-auth](https://github.com/better-auth/better-auth)
implementation (`better-auth@1.4.19`). Work is organized into
self-contained phases, each covering a group of related endpoints.

This roadmap tracks the pinned upstream TypeScript surface plus exposed
Rust plugin routes we intend to keep. Public routes not present in
upstream TS should be removed.

For the v1 release, phases 0-12 are the supported completion target.
Later phases remain tracked here, but they are follow-up/community work
unless explicitly pulled back into core scope.

Phases are ordered so that each one only depends on capabilities from
earlier phases. A phase is complete when every endpoint in it has
Rust-side tests and dual-server (TS-vs-Rust) comparison coverage.

Test suites, scripts, and source comments reference these phase numbers
(e.g. `phase0`, `phase1`).

## Phases

**Phase 0 — Core auth flow:**
`/sign-up/email`, `/sign-in/email`, `/sign-in/username`,
`/is-username-available`,
`/get-session`, `/sign-out`,
`/ok`, `/error`

**Phase 1 — Session and password management:**
`/list-sessions`, `/revoke-session`, `/revoke-sessions`,
`/revoke-other-sessions`, `/refresh-token`, `/get-access-token`,
`/request-password-reset`, `/reset-password/:token`,
`/reset-password`, `/change-password`

**Phase 2 — User self-service and verification:**
`/update-user`, `/delete-user`, `/delete-user/callback`,
`/change-email`, `/send-verification-email`, `/verify-email`

**Phase 3 — Social-linked account surface:**
`/sign-in/social`, `/callback/:id`, `/link-social`, `/list-accounts`,
`/unlink-account`

**Phase 4 — Device authorization grant (RFC 8628):**
`/device/code`, `/device/token`, `/device`,
`/device/approve`, `/device/deny`

**Phase 5 — Machine auth and API-key CRUD:**
`/api-key/create`, `/api-key/get`, `/api-key/list`,
`/api-key/update`, `/api-key/delete`

**Phase 6 — Organization core:**
`/organization/create`, `/organization/check-slug`,
`/organization/update`, `/organization/delete`,
`/organization/get-full-organization`, `/organization/set-active`,
`/organization/list`, `/organization/list-members`,
`/organization/get-active-member`,
`/organization/get-active-member-role`,
`/organization/update-member-role`,
`/organization/remove-member`, `/organization/leave`,
`/organization/invite-member`,
`/organization/accept-invitation`,
`/organization/reject-invitation`,
`/organization/cancel-invitation`,
`/organization/get-invitation`,
`/organization/list-invitations`,
`/organization/list-user-invitations`,
`/organization/has-permission`

**Phase 7 — Account follow-ups:**
`/verify-password`, `/account-info`

**Phase 8 — Passkey surface:**
`/passkey/generate-register-options`,
`/passkey/generate-authenticate-options`,
`/passkey/verify-registration`,
`/passkey/verify-authentication`,
`/passkey/list-user-passkeys`,
`/passkey/delete-passkey`,
`/passkey/update-passkey`

**Phase 9 — Admin CRUD and permissions:**
`/admin/list-users`, `/admin/get-user`, `/admin/create-user`,
`/admin/update-user`, `/admin/remove-user`,
`/admin/set-user-password`, `/admin/set-role`,
`/admin/has-permission`

**Phase 10 — Admin stateful flows:**
`/admin/ban-user`, `/admin/unban-user`,
`/admin/impersonate-user`, `/admin/stop-impersonating`,
`/admin/list-user-sessions`, `/admin/revoke-user-session`,
`/admin/revoke-user-sessions`

**Phase 11 — Two-factor core:**
`/two-factor/enable`, `/two-factor/disable`,
`/two-factor/get-totp-uri`, `/two-factor/verify-totp`,
`/two-factor/send-otp`, `/two-factor/verify-otp`

**Phase 12 — Two-factor recovery:**
`/two-factor/generate-backup-codes`,
`/two-factor/verify-backup-code`,
plus server-only backup-code retrieval via
`TwoFactorPlugin::view_backup_codes(...)` (matching TS
`auth.api.viewBackupCodes`; no public `/two-factor/view-backup-codes`
route in the pinned compat surface)

**Phase 13 — JWT surface:**
When `jwt()` is enabled:
`/token`, `/jwks` (or configured `jwksPath`)

**Phase 14 — Organization teams:**
When `organization({ teams: { enabled: true } })` is enabled:
`/organization/create-team`, `/organization/remove-team`,
`/organization/update-team`, `/organization/list-teams`,
`/organization/set-active-team`, `/organization/list-user-teams`

**Phase 15 — Organization team membership:**
When `organization({ teams: { enabled: true } })` is enabled:
`/organization/list-team-members`,
`/organization/add-team-member`,
`/organization/remove-team-member`

**Phase 16 — Organization custom roles:**
When `organization({ dynamicAccessControl: { enabled: true } })` is enabled:
`/organization/create-role`, `/organization/delete-role`,
`/organization/list-roles`, `/organization/get-role`,
`/organization/update-role`
