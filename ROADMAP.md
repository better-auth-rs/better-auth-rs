# Alignment Roadmap

This project targets strict 1:1 behavioral alignment with the
[TypeScript better-auth](https://github.com/better-auth/better-auth)
implementation (`better-auth@1.7.6`). Work is organized into
self-contained phases, each covering a group of related endpoints.

This roadmap tracks the pinned upstream TypeScript surface plus exposed
Rust plugin routes we intend to keep. Public routes not present in
upstream TS should be removed.

The supported completion target includes phases 0–13 and the additional plugin routes listed below. Organization teams and dynamic roles remain follow-up work. Route coverage describes the configured HTTP surface; it does not establish support for every upstream plugin option or server-only API.

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

**Additional plugin routes:**

| Plugin | HTTP routes |
| --- | --- |
| Anonymous | `/sign-in/anonymous`, `/delete-anonymous-user` |
| Email OTP | `/email-otp/send-verification-otp`, `/email-otp/check-verification-otp`, `/email-otp/verify-email`, `/sign-in/email-otp`, `/email-otp/request-password-reset`, `/forget-password/email-otp`, `/email-otp/reset-password`, `/email-otp/request-email-change`, `/email-otp/change-email` |
| Magic Link | `/sign-in/magic-link`, `/magic-link/verify` |
| Multi Session | `/multi-session/list-device-sessions`, `/multi-session/set-active`, `/multi-session/revoke` |
| OAuth Proxy | `/callback/{provider}/oauth-proxy`, `/oauth-proxy-callback` |
| One Tap | `/one-tap/callback` |
| One Time Token | `/one-time-token/generate`, `/one-time-token/verify` |
| Phone Number | `/phone-number/send-otp`, `/phone-number/verify`, `/sign-in/phone-number`, `/phone-number/request-password-reset`, `/phone-number/reset-password` |
| SIWE | `/siwe/nonce`, `/siwe/get-nonce`, `/siwe/verify` |

These plugins use separate configuration profiles in the dual-runtime suite. Each profile verifies successful authentication and relevant failure paths. Mail and SMS delivery and SIWE verification require application callbacks, as in upstream. See the plugin documentation for Rust configuration and supported options.

HTTP route coverage does not close these behavior gaps:

- [JWT](docs/content/docs/plugins/jwt.mdx) does not implement remote JWKS, custom signing and payload callbacks, additional algorithms, or JWT session cookie caches.
- [Email OTP](docs/content/docs/plugins/email-otp.mdx) does not support application-defined user `additionalFields` schemas and transforms.
- Disabling [Anonymous](docs/content/docs/plugins/anonymous.mdx) or [Phone Number](docs/content/docs/plugins/phone-number.mdx) does not remove their previously stored fields from user output.
- [OAuth Proxy](docs/content/docs/plugins/oauth-proxy.mdx) requires application configuration for hosting URLs instead of vendor environment discovery.

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
