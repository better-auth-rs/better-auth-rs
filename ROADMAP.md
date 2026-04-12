# Alignment Roadmap

This project targets strict 1:1 behavioral alignment with the
[TypeScript better-auth](https://github.com/better-auth/better-auth)
implementation (`better-auth@1.4.19`). Work is organized into
self-contained phases, each covering a group of related endpoints.

Phases are ordered so that each one only depends on capabilities from
earlier phases. A phase is complete when every endpoint in it has
Rust-side tests and dual-server (TS-vs-Rust) comparison coverage.

Test suites, scripts, and source comments reference these phase numbers
(e.g. `phase0`, `phase1`).

## Phases

**Phase 0 — Core auth flow:**
`/sign-up/email`, `/sign-in/email`, `/get-session`, `/sign-out`,
`/ok`, `/error`

**Phase 1 — Session and password management:**
`/list-sessions`, `/revoke-session`, `/revoke-sessions`,
`/revoke-other-sessions`, `/refresh-token`, `/get-access-token`,
`/request-password-reset`, `/reset-password`, `/change-password`

**Phase 2 — User self-service and verification:**
`/update-user`, `/delete-user`, `/delete-user/callback`,
`/change-email`, `/send-verification-email`, `/verify-email`

**Phase 3 — Social-linked account surface:**
`/sign-in/social`, `/callback`, `/link-social`, `/list-accounts`,
`/unlink-account`

**Phase 4 — Machine auth and API-key CRUD:**
Bearer behavior, `/api-key/create`, `/api-key/list`, `/api-key/get`,
`/api-key/update`, `/api-key/delete`, `/api-key/verify`

**Phase 5 — Organization core:**
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

**Phase 6 — Admin core:**
`/admin/list-users`, `/admin/create-user`, `/admin/remove-user`,
`/admin/set-user-password`, `/admin/set-role`,
`/admin/has-permission`

**Phase 7 — Passkey surface:**
All `/passkey/*` endpoints.

**Phase 8 — Organization advanced:**
`/organization/create-team`, `/organization/remove-team`,
`/organization/update-team`, `/organization/list-teams`,
`/organization/set-active-team`, `/organization/list-user-teams`,
`/organization/list-team-members`,
`/organization/add-team-member`,
`/organization/remove-team-member`,
`/organization/create-role`, `/organization/delete-role`,
`/organization/list-roles`, `/organization/get-role`,
`/organization/update-role`

**Phase 9 — Admin extended support flows:**
`/admin/get-user`, `/admin/update-user`, `/admin/ban-user`,
`/admin/unban-user`, `/admin/impersonate-user`,
`/admin/stop-impersonating`, `/admin/list-user-sessions`,
`/admin/revoke-user-session`, `/admin/revoke-user-sessions`

**Phase 10 — Two-factor authentication:**
All `/two-factor/*` endpoints.

**Phase 11 — Cold account and token surfaces:**
`/verify-password`, `/update-session`, `/account-info`, `/token`
