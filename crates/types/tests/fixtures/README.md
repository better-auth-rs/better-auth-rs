`core_auth_responses.json` contains successful `/sign-up/email` and
authenticated `/get-session` responses, plus the unauthenticated
`/get-session` response, captured from two TypeScript runtimes:

- `better-auth@1.4.19`, installed by `compat-tests/client-tests`, with an
  in-memory SQLite database and email/password authentication enabled.
- The configured `compat-tests/reference-server/server.ts` runtime using
  `better-auth@1.6.29`, including its default plugins.

Each capture signs up `types-fixture@example.com` and passes the returned
session cookie to `/get-session`. Only IDs, session tokens, and the nonempty
user-agent value are replaced with fixed fixture values. Field names, dates,
null values, omitted fields, and the empty user-agent value are unchanged.

Regenerate the captures from the repository root with Bun installed:

```sh
(cd compat-tests/client-tests && bun install --frozen-lockfile)
(cd compat-tests/reference-server && bun install --frozen-lockfile)
bun crates/types/tests/fixtures/capture.ts
cargo test -p better-auth-types
cargo test -p better-auth-types --no-default-features
```

The script migrates a fresh in-memory database for 1.4.19 and starts and stops
its own reference-server process on port 3194. Set `TYPES_FIXTURE_PORT` to use
another free port. It reads the installed versions into the capture and only
writes the JSON after both runtimes succeed. Dates remain real capture times,
so recapturing changes them. An optional output path lets you inspect a new
capture before replacing the committed file:

```sh
bun crates/types/tests/fixtures/capture.ts /tmp/core_auth_responses.json
```

`response_views.json` contains hand-authored examples for the remaining shared
views. These exercise client deserialization, optional fields, invitation
status values, and sensitive-field serialization rules; they are not runtime
captures or evidence of upstream endpoint parity.
