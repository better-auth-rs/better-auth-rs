# Session/User reference validation contract

The fixture captures Better Auth 1.7.6 on Memory and SQLite. Three declarations run with native joins enabled and disabled: the default Session reference, a replacement `userId` without a reference, and an optional second reference from `ownerRef` to User.

Each of the 12 cases contains six operations. Unjoined Session and User reads remain successful controls. Joined adapter reads and internal Session lookups use both an existing token and a missing token. Missing or ambiguous references must fail before any query or output callback, including when the token is absent. The fixture contains 72 operations.

The Rust contract uses the shared reference resolver before `get_session_snapshot` reads either model. The ordinary `get_session` and `get_user_by_id` controls do not require a relationship. Native and fallback Session reads retain their existing return types. This change does not claim support for every relationship that the resolver can describe.

The comparison checks complete returned fields and runtime values, complete JSON output, exact configuration error messages, and the complete query and output callback sequence. The internal observation uses the production `SessionManager::resolve` path. The adapter observation uses the production Store snapshot and fallback User read. The sampled fields are visible, and the fixed Session expiry does not require a refresh.

SQLite observations include every column in all four core tables. Every operation must preserve the full snapshot. Memory observations compare complete User, Session, and Account projections through an independent baseline Store. The public Memory Store does not expose Verification enumeration. The upstream empty Verification table remains in the fixture without a Rust raw-table comparison.

Object property order remains unpaired. Upstream Session objects start with `expiresAt`, followed by `token`, and put `id` after application fields. Rust Session views start with `id`, followed by `token` and `expiresAt`. Upstream User objects put `id` after the native fields, whereas Rust User views put `id` first. The Rust test does not reorder either observation. The original `keyOrder` observations remain in the fixture and participate in strict upstream replay. Null results have no property order and are compared on both sides.

The fixture retains each JavaScript error's name, message, enumerable keys, and enumerable properties. Rust maps the reference errors to `AuthError::Config` and compares the exact message. JavaScript error object properties and stack formatting are not Rust compatibility claims. The capture job preserves raw diagnostics separately.

Remaining work includes alternate and reverse Session/User references, relationship arrays, physical aliases, query-history effects, and batch Session lookups. These shapes need separate upstream samples before their behavior or public cardinality can be extended. Object property order and raw Memory Verification observations also remain open.

Run the `account-user-auth` focused CI stage for Rust pairing and strict upstream replay. The stage includes `session_user_join_reference_tests` and `session-user-join-reference.test.ts`. Generate the fixture with `session-user-join-reference-capture.mjs` in GitHub Actions. Do not hand-edit the captured JSON.

Capture CI `37673366103` ran source `cc96bf3`. The fixture SHA-256 is `abc46e5e15f7297fc565e43365f137482ec868cac7ebbf8c695722212e881c4f`. The capture script SHA-256 is `2f27c81209878ea200b5ecff83746ddb6171809250c2016af54b7c0e523d50f6`. The capture passed; the Rust pairing must pass the focused CI stage before this slice is accepted.
