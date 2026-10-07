# Account/User relation contracts

The immutable fixtures pin Better Auth 1.7.6. The capture modules under `compat-tests/reference-server/contracts/` retain the upstream observations. Run upstream replay, Rust tests, and Clippy in GitHub Actions.

## Selected relation reads

`account-user-selected-relations-1.7.6.json` contains 44 cases and 176 operations across Memory, SQLite, and both join modes. `account_user_selected_relations_reference_tests` pairs the 88 internal adapter operations. The other 88 observations describe the JavaScript adapter boundary and remain in the fixture.

The Rust contract compares the complete internal result, its JSON representation, output callbacks, query order, and unchanged observable storage. Account observations use `AccountView::internal_fields()` to retain the password. User JSON observations use the production `Serialize` implementation. Relation object and array shapes remain distinct. Nested record property order is not paired; the fixture retains `keyOrder`. The Memory adapter has no public exhaustive table snapshot.

## HTTP authentication boundaries

`account-user-auth-boundary-1.7.6.json` contains 16 requests: four scenarios, two backends, and two join modes. `account_user_auth_boundary_reference_tests` submits each request through the production Axum router with `oneshot`.

- An alternate Account reference selects User b. The Account retains canonical owner User a. Admission, Session issuance, the response, and the signed Cookie use the selected User.
- A reverse reference returns multiple Users. Memory admission and Session input retain an own Undefined User ID. The public response contains numeric User keys. SQLite rejects the missing Session owner after the Account token update commits.
- A unique Account reference produces one Account. Both social and email sign-in fail before admission, password work, writes, or Cookie issuance.

The contract compares complete paired HTTP status, authentication headers, Cookie attributes, JSON bodies, provider input, admission input and original request metadata, output callbacks, adapter queries, and database hooks. The callback sequence preserves failure positions. All create, update, and delete hooks are installed for User, Account, Session, and Verification; any unexpected hook fails the comparison. Axum framing headers are checked against the actual body length.

The SQLite setup enables foreign keys and creates the selected relation for each scenario. The Session owner always references User. The alternate relation binds Account accessToken to User. The reverse relation binds User image to Account. The unique relation binds Account userId to User with a unique constraint. Reverse scenarios seed Account before User. Other scenarios seed User before Account.

SQLite snapshots inspect every physical column and row in all four tables. Timestamp text is parsed and compared as UTC instants with millisecond precision. Driver-specific timestamp text encoding is not paired. The contract preserves SQLite boolean and null values.

Memory observations use a separate runtime without callbacks. The contract reads all listed Users, Accounts for those Users, Sessions for those Users, and every token seen at Session issuance. User observations use the production projection for the active schema. Account observations include the password. A Session projection exposes own Undefined for an absent owner; the Memory fixture's physical row omits that owner. The test compares that explicit projection boundary. These observations do not prove an exhaustive snapshot of private Memory tables or independently enumerate Verification records. The complete request query and hook sequence checks that these scenarios do not write User or Verification records.

Dynamic fields are replaced only after checks against actual observations. The contract checks token length and character set, agreement between hooks and storage, nonempty Session IDs, request time bounds, Session lifetime, and Account-before-Session time order. Cookie verification uses the production HMAC verifier and requires the persisted token. The fixture remains unchanged.

The following boundaries are retained in the upstream fixture but are not paired with Rust:

- JavaScript error names, messages, enumerable properties, property order, and `console.error` arguments. Rust checks the native error category, failure condition, API error callback count, and callback position. CI output retains Rust diagnostics.
- Fetch `statusText`. Axum exposes the numeric status without the captured Fetch reason phrase.
- JSON object property order and nested record enumeration order. The HTTP comparison checks complete parsed JSON values and exact empty failure bodies.
- The upstream global `fetch` trap. Rust installs custom provider verification and profile callbacks and checks their complete inputs. The test does not claim a process-wide network trap.
- The upstream Memory `checked.completeStorage` flag. The Rust public adapter cannot reproduce that raw-table observation.

The focused Rust target is `cargo test --features axum,seaorm2 --test account_user_auth_boundary_reference_tests`. The CI runner must invoke the target inside the project devenv.
