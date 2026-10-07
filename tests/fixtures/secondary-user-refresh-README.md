# Secondary User refresh contract

The fixture captures Better Auth 1.7.6 on Memory and SQLite. The Rust contract runs the same nine scenarios through the database hooks, transaction wrapper, and production secondary store.

The separate `secondary-user-refresh-values-1.7.6.json` fixture adds three scenarios on each backend without replacing the original eighteen observations: a numeric cached expiry, a non-array active-session index, and an index with a valid entry followed by an entry without an expiry. Both fixtures use the same Rust observer and state comparison. Numeric expiry remains numeric in cache writes, and the complete cached Session must remain unchanged.

The contract compares the complete event sequence, returned value, database observations, and ordered cache entries. Cache values remain complete JSON strings, including key order. The parallel case records state when the operation returns, then releases the pending sibling and waits for its cache write. The contract checks `updatedAt` and cache TTL against the operation window before normalization.

SQLite observations contain every column from all four core tables. The fixture enables database Session and Verification storage so both tables exist. Rust uses the existing minimal core schema. Memory observations use the public User, Account, and Session projections. The public Rust adapter does not expose all raw Memory tables; the upstream empty Verification table remains in the fixture but has no Rust raw-table comparison.

The upstream fixture retains each JavaScript error's name, message, enumerable own keys, enumerable own properties, and injected object identity. Rust observations retain exact `Debug` and `Display` output, including the `AuthError` variant and complete diagnostic. This also covers borrowed logger errors without requiring a `'static` downcast. Injected cache, after-hook, and rollback errors must retain their exact input message. Missing User and malformed cache envelope errors must produce the explicit Rust `Internal` diagnostic at the same event position. JavaScript native error names, engine diagnostic wording, enumerable properties, and object identity are not Rust compatibility claims. Stack formatting is excluded from both observations.

Native hooks have no request context. The comparison maps upstream `null` or `undefined` context to Rust `None`, after checking that each side reports an absent request. The Rust before-hook also checks the complete typed patch before projecting supplied fields.

The upstream adapter factory emits one initialization diagnostic before each scenario's first transaction. The comparison first checks the complete initial `debug` event, including the exact Memory or Kysely adapter message and empty arguments. The comparison then removes only that event. This adapter initialization diagnostic is outside the User refresh comparison; Rust does not claim to be the JavaScript Kysely adapter. All remaining logger events participate in the strict comparison.

Generate the base fixture with `compat-tests/reference-server/contracts/secondary-user-refresh-capture.mjs` in GitHub Actions. Generate the additional value fixture with `secondary-user-refresh-values-capture.mjs`. Run the corresponding `.test.ts` files for upstream capture verification and `nullable_user_update_tests` for Rust pairing. Do not hand-edit the captured JSON.

Capture CI 37660864247 ran source `b51a51d75495ae10dfb7990ad4359eed6c3ab4d3`. The 18-case fixture has SHA-256 `51ea4a1791bea03b6f8ec60e4829f8d2a24dec8c0ad78b326fc96463b6919989`. Source metadata, artifact checksum, and byte-identical replay were verified before import.

Capture CI 37661567851 ran source `bc1570e3f1ce3fb9d7f974c6d3f4793c24fb1eed` and strictly replayed the original 18-case fixture before capturing the six value scenarios. The value fixture has SHA-256 `c6c0c7b3b34b1720528939a44b7f986e8145f28e462b4695680ee1b90efda8c2`. Source metadata, artifact checksum, and byte-identical replay were verified before import.
