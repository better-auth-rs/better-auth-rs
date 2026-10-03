# Generated schema consumer

Run from the repository root:

```sh
devenv shell -- ./scripts/consumer-check.sh
```

The script runs the public CLI with every supported schema plugin and separately with the Organization schema configuration in `organization-schema.json`. The script writes generated code to a temporary directory, then formats, lints, and tests this independent Cargo package. The package uses the public `better-auth` dependency and does not use the internal bundled schema.

The authentication test creates SQLite tables and exercises registration, login, a protected Axum route, API Key creation, and TOTP enrollment. The test verifies that subsequent password login requires a second factor. Database writes verify email and two-factor uniqueness, plus session foreign keys. Duplicate provider accounts remain storable, and account lookup rejects the ambiguous identity.

The Organization test selects six generated application models through `with_organization_schema`. The test verifies mapped table and column names, nullable metadata, typed scalar/date/enum/JSON/array fields, partial updates, member defaults, invitation and role fields, and deletion. Built-in overrides verify mapping precedence, runtime Serde aliases, added and removed single-column uniqueness, and unchanged primary keys. Direct database writes verify mapped foreign keys and team membership uniqueness. The CLI configuration defines storage; the application supplies `UserFieldConfig` runtime policies separately.

The dynamic schema test replaces built-in string and date columns with numeric, boolean, JSON, and string columns. The test verifies numeric slug lookup, SQL NULL, raw timestamp strings, and an omitted output field whose database value remains present.

The `sqlite-json-schema.json` consumer uses generated `SqlText` fields for ordinary non-reference JSON declarations. Its pinned SQLite comparison passes for a required adapter default, optional omission, explicit null, object/array input, encoded/invalid/whitespace text, integer `12`, fraction `12.5`, both Booleans, and partial updates. Complete callback events, returned display presence/value maps, and independent physical text/SQL NULL are compared across 11 create/read cases and three update/read cases. All 23 library consumers, consumer formatting, and consumer Clippy pass. The live PostgreSQL test is excluded from this focused run. The existing Organization and Device raw-model assertions now name the complete `SqlText::Text` values; their public semantic contracts and fixtures remain unchanged.

The field attributes schema tests mapped and external foreign keys, all five deletion actions, required fields, ordinary indexes, unique constraints, and the absence of an index for `sortable`. The SQLite consumer verifies fractional values in both `INTEGER` and `BIGINT` columns. Number, boolean, JSON, and array fields that reference `id` retain database binding behavior and return strings after one application output transform. The test includes negative zero and exponent-form numeric input to distinguish database text affinity from premature JavaScript string conversion.

The reference binding checks use SQLite and the pinned upstream Bun driver. The signed 52-bit integer binding rule applies only to SQLite. PostgreSQL parameter conversion follows node-postgres's documented string conversion; this consumer does not connect to PostgreSQL or MySQL. Run equivalent database-backed checks before claiming runtime parity for those drivers.

Application-owned user and session models also verify reference writes through different Serde and SQL aliases. The test covers defaults, explicit updates, session refresh callbacks, and one output transform per projection.

The generated `create_auth_tables` function initializes an empty database. Application-owned versioned migrations must handle existing databases and later plugin additions.

The plugin schema in `plugin-schema.json` renames all six plugin tables and every non-primary plugin column. The consumer binds `AppPluginSchema`, exercises HTTP authentication, API key quotas, TOTP, JWT keys, and verifies device claims, passkey credential updates, wallet chain lookup, and mapped database constraints. Last Login Method checks registration and subsequent login writes through a mapped nullable user column. Default plugin tables do not exist in this database.

The database rate-limit schema uses the explicit `--rate-limit-database` option and `rate-limit-schema.json`. The consumer verifies a mapped table, all mapped counter columns, unique keys, fractional stored counts, and atomic allowance decisions through the generated seventh `AppPluginSchema` model.
