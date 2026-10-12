# Explicit MySQL text commands

The patched MySQL driver supports `Statement::from_mysql_text(Vec<u16>)` when `sqlx-mysql` is enabled. Use this constructor only after the application has compiled and formatted the complete SQL command. The constructor retains logical UTF-16 and derives the UTF-8 command bytes once. `Statement::mysql_text_sql()` exposes the logical text for contract checks.

The private command records explicit protocol provenance. Ordinary `from_string`, `from_sql_and_values`, and query-builder statements retain the existing prepared protocol. An empty parameter vector does not select COM_QUERY. The common MySQL `sqlx_query` constructor forwards explicit text commands for pool, transaction, and stream execution. Parameter conversion for ordinary statements remains lazy and runs after acquisition.

The immutable command owns the SQL that is sent. The public `sql` and `values` fields remain compatibility views for explicit text commands. Mutating these views does not mutate the command or its error provenance. `Display` renders the command's actual UTF-8 text. Construct another statement to send different SQL.

The private field prevents external construction through `Statement { ... }` when MySQL support is enabled. Migrate struct literals to `Statement::from_string` or `Statement::from_sql_and_values`. The three internal literals use these constructors. No application query producer selects the new protocol automatically.

The patch preserves connection acquisition, transaction ownership, stream ownership, error conversions, and metric callbacks. The patch does not select a different compiler, reconstruct interpolated SQL, or add a new connection or transaction. The driver test module contains three ignored MySQL service tests for native errors, explicit protocol selection, pool and transaction streams, cancellation drain, atomic conditional updates, connection identity, and rollback. Run these tests in GitHub CI with `BETTER_AUTH_TEST_MYSQL_URL` and the existing MySQL runtime features.
