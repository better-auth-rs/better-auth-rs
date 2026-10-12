# MySQL server-error command attribution

This package starts from published `sqlx-mysql` 0.8.6, revision `bab1b022bd56a64f9a08b46b36b97c5cff19d77e`. The package manifest, dependencies, and upstream licenses remain unchanged.

`MySqlDatabaseError::sql()` exposes the SQL associated with the dispatched command that returned the server error. Text commands retain the sent SQL. Prepared commands retain the SQL template. The driver does not interpolate binary parameters. Errors outside SQL commands have no SQL value. Existing SQLSTATE, error number, message, classification, source type, and diagnostic formatting remain unchanged.

The stream records SQL after the original packet encoder queues the command bytes. Each pending response owns its optional SQL through result reading, cancellation, drain, and queued transaction rollback. Ping commands use the same response queue with no SQL value. Response-free COM_STMT_CLOSE and COM_QUIT packets do not create response entries. Prepare metadata and result metadata retain their remaining packet counts. The driver removes completed response state before yielding a completed result. Partial frame lengths and accumulated protocol fragments remain in the same stream across cancellation. TLS and boxed-socket conversions transfer this state with the original socket.

The patch does not change connection acquisition, transaction ownership, prepared-statement caching, parameter encoding, SQL compilation, or the selected text/binary protocol. Transport and encoding errors propagate through their existing paths. The patch does not provide mysql2 SQL formatting or establish full MySQL compatibility.

The `connection::stream::error_transport_tests` module contains deterministic protocol regressions. The `connection::stream::error_transport_live_tests` module contains ignored tests for the real MySQL CI service. Run `scripts/test-mysql-driver-errors.sh` through the CI devenv shell. The script verifies that the patched package is the only resolved `sqlx-mysql` 0.8.6 and requires all 20 protocol tests and all 3 live tests to pass.
