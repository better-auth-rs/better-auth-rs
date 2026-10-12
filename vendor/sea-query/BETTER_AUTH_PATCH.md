# Native adapter parameters

The local SeaQuery 1.0.0-rc.31 patch preserves the package version and dependency graph. Ordinary builders retain their syntax and typed parameter paths.

`Value::PostgresUnspecifiedText` carries PostgreSQL text with an unspecified OID through the dedicated binder. Other backend and serialization paths reject the carrier.

`Expr::ExternalParameter` owns a type-erased native payload. Clones share that payload; the node has no index into another query's parameters. Ordinary builders and value writers reject the node. The opt-in `KyselyMysqlQueryBuilder` and application collector retain the complete AST parameter order before native formatting. An unrecognized payload returns an application error before formatter callbacks run.

The MySQL compiler shares the existing backend implementation. A keyword hook changes compiler-owned spelling and preserves raw SQL, identifiers, custom functions, and operators. The application uses AST accessors to construct the upstream primary-relation wrapper and repeat ordering. The adapter keeps count queries, create and update readback, locked consumption, and atomic increments at their existing boundaries.

Downstream exhaustive matches must handle both enum variants. No ordinary application query must use the native node. These changes do not establish parity for every Kysely AST or JavaScript value form. Run the original backend suites and frozen compiler, formatter, and native-binding contracts through `scripts/test-mysql-text.sh` in GitHub CI.
