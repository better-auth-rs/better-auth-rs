SELECT
    a.attname AS column_name,
    a.attnotnull AS not_null,
    a.atthasdef AS has_default,
    c.relname AS table_name,
    ns.nspname AS schema_name,
    pg_catalog.pg_get_serial_sequence(
        pg_catalog.quote_ident(ns.nspname) || '.' || pg_catalog.quote_ident(c.relname),
        a.attname
    ) IS NOT NULL AS auto_incrementing,
    pg_catalog.current_schemas(true)::text[] AS search_path
FROM pg_catalog.pg_attribute AS a
JOIN pg_catalog.pg_class AS c ON a.attrelid = c.oid
JOIN pg_catalog.pg_namespace AS ns ON c.relnamespace = ns.oid
WHERE c.relkind IN ('r', 'v', 'p', 'f')
    AND ns.nspname !~ '^pg_'
    AND ns.nspname NOT IN ('information_schema', 'crdb_internal')
    AND pg_catalog.has_schema_privilege(ns.nspname, 'USAGE')
    AND a.attnum >= 0
    AND a.attisdropped != true
    AND c.relname NOT IN ('kysely_migration', 'kysely_migration_lock')
ORDER BY ns.nspname, c.relname, a.attnum
