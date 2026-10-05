SELECT
    a.attname AS column_name,
    a.attnotnull AS not_null,
    a.atthasdef AS has_default,
    c.relname AS table_name,
    ns.nspname AS schema_name,
    -- Read sequence ownership from catalog OIDs without resolving names during unrelated DDL.
    EXISTS (
        SELECT 1
        FROM pg_catalog.pg_depend AS dependency
        JOIN pg_catalog.pg_class AS sequence ON sequence.oid = dependency.objid
        WHERE dependency.refclassid = 'pg_catalog.pg_class'::regclass
            AND dependency.refobjid = c.oid
            AND dependency.refobjsubid = a.attnum
            AND dependency.classid = 'pg_catalog.pg_class'::regclass
            AND dependency.objsubid = 0
            AND dependency.deptype IN ('a', 'i')
            AND sequence.relkind = 'S'
    ) AS auto_incrementing,
    pg_catalog.current_schemas(true)::text[] AS search_path
FROM pg_catalog.pg_attribute AS a
JOIN pg_catalog.pg_class AS c ON a.attrelid = c.oid
JOIN pg_catalog.pg_namespace AS ns ON c.relnamespace = ns.oid
WHERE c.relkind IN ('r', 'v', 'p', 'f')
    AND ns.nspname !~ '^pg_'
    AND ns.nspname NOT IN ('information_schema', 'crdb_internal')
    AND pg_catalog.has_schema_privilege(ns.oid, 'USAGE')
    AND a.attnum >= 0
    AND a.attisdropped != true
    AND c.relname NOT IN ('kysely_migration', 'kysely_migration_lock')
ORDER BY ns.nspname, c.relname, a.attnum
