SELECT
    columns.COLUMN_NAME AS column_name,
    columns.COLUMN_DEFAULT AS column_default,
    columns.TABLE_NAME AS table_name,
    columns.TABLE_SCHEMA AS schema_name,
    columns.IS_NULLABLE AS is_nullable,
    columns.EXTRA AS extra
FROM information_schema.columns AS columns
JOIN information_schema.tables AS tables
    ON columns.TABLE_CATALOG = tables.TABLE_CATALOG
    AND columns.TABLE_SCHEMA = tables.TABLE_SCHEMA
    AND columns.TABLE_NAME = tables.TABLE_NAME
WHERE columns.TABLE_SCHEMA = database()
    AND columns.TABLE_NAME NOT IN ('kysely_migration', 'kysely_migration_lock')
ORDER BY columns.TABLE_NAME, columns.ORDINAL_POSITION
