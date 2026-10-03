import { ok } from "node:assert/strict";
import { getAuthTables } from "@better-auth/core/db";
import { Database } from "bun:sqlite";
import { getMigrations } from "better-auth/db/migration";
import configurations from "../../schema-consumer/verification-catalog-config.json";

type TableRow = { type: string; name: string; tbl_name: string };
type ColumnRow = {
  cid: number;
  name: string;
  type: string;
  notnull: number;
  dflt_value: string | null;
  pk: number;
};
type IndexRow = {
  seq: number;
  name: string;
  unique: number;
  origin: string;
  partial: number;
};
type IndexColumnRow = { seqno: number; cid: number; name: string | null };
type ExtendedIndexColumnRow = IndexColumnRow & {
  desc: number;
  coll: string;
  key: number;
};
type ForeignKeyRow = {
  id: number;
  seq: number;
  table: string;
  from: string;
  to: string | null;
  on_update: string;
  on_delete: string;
  match: string;
};
type DdlRow = TableRow & { sql: string | null };

export async function captureVerificationCatalog() {
  const cases = [];
  for (const [name, configuration] of Object.entries(configurations)) {
    const database = new Database(":memory:");
    const options = {
      ...configuration,
      baseURL: "http://verification-catalog.test",
      secret: "ordinary-verification-catalog-secret-at-least-32-characters",
      database,
      telemetry: { enabled: false },
    };
    try {
      await (await getMigrations(options)).runMigrations();
      const tableName = getAuthTables(options).verification.modelName;
      const table = database.query<TableRow, [string]>(
        "SELECT type, name, tbl_name FROM sqlite_schema WHERE type = 'table' AND name = ?",
      ).get(tableName);
      ok(table, "The generated Verification table exists in the SQLite catalog");
      const columns = database.query<ColumnRow, [string]>(
        'SELECT cid, name, type, "notnull", dflt_value, pk FROM pragma_table_info(?) ORDER BY cid',
      ).all(tableName);
      const indexes = database.query<IndexRow, [string]>(
        'SELECT seq, name, "unique", origin, partial FROM pragma_index_list(?) ORDER BY seq',
      ).all(tableName).map((definition) => ({
        definition,
        columns: database.query<IndexColumnRow, [string]>(
          "SELECT seqno, cid, name FROM pragma_index_info(?) ORDER BY seqno",
        ).all(definition.name),
        extendedColumns: database.query<ExtendedIndexColumnRow, [string]>(
          'SELECT seqno, cid, name, "desc", coll, "key" FROM pragma_index_xinfo(?) ORDER BY seqno',
        ).all(definition.name),
      }));
      const foreignKeys = database.query<ForeignKeyRow, [string]>(
        'SELECT id, seq, "table", "from", "to", on_update, on_delete, "match" FROM pragma_foreign_key_list(?) ORDER BY id, seq',
      ).all(tableName);
      const ddl = database.query<DdlRow, [string]>(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE tbl_name = ? ORDER BY type, name",
      ).all(tableName);
      console.error(JSON.stringify({ case: name, ddl }));
      cases.push({ name, table, columns, indexes, foreignKeys });
    } finally {
      database.close();
    }
  }
  return {
    version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    database: "sqlite",
    cases,
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureVerificationCatalog(), null, 2));
