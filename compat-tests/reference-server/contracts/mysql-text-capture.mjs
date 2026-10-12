import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname } from "node:path";
import { Kysely, MysqlDialect, sql } from "kysely";

const require = createRequire(import.meta.url);
const mysql2 = require("mysql2");
const escaperEntry = require.resolve("sql-escaper", {
  paths: [dirname(require.resolve("mysql2"))],
});
const escaperRoot = dirname(dirname(escaperEntry));
const escaperHashes = {
  "LICENSE": "93277a18ec90d5b72d3bfaaaccc73cec7e735a8a1b154b74e9fec3e529603cbf",
  "lib/index.js": "ac9bfa502b26eea8f8503036a4944046701c37f755bd4da8710482980fe61eed",
  "package.json": "ea2757620053be93e93337220b1c517caded5c9e46b55482bf6ab494009aa9de",
};
for (const [file, expectedHash] of Object.entries(escaperHashes)) {
  for (const path of [
    `${escaperRoot}/${file}`,
    new URL(`../../../vendor/sql-escaper-source/${file}`, import.meta.url),
  ]) {
    const actualHash = createHash("sha256").update(readFileSync(path)).digest("hex");
    if (actualHash !== expectedHash) throw new Error(`Unexpected sql-escaper source: ${path}`);
  }
}
const version = JSON.parse(readFileSync(new URL("../node_modules/kysely/package.json", import.meta.url))).version;
const mysqlVersion = require("mysql2/package.json").version;
const escaperVersion = JSON.parse(readFileSync(`${escaperRoot}/package.json`)).version;
if (version !== "0.29.5" || mysqlVersion !== "3.24.5" || escaperVersion !== "1.5.2") {
  throw new Error(`Unexpected pinned versions: ${version}, ${mysqlVersion}, ${escaperVersion}`);
}
if (process.env.TZ !== "UTC") throw new Error("Run the source capture with TZ=UTC");

function value(input) {
  if (Array.isArray(input)) return input.map(value);
  if (input === null || typeof input !== "object") return input;
  switch (input.$type) {
    case "undefined": return undefined;
    case "number": return Number(input.value);
    case "date": return new Date(value(input.value));
    case "utf16": return String.fromCharCode(...input.value);
    case "raw": return { toSqlString() { return input.value; } };
    default: return Object.fromEntries(Object.entries(input).map(([key, entry]) => [key, value(entry)]));
  }
}
const units = (text) => Array.from({ length: text.length }, (_, index) => text.charCodeAt(index));
const formatCases = JSON.parse(readFileSync(new URL("./mysql-text-cases.json", import.meta.url)));
const formats = formatCases.map((entry) => ({
  name: entry.name,
  units: units(mysql2.format(entry.sql, entry.values.map(value))),
}));

function native(throwOnRead) {
  const events = [];
  const error = { marker: "render-error" };
  let reads = 0;
  const object = new Proxy({}, {
    has(_target, property) {
      if (property === "toSqlString") events.push("has");
      return property === "toSqlString";
    },
    get(_target, property) {
      if (property !== "toSqlString") return undefined;
      events.push(`get:${++reads}`);
      if (reads === throwOnRead) throw error;
      return function () {
        events.push(`call:${this === object}:${arguments.length}`);
        return "CURRENT_TIMESTAMP";
      };
    },
  });
  try {
    return { events, units: units(mysql2.format("select ?", [object])) };
  } catch (caught) {
    return { events, sameError: caught === error };
  }
}

const db = new Kysely({ dialect: new MysqlDialect({ pool: {} }) });
const compiled = [
  ["insert", db.insertInto("MiX`ed").values({ id: "a?", Name: "O'Reilly", enabled: true })],
  ["select", db.selectFrom("MiX`ed").selectAll().where("MiX`ed.id", "=", "ID").orderBy("Name", "desc").limit(2).offset(1)],
  ["update", db.updateTable("MiX`ed").set({ Name: "NEW", count: sql`${sql.ref("count")} + ${1}` }).where("MiX`ed.id", "=", "ID")],
  ["delete", db.deleteFrom("MiX`ed").where("MiX`ed.id", "in", ["A", "B"])],
  ["empty-in", db.selectFrom("MiX`ed").selectAll().where("MiX`ed.id", "in", [])],
  ["null", db.selectFrom("MiX`ed").selectAll().where("MiX`ed.Name", "is", null)],
  ["raw", db.selectFrom("MiX`ed").selectAll().where(sql`LOWER(${sql.ref("MiX`ed.Name")}) LIKE LOWER(${"A?"})`)],
  ["lock", db.selectFrom("MiX`ed").select("id").where("MiX`ed.id", "=", "ID").limit(1).forUpdate().skipLocked()],
  ["join", db.selectFrom(db.selectFrom("MiX`ed").selectAll().where("MiX`ed.id", "=", "ID").as("primary")).selectAll("primary").leftJoin("Child as child", "child.parent", "primary.id").select("child.Name as childName")],
  ["immediate", db.selectFrom("MiX`ed").select([sql.lit("A\\'B").as("Value"), sql.lit(true).as("Bool"), sql.lit(null).as("Null")])],
  ["count", db.selectFrom("MiX`ed").select(db.fn.count("id").as("count"))],
].map(([name, query]) => {
  const compiled = query.compile();
  return { name, sql: compiled.sql, parameters: compiled.parameters };
});
const output = { versions: { kysely: version, mysql2: mysqlVersion, sqlEscaper: escaperVersion }, formats, native: [native(0), native(2)], compiled };
if (!process.argv[2]) throw new Error("Specify the source observation output path");
writeFileSync(process.argv[2], `${JSON.stringify(output, null, 2)}\n`);
