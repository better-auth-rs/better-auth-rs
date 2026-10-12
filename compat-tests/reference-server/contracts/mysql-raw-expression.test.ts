import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { Kysely, MysqlDialect, sql } from "kysely";

test("pinned MySQL raw operands retain only caller-supplied parentheses", () => {
  const metadata = JSON.parse(readFileSync(new URL("../node_modules/kysely/package.json", import.meta.url), "utf8"));
  expect(metadata.version).toBe("0.29.5");
  const db = new Kysely({ dialect: new MysqlDialect({ pool: {} as never }) });
  for (const parenthesized of [false, true]) {
    const operand = parenthesized ? sql`(LOWER(${sql.ref("users.name")}))` : sql`LOWER(${sql.ref("users.name")})`;
    const expression = parenthesized ? "(LOWER(`users`.`name`))" : "LOWER(`users`.`name`)";
    for (const operator of ["=", "<>", "in", "not in"] as const) {
      const membership = operator === "in" || operator === "not in";
      const compiled = db.selectFrom("users").selectAll().where(operand, operator, membership ? ["upper"] : "upper").compile();
      expect(compiled.sql).toBe(`select * from \`users\` where ${expression} ${operator} ${membership ? "(?)" : "?"}`);
      expect(compiled.parameters).toStrictEqual(["upper"]);
    }
    const compiled = db.selectFrom("users").selectAll().where(sql.val("upper"), "=", operand).compile();
    expect(compiled.sql).toBe(`select * from \`users\` where ? = ${expression}`);
    expect(compiled.parameters).toStrictEqual(["upper"]);
  }
});
