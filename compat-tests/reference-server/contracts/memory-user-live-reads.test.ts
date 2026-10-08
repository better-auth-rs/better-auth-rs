import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { getMigrations } from "better-auth/db/migration";
import fixture from "../../../tests/fixtures/memory-user-live-reads-1.7.6.json";
import { capture } from "../../../tests/fixtures/memory-user-live-reads.capture.mjs";

for (const expected of fixture.cases) {
  test(`Memory ${expected.path} joins=${expected.joins} reads live display fields`, async () => {
    expect(await capture(expected.path, expected.joins)).toEqual(expected);
  });
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const path of ["create", "update"] as const) {
    test(`${backend} User ${path} preserves the adapter output source`, async () => {
      const database = backend === "sqlite" ? new Database(":memory:") : undefined;
      try {
        if (database) await (await getMigrations({ database })).runMigrations();
        expect(await capture(path, false, database)).toEqual({
          path, joins: false,
          events: [["name", "ordinary-name"], ["display-write", "image-after"]],
          result: [{ name: "ordinary-name-visible", image: backend === "memory" ? "image-after" : "image-before" }],
          stored: { name: "ordinary-name", image: "image-after" },
        });
      } finally {
        database?.close();
      }
    });
  }
}
