import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth, type BetterAuthOptions } from "better-auth";

const date = (offset: number) => new Date(1_893_456_000_000 + offset * 1000);

for (const rejectedInput of [false, true]) {
  test(`SQLite User input ${rejectedInput ? "failure precedes" : "runs before"} the second query binding`, async () => {
    const database = new Database(":memory:");
    try {
      // Adapter writes or reads would replace the application ID declaration before this update.
      database.exec(`CREATE TABLE user (id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL, emailVerified INTEGER NOT NULL, image TEXT, createdAt TEXT NOT NULL, updatedAt TEXT NOT NULL);
        INSERT INTO user VALUES ('seed', 'Before', 'seed@example.test', 1, NULL, '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z');`);
      const raw = () => database.query("SELECT * FROM user ORDER BY id").all() as Record<string, unknown>[];
      const before = raw();
      const events: string[] = [];
      let reject = rejectedInput;
      const options: BetterAuthOptions = {
        database, baseURL: "http://query-binding-order.test",
        secret: "query-binding-order-contract-at-least-32-characters",
        logger: { disabled: true }, telemetry: { enabled: false },
        user: { additionalFields: {
          name: { type: "string", transform: {
            input(value) {
              events.push("name-input");
              if (reject) throw new Error("user-input-rejected");
              return value;
            },
            output(value) { events.push("name-output"); return value; },
          } },
          image: { type: "string", defaultValue() {
            events.push("image-default");
            return "creation-only-image";
          } },
          updatedAt: { type: "date", onUpdate() {
            events.push("updated-on-update");
            return date(1);
          }, transform: { input(value) {
            events.push("updated-input");
            expect(value).toStrictEqual(date(1));
            return value;
          } } },
          id: { type: "string", fieldName: "old_id" },
        } },
      };
      const { adapter } = await betterAuth(options).$context;
      expect(events).toStrictEqual([]);
      const update = () => adapter.update({ model: "user", where: [{ field: "id", value: "seed" }], update: { name: "After" } });
      let failure: unknown;
      try { await update(); } catch (error) { failure = error; }
      if (!(failure instanceof Error)) throw new Error("The first User update must fail");
      expect({ name: failure.name, message: failure.message }).toStrictEqual(rejectedInput
        ? { name: "Error", message: "user-input-rejected" }
        : { name: "BetterAuthError", message: "Field old_id not found in model user" });
      expect(events).toStrictEqual(rejectedInput ? ["name-input"] : ["name-input", "updated-on-update", "updated-input"]);
      expect(raw()).toStrictEqual(before);

      reject = false;
      events.length = 0;
      expect(await update()).toStrictEqual({
        id: "seed", name: "After", email: "seed@example.test", emailVerified: true,
        image: null, createdAt: date(0), updatedAt: date(1),
      });
      expect(events).toStrictEqual(["name-input", "updated-on-update", "updated-input", "name-output"]);
      expect(raw()).toStrictEqual(before.map(row => ({ ...row, name: "After", updatedAt: date(1).toISOString() })));
    } finally {
      database.close();
    }
  });
}
