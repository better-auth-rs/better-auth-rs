import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";

export const fixturePath = "/__test/verification-date-output";
export type DateOutputCase = {
  mode: "database" | "cache" | "database-cache";
  kind: "number" | "null" | "undefined" | "object" | "invalid-date";
};

export async function verificationDateOutput(input: DateOutputCase) {
  const database = new Database(":memory:");
  const entries = new Map<string, string>();
  const events: string[] = [];
  const usesCache = input.mode !== "database";
  const usesDatabase = input.mode !== "cache";
  const replacement = {
    number: 4_102_444_800_000,
    null: null,
    undefined,
    object: { unknown: true },
    "invalid-date": "invalid-date",
  }[input.kind];
  const options = {
    database,
    baseURL: "http://localhost:3000",
    secret: "verification-date-output-fixture-secret-at-least-32-characters",
    logger: { disabled: true },
    ...(usesCache ? { secondaryStorage: {
      async get(key: string) { return entries.get(key) ?? null; },
      async set(key: string, value: string) {
        events.push("cache.set");
        entries.set(key, value);
      },
      async delete(key: string) { entries.delete(key); },
      async getAndDelete(key: string) {
        const value = entries.get(key) ?? null;
        entries.delete(key);
        return value;
      },
    } } : {}),
    verification: {
      storeInDatabase: usesDatabase,
      disableCleanup: true,
      additionalFields: {
        expiresAt: {
          type: "date" as const,
          required: true,
          transform: { output: () => {
            events.push("output");
            return replacement;
          } },
        },
      },
    },
    databaseHooks: { verification: { create: { after: async () => {
      events.push("after");
    } } } },
  };
  try {
    await (await getMigrations(options)).runMigrations();
    const context = await betterAuth(options).$context;
    let created: Record<string, unknown> | undefined;
    let createError = false;
    try {
      created = await context.internalAdapter.createVerificationValue({
        identifier: "date-output", value: "proof", expiresAt: new Date("2100-01-01T00:00:00Z"),
      });
    } catch (error) {
      if (!(error instanceof TypeError)) throw error;
      createError = true;
    }
    const createEvents = events.slice();
    const rowCount = () => usesDatabase
      ? (database.query("SELECT COUNT(*) AS count FROM verification").get() as { count: number }).count : 0;
    const rowsBefore = rowCount();
    const cacheBefore = entries.size;
    const createdJSON = created ? JSON.parse(JSON.stringify(created)) : {};
    const consumed = createError ? undefined
      : await context.internalAdapter.consumeVerificationValue("date-output");
    return {
      createError,
      createdHasExpiry: Object.hasOwn(createdJSON, "expiresAt"),
      createdExpiry: createdJSON.expiresAt ?? null,
      rowsBefore, cacheBefore, createEvents,
      consumeFound: consumed === undefined ? null : consumed !== null,
      rowsAfter: rowCount(),
    };
  } finally {
    database.close();
  }
}

export async function routeVerificationDateOutput(request: Request) {
  if (new URL(request.url).pathname !== fixturePath) return null;
  return Response.json(await verificationDateOutput(await request.json()));
}
