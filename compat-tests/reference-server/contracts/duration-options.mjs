import assert from "node:assert/strict";
import { Database } from "bun:sqlite";
import { readFileSync, writeFileSync } from "node:fs";

const events = [];
globalThis.fetch = async (input, init) => {
  assert.equal(String(input), "https://duration-options.test/capture");
  events.push(JSON.parse(init.body));
  return Response.json({});
};
const { betterAuth } = await import("better-auth");
const { getMigrations } = await import("better-auth/db/migration");
const cases = [
  ["omitted", undefined], ["zero", 0], ["default", 3600], ["integer", 90],
  ["fractional", 1.5], ["negative", -1.5], ["submillisecond", 0.0005],
  ["negative-submillisecond", -0.0005], ["nan", Number.NaN],
];
const results = {};
const now = 1_700_000_000_123;
for (const [name, seconds] of cases) {
  const database = new Database(":memory:");
  let token;
  let senderCalls = 0;
  const options = {
    database, baseURL: "https://duration-options.test",
    secret: "ordinary-duration-options-secret-more-than-32-characters",
    logger: { disabled: true }, telemetry: { enabled: true },
    emailAndPassword: {
      enabled: true, resetPasswordTokenExpiresIn: seconds,
      sendResetPassword: async (data) => { token = data.token; senderCalls++; },
    },
    emailVerification: { expiresIn: seconds },
  };
  try {
    await (await getMigrations(options)).runMigrations();
    const count = events.length;
    const auth = betterAuth(options);
    const context = await auth.$context;
    assert.equal(events.length, count + 1);
    await context.internalAdapter.createUser({ name: "Duration User", email: "duration@example.test", emailVerified: false });
    const originalNow = Date.now;
    let response;
    try {
      Date.now = () => now;
      response = await auth.api.requestPasswordReset({ body: { email: "duration@example.test" } });
    } finally { Date.now = originalNow; }
    const stored = await context.adapter.findOne({ model: "verification", where: [{ field: "identifier", value: `reset-password:${token}` }] });
    const config = events[count].payload.config;
    results[name] = JSON.parse(JSON.stringify({
      configured: seconds, now, response, senderCalls,
      expiresAt: stored.expiresAt.getTime(), lifetimeMillis: stored.expiresAt.getTime() - now,
      emailVerification: config.emailVerification, emailAndPassword: config.emailAndPassword,
    }));
  } finally { database.close(); }
}
const fixture = new URL("../../../tests/fixtures/duration-options-1.7.6.json", import.meta.url);
if (process.env.DURATION_OPTIONS_OUTPUT) {
  writeFileSync(process.env.DURATION_OPTIONS_OUTPUT, JSON.stringify(results, null, 2) + "\n");
  console.log(`Captured ${Object.keys(results).length} SQLite reset and initialization duration cases`);
} else {
  assert.deepEqual(results, JSON.parse(readFileSync(fixture, "utf8")));
  console.log(`${Object.keys(results).length} SQLite reset and initialization duration cases match the Rust fixture`);
}
