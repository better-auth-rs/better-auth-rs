import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { createKyselyAdapter, kyselyAdapter } from "@better-auth/kysely-adapter";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { emailOTP, magicLink } from "better-auth/plugins";
import {
  assertOutcome, decorate, email, expiresIn, hooks, native, normalizeCapture, origin,
  request, scenarios, secret, seed, tables,
} from "./user-verification-cleanup-support.mjs";

const version = "1.7.6";
for (const name of ["better-auth", "@better-auth/core"]) {
  assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
}

async function captureCase(backend, route, scenario, recorder, diagnostics) {
  const memory = Object.fromEntries(tables.map(model => [model, []]));
  const sqlite = backend === "sqlite" ? new Database(":memory:") : null;
  const state = { enabled: false, events: [] };
  const record = event => { if (state.enabled) state.events.push(native(event)); };
  const snapshot = () => Object.fromEntries(tables.map(model => [model, native(sqlite
    ? sqlite.query(`SELECT * FROM "${model}" ORDER BY "id"`).all() : memory[model]) ]));
  let nextId = 0;
  const options = {
    baseURL: origin, secret, logger: { disabled: true }, telemetry: { enabled: false },
    rateLimit: { enabled: false }, session: { expiresIn, cookieCache: { enabled: false } },
    advanced: { database: { generateId: ({ model }) => `generated-${model}-${++nextId}` } },
    emailVerification: {
      beforeEmailVerification(user) { record({ kind: "verification.before", user }); },
      afterEmailVerification(user) { record({ kind: "verification.after", user }); },
    },
    databaseHooks: hooks(state, scenario, record),
    onAPIError: { onError(error) { record({ kind: "api-error", error }); } },
    plugins: route === "email-otp"
      ? [emailOTP({ sendVerificationOTP: async () => { throw new Error("Cleanup must not send a new OTP"); } })]
      : [magicLink({ sendMagicLink: async () => { throw new Error("Cleanup must not send a new magic link"); } })],
  };
  try {
    let factory = memoryAdapter(memory);
    if (sqlite) {
      const rawOptions = { ...options, database: sqlite };
      await (await getMigrations(rawOptions)).runMigrations();
      const { kysely, databaseType, transaction } = await createKyselyAdapter(rawOptions);
      assert.equal(databaseType, "sqlite");
      factory = kyselyAdapter(kysely, { type: databaseType, transaction });
    }
    options.database = current => decorate(factory(current), scenario, state, record, snapshot);
    const auth = betterAuth(options);
    const { adapter } = await auth.$context;
    await seed(adapter, route, scenario, sqlite ? null : memory);
    const before = snapshot();
    const execute = async () => {
      state.events = [];
      state.enabled = true;
      recorder.record = record;
      const result = await auth.handler(request(route));
      const response = { status: result.status, statusText: result.statusText, headers: [...result.headers],
        cookies: result.headers.getSetCookie(), body: await result.text() };
      state.enabled = false;
      recorder.record = null;
      return { events: state.events, response, after: snapshot() };
    };
    const window = { start: Date.now() };
    const first = await execute();
    const replay = await execute();
    window.end = Date.now();
    const observation = { backend, route, scenario: scenario.name, nativeId: native(scenario.inject ? scenario.id : scenario.storageId),
      physicalOwnerId: before.user.find(row => row.email === email).id,
      request: { method: request(route).method, url: request(route).url,
        ...(route === "email-otp" ? { body: { email, otp: "123456" } } : {}) },
      before, ...first, replay };
    diagnostics.push({ window, observation });
    assertOutcome(scenario, before, first.after, first.events, first.response);
    assert.deepEqual(replay.after, first.after, "A consumed proof replay must preserve all storage");
    assert.deepEqual(replay.response.cookies, []);
    assert.equal(replay.response.status, route === "email-otp" ? 400 : 302);
    if (route === "email-otp") assert.equal(JSON.parse(replay.response.body).code, "INVALID_OTP");
    else assert.equal(new URL(new Headers(replay.response.headers).get("location")).searchParams.get("error"), "INVALID_TOKEN");
    return normalizeCapture(observation, window);
  } finally {
    state.enabled = false;
    recorder.record = null;
    sqlite?.close();
  }
}

export async function captureUserVerificationCleanup({ diagnostics = [] } = {}) {
  const recorder = { record: null };
  const originalConsoleError = console.error;
  console.error = (...args) => {
    assert.ok(recorder.record, "A console error outside the measured request must fail the capture");
    recorder.record({ kind: "console.error", args });
  };
  try {
    const cases = [];
    for (const backend of ["memory", "sqlite"]) for (const route of ["email-otp", "magic-link"]) {
      for (const scenario of scenarios()) {
        if (scenario.failure === "user-not-null" && backend !== "sqlite") continue;
        cases.push(await captureCase(backend, route, scenario, recorder, diagnostics));
      }
    }
    assert.equal(cases.length, 62);
    return { version, scenarios: native(scenarios()), cases };
  } finally { console.error = originalConsoleError; }
}

if (import.meta.main) {
  const diagnostics = [];
  try {
    assert.ok(process.argv[2], "Pass a fixture output path");
    writeFileSync(process.argv[2], `${JSON.stringify(await captureUserVerificationCleanup({ diagnostics }), null, 2)}\n`);
  } finally {
    if (process.argv[2]) writeFileSync(`${process.argv[2]}.raw-diagnostics.json`, `${JSON.stringify(diagnostics, null, 2)}\n`);
  }
}
