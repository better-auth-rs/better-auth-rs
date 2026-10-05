import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { onRequestRateLimit } from "../node_modules/better-auth/dist/api/rate-limiter/index.mjs";
import { captureFreshServerCatalog } from "./server-catalog-shared.mjs";

const rule = { window: 600, max: 100 };

async function observeCounter({ options, query, backend }) {
  const context = await betterAuth(options).$context;
  const url = new URL("/api/auth/ordinary-counter", options.baseURL);
  const headers = { "x-forwarded-for": "192.0.2.10" };
  const quote = name => backend === "postgres" ? `"${name.replaceAll('"', '""')}"` : `\`${name.replaceAll("`", "``")}\``;
  const configuration = options.rateLimit;
  const table = quote(configuration.modelName || "rateLimit");
  const count = quote(configuration.fields?.count || "count");
  const lastRequest = quote(configuration.fields?.lastRequest || "lastRequest");
  let id;
  let key;
  const steps = [];
  for (const expected of [1, 2]) {
    const started = Date.now();
    const response = await onRequestRateLimit(new Request(url, { headers }), context);
    const finished = Date.now();
    assert.equal(response, undefined);
    const rows = await context.adapter.findMany({ model: "rateLimit" });
    assert.equal(rows.length, 1);
    const row = rows[0];
    assert.equal(typeof row.id, "string");
    assert.ok(row.id.length > 0);
    assert.equal(typeof row.key, "string");
    assert.ok(row.key.length > 0);
    if (id === undefined) { id = row.id; key = row.key; }
    assert.equal(row.id, id);
    assert.equal(row.key, key);
    assert.equal(row.count, expected);
    const time = Number(row.lastRequest);
    assert.ok(Number.isSafeInteger(time));
    assert.ok(started <= time && time <= finished);
    const raw = await query(`SELECT ${count} AS count, ${lastRequest} AS last_request FROM ${table} WHERE id = ${backend === "postgres" ? "$1" : "?"}`, [id]);
    assert.equal(raw.length, 1);
    assert.equal(raw[0].count, expected);
    const rawTime = Number(raw[0].last_request);
    assert.ok(Number.isSafeInteger(rawTime));
    assert.equal(rawTime, time);
    steps.push({ allowed: true, retryAfter: null,
      row: { ...row, id: "<counter-id>", lastRequest: "<last-request>" }, rawCount: raw[0].count });
  }
  return { rule, key, steps };
}

export async function captureRateLimitServerRuntime(backend) {
  const version = JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")).version;
  assert.equal(version, "1.7.6");
  const configurations = JSON.parse(readFileSync(new URL("../../schema-consumer/jwk-rate-limit-catalog-config.json", import.meta.url), "utf8"));
  const cases = [];
  for (const name of ["default", "custom"]) {
    const rateLimit = configurations[name].rateLimit;
    const configuration = rateLimit === undefined ? {} : { rateLimit };
    const observed = await captureFreshServerCatalog(backend, [rateLimit?.modelName || "rateLimit"], {
      rateLimit: { enabled: true, storage: "database", ...rule, ...rateLimit },
      advanced: { ipAddress: { ipAddressHeaders: ["x-forwarded-for"] } },
    }, observeCounter);
    cases.push({ name, configuration, ...observed.observation });
  }
  return { version, database: backend, cases };
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the second argument");
  writeFileSync(output, JSON.stringify(await captureRateLimitServerRuntime(backend), null, 2) + "\n");
}
