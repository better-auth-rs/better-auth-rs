import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { apiKey } from "@better-auth/api-key";
import { createHMAC } from "@better-auth/utils/hmac";
import { memoryAdapter } from "better-auth/adapters/memory";
import { organization } from "better-auth/plugins";

const contract = JSON.parse(readFileSync(new URL("../../../tests/fixtures/api-key-create-gate-cases.json", import.meta.url), "utf8"));
const secret = "api-key-create-gate-contract-secret-at-least-32-characters";
const baseURL = "http://create-gate.test";

async function harness(organizationKeys = false) {
  const memory = { user: [], session: [], account: [], verification: [], apikey: [], organization: [], member: [], invitation: [] };
  const sessions = new Map<string, string>();
  const selected = { key: null as string | null };
  const callbacks: unknown[] = [];
  const auth = betterAuth({
    database: memoryAdapter(memory), baseURL, secret,
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    secondaryStorage: {
      async get(key: string) { return sessions.get(key) ?? null; },
      async set(key: string, value: string) { sessions.set(key, value); },
      async delete(key: string) { sessions.delete(key); },
    },
    plugins: [apiKey({
      references: organizationKeys ? "organization" : "user",
      enableSessionForAPIKeys: true,
      customAPIKeyGetter: () => selected.key,
      deferUpdates: false,
      permissions: { defaultPermissions: async (reference: unknown) => {
        callbacks.push(reference);
        return { machine: ["read"] };
      } },
    }), ...(organizationKeys ? [organization()] : [])],
  });
  const context = await auth.$context;
  const http = (body: unknown, cookie = "") => auth.handler(new Request(`${baseURL}/api/auth/api-key/create`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: baseURL, cookie },
    body: JSON.stringify(body),
  }));
  return { auth, context, sessions, selected, callbacks, http };
}

for (const sample of contract.cases) {
  test(`API Key typed and HTTP creation gate: ${sample.name}`, async () => {
    const f = await harness(sample.organization);
    const typed = contract.errors[sample.typed];
    await expect(f.auth.api.createApiKey({ body: sample.body })).rejects.toMatchObject({
      statusCode: typed.status, body: typed.body,
    });
    const http = await f.http(sample.body);
    const expected = contract.errors[sample.http];
    expect(http.status).toBe(expected.status);
    expect(await http.json()).toStrictEqual(expected.body);
    expect(f.callbacks).toStrictEqual([]);
    expect(await f.context.adapter.count({ model: "apikey" })).toBe(0);
  });
}

test("API Key typed and HTTP creation cannot replace the authenticated user", async () => {
  const f = await harness();
  const owner = await f.context.internalAdapter.createUser({ name: "Owner", email: "owner@create-gate.test", emailVerified: true });
  const source = await f.auth.api.createApiKey({ body: { userId: owner.id } });
  f.selected.key = source.key;
  f.callbacks.length = 0;
  const expected = contract.errors.UNAUTHORIZED_SESSION;
  await expect(f.auth.api.createApiKey({ body: { userId: "other-user" } })).rejects.toMatchObject({
    statusCode: expected.status, body: expected.body,
  });
  f.selected.key = null;
  const now = new Date();
  f.sessions.set("actor-token", JSON.stringify({
    session: { id: "actor-session", userId: owner.id, token: "actor-token", createdAt: now, updatedAt: now, expiresAt: new Date("2100-01-01T00:00:00Z") },
    user: owner,
  }));
  const signature = await createHMAC("SHA-256", "base64").sign(secret, "actor-token");
  const response = await f.http({ userId: "other-user" }, `better-auth.session_token=${encodeURIComponent(`actor-token.${signature}`)}`);
  expect(response.status).toBe(expected.status);
  expect(await response.json()).toStrictEqual(expected.body);
  expect(f.callbacks).toStrictEqual([]);
  const rows = await f.context.adapter.findMany({ model: "apikey" });
  expect(rows.map((row: any) => [row.id, row.referenceId])).toStrictEqual([[source.id, owner.id]]);
});
