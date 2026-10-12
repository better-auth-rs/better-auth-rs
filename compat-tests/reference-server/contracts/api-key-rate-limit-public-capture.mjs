import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { withClock } from "./email-verification-duration-capture.mjs";
import {
  assertSecondaryNativeVersions, createSecondaryNativeObserver,
  secondaryNativeNow as now, secondaryNativeVersion as version,
} from "./secondary-native-shared.mjs";

export async function captureApiKeyRateLimitPublic() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core", "@better-auth/api-key"]);
  return await withClock(async setClock => {
    setClock(now);
    const state = createSecondaryNativeObserver();
    const key = {
      id: "usage-key", name: "Usage key", start: null, prefix: null,
      key: "usage-secret", referenceId: "owner", configId: "default",
      refillInterval: null, refillAmount: null, lastRefillAt: null,
      enabled: true, rateLimitEnabled: true, rateLimitTimeWindow: 2_000,
      rateLimitMax: 3, requestCount: 3, remaining: 3, lastRequest: new Date(now - 1_000),
      expiresAt: null, createdAt: new Date(now - 60_000), updatedAt: new Date(now - 60_000),
      permissions: null, metadata: null,
    };
    const values = new Map([
      ["api-key:usage-secret", JSON.stringify(key)],
      ["api-key:by-id:usage-key", JSON.stringify(key)],
      ["api-key:by-ref:owner", '["usage-key"]'],
    ]);
    const memory = { user: [], session: [], account: [], verification: [], apikey: [] };
    const storageEvents = [];
    const logs = [];
    const customStorage = {
      async get(key) { storageEvents.push(["get", key]); return values.get(key) ?? null; },
      async set(key, value, ttl) { storageEvents.push(["set", key, value, ttl]); values.set(key, value); },
      async delete(key) { storageEvents.push(["delete", key]); values.delete(key); },
    };
    const auth = betterAuth({
      database: memoryAdapter(memory), baseURL: "https://api-key-rate-limit-public.test",
      secret: "api-key-rate-limit-public-contract-at-least-thirty-two-characters",
      telemetry: { enabled: false }, rateLimit: { enabled: false },
      logger: { level: "error", disableColors: true, log(level, message, ...arguments_) {
        logs.push({ level, message, arguments: arguments_ });
      } },
      plugins: [apiKey({ storage: "secondary-storage", customStorage, disableKeyHashing: true })],
    });
    await auth.$context;
    const before = state.snapshot({ database: memory, cache: [...values] });
    const result = await auth.api.verifyApiKey({ body: { key: "usage-secret" } });
    assert.deepEqual(result, {
      valid: false, error: { message: "Rate limit exceeded.", code: "RATE_LIMITED", details: { tryAgainIn: 1_000 } }, key: null,
    });
    assert.deepEqual(storageEvents, [["get", "api-key:usage-secret"]]);
    const after = state.snapshot({ database: memory, cache: [...values] });
    assert.deepEqual(after, before);
    return { version, contract: "api-key-rate-limit-public", cases: [{
      name: "secondary-deny", before, result: state.snapshot(result), after,
      storageEvents: state.snapshot(storageEvents), logs: state.snapshot(logs),
    }] };
  });
}

if (import.meta.main) {
  const output = `${JSON.stringify(await captureApiKeyRateLimitPublic(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], output);
  else process.stdout.write(output);
}
