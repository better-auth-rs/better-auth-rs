import { compatScenario } from "../../support/scenario";

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("expected object response body");
  }
  return value as Record<string, unknown>;
}

function asArray(value: unknown): unknown[] {
  if (!Array.isArray(value)) {
    throw new Error("expected array response body");
  }
  return value;
}

// ---------------------------------------------------------------------------
// Helper: sign up and get a session cookie header for authenticated requests
// ---------------------------------------------------------------------------

async function signUpAndGetHeaders(
  ctx: Parameters<Parameters<typeof compatScenario>[1]>[0],
  prefix: string,
) {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail(prefix);

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "API Key Test User",
  });

  return { signup, email, primary };
}

// =========================================================================
// CRUD — happy path
// =========================================================================

compatScenario("api-key create returns key and all expected fields", async (ctx) => {
  const { primary } = await signUpAndGetHeaders(ctx, "phase5-create");

  const res = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/create",
    method: "POST",
    json: {},
  });

  const body = asRecord(res.body);

  return {
    status: res.status,
    shape: {
      hasKey: typeof body.key === "string" && (body.key as string).length > 0,
      hasId: typeof body.id === "string",
      hasUserId: typeof body.userId === "string",
      name: body.name,
      prefix: body.prefix,
      enabled: body.enabled,
      rateLimitEnabled: body.rateLimitEnabled,
      rateLimitTimeWindow: body.rateLimitTimeWindow,
      rateLimitMax: body.rateLimitMax,
      requestCount: body.requestCount,
      remaining: body.remaining,
      refillInterval: body.refillInterval,
      refillAmount: body.refillAmount,
      lastRefillAt: body.lastRefillAt,
      lastRequest: body.lastRequest,
      expiresAt: body.expiresAt,
      hasCreatedAt: typeof body.createdAt === "string",
      hasUpdatedAt: typeof body.updatedAt === "string",
      metadata: body.metadata,
      permissions: body.permissions,
    },
  };
});

compatScenario("api-key create key has expected length and charset", async (ctx) => {
  const { primary } = await signUpAndGetHeaders(ctx, "phase5-keyfmt");

  const res = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/create",
    method: "POST",
    json: {},
  });

  const body = asRecord(res.body);
  const key = body.key as string;

  return {
    status: res.status,
    keyLength: key.length,
    // TS generates [a-zA-Z] only — no digits, no special chars
    keyIsAlphaOnly: /^[a-zA-Z]+$/.test(key),
  };
});

compatScenario("api-key list returns created keys without key field", async (ctx) => {
  const { primary } = await signUpAndGetHeaders(ctx, "phase5-list");

  // Create two keys
  await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/create",
    method: "POST",
    json: { name: "key-one" },
  });
  await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/create",
    method: "POST",
    json: { name: "key-two" },
  });

  const res = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/list",
  });

  const items = asArray(res.body);

  return {
    status: res.status,
    count: items.length,
    // Verify no plaintext key is returned in list
    noKeyField: items.every((item) => {
      const rec = asRecord(item);
      return rec.key === undefined;
    }),
    // List should return insertion order (not reverse)
    names: items.map((item) => asRecord(item).name),
  };
});

compatScenario("api-key get by id returns expected shape", async (ctx) => {
  const { primary } = await signUpAndGetHeaders(ctx, "phase5-get");

  const createRes = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/create",
    method: "POST",
    json: { name: "get-test-key" },
  });
  const created = asRecord(createRes.body);

  const getRes = await ctx.rawRequest({
    actor: "primary",
    path: `/api/auth/api-key/get?id=${created.id}`,
  });

  const got = asRecord(getRes.body);

  return {
    status: getRes.status,
    nameMatches: got.name === "get-test-key",
    noKeyField: got.key === undefined,
    hasId: typeof got.id === "string",
  };
});

compatScenario("api-key update accepts keyId field and updates name", async (ctx) => {
  const { primary } = await signUpAndGetHeaders(ctx, "phase5-update");

  const createRes = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/create",
    method: "POST",
    json: { name: "before-update" },
  });
  const created = asRecord(createRes.body);

  const updateRes = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/update",
    method: "POST",
    json: {
      keyId: created.id,
      name: "after-update",
      enabled: false,
    },
  });

  const updated = asRecord(updateRes.body);

  return {
    status: updateRes.status,
    name: updated.name,
    enabled: updated.enabled,
  };
});

compatScenario("api-key delete accepts keyId and returns success", async (ctx) => {
  const { primary } = await signUpAndGetHeaders(ctx, "phase5-delete");

  const createRes = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/create",
    method: "POST",
    json: {},
  });
  const created = asRecord(createRes.body);

  const deleteRes = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/delete",
    method: "POST",
    json: {
      keyId: created.id,
    },
  });

  const deleteBody = asRecord(deleteRes.body);

  return {
    status: deleteRes.status,
    body: deleteBody,
  };
});

// Note: /api-key/verify and /api-key/delete-all-expired-api-keys are
// server-only endpoints in TS (not exposed over HTTP). The Rust server
// exposes them as convenience routes but they are NOT part of the client
// wire contract. Compat tests for these are omitted.

// =========================================================================
// Expiration
// =========================================================================

compatScenario("api-key create with expiresIn sets expiresAt approximately correct", async (ctx) => {
  const { primary } = await signUpAndGetHeaders(ctx, "phase5-expires");

  // expiresIn is in seconds in TS — 86400 = 1 day
  const res = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/create",
    method: "POST",
    json: {
      expiresIn: 86400,
    },
  });

  const body = asRecord(res.body);
  const expiresAt = body.expiresAt as string;

  // Verify expiresAt is roughly 1 day from now (within 10 second tolerance)
  const expiresMs = new Date(expiresAt).getTime();
  const expectedMs = Date.now() + 86400 * 1000;
  const diffSeconds = Math.abs(expiresMs - expectedMs) / 1000;

  return {
    status: res.status,
    hasExpiresAt: typeof expiresAt === "string",
    expiresAtRoughlyOneDayFromNow: diffSeconds < 10,
  };
});

// =========================================================================
// Edge cases — default values
// =========================================================================

compatScenario("api-key create defaults rate limit fields from config", async (ctx) => {
  const { primary } = await signUpAndGetHeaders(ctx, "phase5-defaults");

  const res = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/create",
    method: "POST",
    json: {},
  });

  const body = asRecord(res.body);

  return {
    status: res.status,
    // These should match the global defaults
    rateLimitEnabled: body.rateLimitEnabled,
    rateLimitTimeWindow: body.rateLimitTimeWindow,
    rateLimitMax: body.rateLimitMax,
    requestCount: body.requestCount,
  };
});

// delete-all-expired is server-only in TS — see note above.

// =========================================================================
// Metadata
// =========================================================================

compatScenario("api-key create with metadata preserves it", async (ctx) => {
  const { primary } = await signUpAndGetHeaders(ctx, "phase5-metadata");

  const res = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/create",
    method: "POST",
    json: {
      metadata: { env: "test", version: 1 },
    },
  });

  const body = asRecord(res.body);

  return {
    status: res.status,
    metadata: body.metadata,
  };
});

// =========================================================================
// Prefix and start field
// =========================================================================

compatScenario("api-key create with prefix includes prefix in start field", async (ctx) => {
  const { primary } = await signUpAndGetHeaders(ctx, "phase5-prefix-start");

  const res = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/create",
    method: "POST",
    json: {
      prefix: "ba_",
    },
  });

  const body = asRecord(res.body);
  const key = body.key as string;
  const start = body.start as string;

  return {
    status: res.status,
    prefix: body.prefix,
    keyStartsWithPrefix: key.startsWith("ba_"),
    // TS computes start from the full key (including prefix),
    // so start should equal key.substring(0, 6)
    startMatchesKeySubstring: start === key.substring(0, 6),
    startLength: start.length,
  };
});

compatScenario("api-key create without prefix has start from key beginning", async (ctx) => {
  const { primary } = await signUpAndGetHeaders(ctx, "phase5-no-prefix-start");

  const res = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/create",
    method: "POST",
    json: {},
  });

  const body = asRecord(res.body);
  const key = body.key as string;
  const start = body.start as string;

  return {
    status: res.status,
    startMatchesKeySubstring: start === key.substring(0, 6),
    startLength: start.length,
  };
});

// =========================================================================
// Permissions in response
// =========================================================================

compatScenario("api-key create rejects server-only permissions field from client", async (ctx) => {
  const { primary } = await signUpAndGetHeaders(ctx, "phase5-perms-reject");

  // TS rejects server-only fields (permissions, remaining, refillAmount, etc.)
  // when the request comes over HTTP (i.e. from a client)
  const res = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/create",
    method: "POST",
    json: {
      permissions: { admin: ["read", "write"], user: ["read"] },
    },
  });

  return {
    status: res.status,
  };
});

// =========================================================================
// Error shapes
// =========================================================================

compatScenario("api-key create without session returns 401", async (ctx) => {
  // Don't sign up — just call create directly without session
  const res = await ctx.rawRequest({
    path: "/api/auth/api-key/create",
    method: "POST",
    json: {},
  });

  return {
    status: res.status,
  };
});

compatScenario("api-key get non-existent key returns error", async (ctx) => {
  const { primary } = await signUpAndGetHeaders(ctx, "phase5-get-missing");

  const res = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/get?id=non-existent-id",
  });

  return {
    status: res.status,
  };
});

compatScenario("api-key update non-existent key returns error", async (ctx) => {
  const { primary } = await signUpAndGetHeaders(ctx, "phase5-update-missing");

  const res = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/update",
    method: "POST",
    json: {
      keyId: "non-existent-id",
      name: "new-name",
    },
  });

  return {
    status: res.status,
  };
});

compatScenario("api-key delete non-existent key returns error", async (ctx) => {
  const { primary } = await signUpAndGetHeaders(ctx, "phase5-delete-missing");

  const res = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/delete",
    method: "POST",
    json: {
      keyId: "non-existent-id",
    },
  });

  return {
    status: res.status,
  };
});

compatScenario("api-key get another users key returns error", async (ctx) => {
  // User A creates a key, user B tries to get it
  const { primary } = await signUpAndGetHeaders(ctx, "phase5-cross-user-get-a");

  const createRes = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/create",
    method: "POST",
    json: { name: "user-a-key" },
  });
  const created = asRecord(createRes.body);

  // Sign up user B
  const userB = ctx.actor("userB");
  await userB.client.signUp.email({
    email: ctx.uniqueEmail("phase5-cross-user-get-b"),
    password: "password123",
    name: "User B",
  });

  const getRes = await ctx.rawRequest({
    actor: "userB",
    path: `/api/auth/api-key/get?id=${created.id}`,
  });

  return {
    status: getRes.status,
  };
});

// =========================================================================
// List ordering
// =========================================================================

compatScenario("api-key list returns keys in insertion order", async (ctx) => {
  const { primary } = await signUpAndGetHeaders(ctx, "phase5-list-order");

  // Create three keys in sequence
  await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/create",
    method: "POST",
    json: { name: "first" },
  });
  await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/create",
    method: "POST",
    json: { name: "second" },
  });
  await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/create",
    method: "POST",
    json: { name: "third" },
  });

  const res = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/list",
  });

  const items = asArray(res.body);

  return {
    status: res.status,
    count: items.length,
    // TS returns insertion order (no explicit sort)
    names: items.map((item) => asRecord(item).name),
  };
});

// =========================================================================
// Update edge cases
// =========================================================================

compatScenario("api-key update with no fields returns error", async (ctx) => {
  const { primary } = await signUpAndGetHeaders(ctx, "phase5-update-empty");

  const createRes = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/create",
    method: "POST",
    json: { name: "empty-update-key" },
  });
  const created = asRecord(createRes.body);

  // Send update with only keyId and no actual changes
  const updateRes = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/update",
    method: "POST",
    json: {
      keyId: created.id,
    },
  });

  return {
    status: updateRes.status,
  };
});

compatScenario("api-key update expiresIn null clears expiration", async (ctx) => {
  const { primary } = await signUpAndGetHeaders(ctx, "phase5-update-null-exp");

  // Create a key with expiration
  const createRes = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/create",
    method: "POST",
    json: { expiresIn: 86400 },
  });
  const created = asRecord(createRes.body);

  // Update with expiresIn: null to clear expiration
  const updateRes = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/api-key/update",
    method: "POST",
    json: {
      keyId: created.id,
      expiresIn: null,
    },
  });

  const updated = asRecord(updateRes.body);

  return {
    status: updateRes.status,
    expiresAt: updated.expiresAt,
  };
});
