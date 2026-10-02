import { Database } from "bun:sqlite";
import { createHmac } from "node:crypto";
import { createRequire } from "node:module";
import { isDeepStrictEqual } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";

const reference = fileURLToPath(new URL("../../compat-tests/reference-server", import.meta.url));
const requireReference = createRequire(`${reference}/package.json`);
const upstream = specifier => import(pathToFileURL(requireReference.resolve(specifier)).href);
const { betterAuth } = await upstream("better-auth");
const { admin } = await upstream("better-auth/plugins");
const { memoryAdapter } = await upstream("better-auth/adapters/memory");
const { getMigrations } = await upstream("better-auth/db/migration");

const origin = "http://admin-update-cancel.test";
const secret = "ordinary-admin-display-update-secret-at-least-32-characters";
const message = "ordinary display hook error";
const createdAt = new Date("2025-01-01T00:00:00.000Z");
const validUntil = new Date("2099-01-01T00:00:00.000Z");
const json = value => JSON.parse(JSON.stringify(value));

function responseUser(value) {
  if (value === null) return null;
  const result = json(value);
  if (typeof result.updatedAt !== "string" || !Number.isFinite(Date.parse(result.updatedAt))) {
    throw new Error("The successful response must contain an update timestamp");
  }
  result.updatedAt = "<timestamp>";
  return result;
}

async function observe(backend, channel, mode) {
  const events = [];
  const originalError = new Error(message);
  const database = backend === "sqlite" ? new Database(":memory:") : null;
  const memory = { user: [], session: [], account: [], verification: [] };
  const options = {
    database: database ?? memoryAdapter(memory), baseURL: origin, secret,
    telemetry: { enabled: false }, logger: { disabled: true }, rateLimit: { enabled: false },
    session: { disableSessionRefresh: true, cookieCache: { enabled: false } },
    databaseHooks: { user: { update: {
      before(data) {
        events.push({ phase: "before", name: data.name });
        if (mode === "cancel") return false;
        if (mode === "error") throw originalError;
      },
      after(user) { events.push({ phase: "after", name: user?.name ?? null }); },
    } } },
    plugins: [admin()],
  };
  try {
    if (database) await (await getMigrations(options)).runMigrations();
    const auth = betterAuth(options);
    const { adapter } = await auth.$context;
    for (const [id, name, role] of [["actor", "Ordinary Admin", "admin"], ["target", "Original", "user"]]) {
      await adapter.create({ model: "user", forceAllowId: true, data: {
        id, name, role, email: `${id}@admin-update-cancel.test`, emailVerified: true,
        image: null, banned: false, createdAt, updatedAt: createdAt,
      } });
    }
    await adapter.create({ model: "session", forceAllowId: true, data: {
      id: "actor-session", userId: "actor", token: "ordinary-display-token", expiresAt: validUntil,
      createdAt, updatedAt: createdAt,
    } });
    const signature = createHmac("sha256", secret).update("ordinary-display-token").digest("base64");
    const cookie = `better-auth.session_token=${encodeURIComponent(`ordinary-display-token.${signature}`)}`;
    const headers = new Headers({ "content-type": "application/json", origin, cookie });
    const body = { userId: "target", data: { name: "Changed" } };
    const read = () => adapter.findOne({ model: "user", where: [{ field: "id", value: "target" }] });
    const before = json(await read());
    let outcome;
    let returned;
    if (channel === "http") {
      const response = await auth.handler(new Request(`${origin}/api/auth/admin/update-user`, {
        method: "POST", headers, body: JSON.stringify(body),
      }));
      const text = await response.text();
      if (response.ok) returned = JSON.parse(text);
      outcome = {
        status: response.status,
        headers: [...response.headers].sort(([a], [b]) => a.localeCompare(b)),
        ...(response.ok ? { body: responseUser(returned) } : { bodyText: text }),
      };
    } else {
      try {
        returned = json(await auth.api.adminUpdateUser({ headers, body }));
        outcome = { body: responseUser(returned) };
      } catch (error) {
        outcome = { error: { message: error.message, original: error === originalError } };
      }
    }
    const after = json(await read());
    return {
      backend, channel, mode, outcome, events,
      storedName: after.name,
      storedUnchanged: isDeepStrictEqual(before, after),
      responseMatchesStored: returned == null ? null : isDeepStrictEqual(returned, after),
    };
  } finally { database?.close(); }
}

export async function captureAdminUpdateCancellation() {
  const cases = [];
  for (const backend of ["memory", "sqlite"]) {
    for (const channel of ["http", "native"]) {
      for (const mode of ["success", "cancel", "error"]) cases.push(await observe(backend, channel, mode));
    }
  }
  return {
    version: (await Bun.file(`${reference}/node_modules/better-auth/package.json`).json()).version,
    cases,
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureAdminUpdateCancellation(), null, 2));
