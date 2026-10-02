import { Database } from "bun:sqlite";
import { createHmac } from "node:crypto";

const modules = `${import.meta.dir}/../../compat-tests/reference-server/node_modules`;
const { betterAuth } = await import(`${modules}/better-auth/dist/index.mjs`);
const { admin } = await import(`${modules}/better-auth/dist/plugins/admin/index.mjs`);
const { getMigrations } = await import(`${modules}/better-auth/dist/db/get-migration.mjs`);

const origin = "http://admin-duration.test";
const secret = "ordinary-admin-duration-secret-longer-than-32-characters";
const issuedAt = 2_000_000_000_123;
const createdAt = new Date("2025-01-01T00:00:00.000Z");
const validUntil = new Date("2099-01-01T00:00:00.000Z");

const user = (row) => ({ name: row.name, email: row.email, role: row.role });
const ban = (row) => ({
  ...user(row), banned: row.banned, banReason: row.banReason,
  lifetimeMillis: row.banExpires == null ? null : new Date(row.banExpires).getTime() - issuedAt,
});
const session = (row) => ({
  userId: row.userId, impersonatedBy: row.impersonatedBy,
  lifetimeMillis: new Date(row.expiresAt).getTime() - issuedAt,
});

function cookie(header) {
  const [pair, ...raw] = header.split(";").map(value => value.trim());
  const index = pair.indexOf("=");
  const attributes = Object.fromEntries(raw.map(attribute => {
    const split = attribute.indexOf("=");
    if (split === -1) return [attribute.toLowerCase(), true];
    const name = attribute.slice(0, split).toLowerCase();
    const value = attribute.slice(split + 1);
    return [name, name === "samesite" ? value.toLowerCase() : value];
  }));
  return { name: pair.slice(0, index), valuePresent: pair.slice(index + 1).length > 0, attributes };
}

export const cases = [
  ...["ban", "impersonate"].flatMap(operation => [
    { name: "omitted", operation },
    { name: "zero", operation, configured: 0 },
    { name: "fractional", operation, configured: 1.5 },
  ]),
  { name: "request-priority", operation: "ban", configured: 1.5, requested: 2.5 },
  { name: "request-zero", operation: "ban", configured: 1.5, requested: 0 },
];

export async function capture(input) {
  const database = new Database(":memory:");
  const option = input.operation === "ban" ? "defaultBanExpiresIn" : "impersonationSessionDuration";
  const options = {
    database, baseURL: origin, secret,
    telemetry: { enabled: false }, logger: { disabled: true }, rateLimit: { enabled: false },
    session: { cookieCache: { enabled: false } },
    plugins: [admin({ ...(input.configured === undefined ? {} : { [option]: input.configured }) })],
  };
  try {
    await (await getMigrations(options)).runMigrations();
    const auth = betterAuth(options);
    const { adapter } = await auth.$context;
    const create = (model, data) => adapter.create({ model, forceAllowId: true, data: {
      createdAt, updatedAt: createdAt, ...data,
    } });
    for (const [id, name, role] of [["admin", "Ordinary Admin", "admin"], ["ordinary", "Ordinary User", "user"]]) {
      await create("user", { id, name, role, email: `${id}@admin-duration.test`, emailVerified: true, banned: false, banReason: null, banExpires: null });
    }
    await create("session", { id: "admin-session", userId: "admin", token: "ordinary-admin-token", expiresAt: validUntil });
    const signature = createHmac("sha256", secret).update("ordinary-admin-token").digest("base64");
    const signedCookie = `better-auth.session_token=${encodeURIComponent(`ordinary-admin-token.${signature}`)}`;
    const body = { userId: "ordinary", ...(input.operation === "ban" ? { banReason: "Ordinary administrative update" } : {}), ...(input.requested === undefined ? {} : { banExpiresIn: input.requested }) };
    const path = input.operation === "ban" ? "/admin/ban-user" : "/admin/impersonate-user";
    const originalNow = Date.now;
    let response;
    try {
      Date.now = () => issuedAt;
      response = await auth.handler(new Request(`${origin}/api/auth${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", origin, cookie: signedCookie },
        body: JSON.stringify(body),
      }));
    } finally { Date.now = originalNow; }
    const output = await response.json();
    const ordinary = await adapter.findOne({ model: "user", where: [{ field: "id", value: "ordinary" }] });
    const sessions = await adapter.findMany({ model: "session", where: [{ field: "userId", value: "ordinary" }] });
    return {
      ...input, status: response.status,
      body: !response.ok ? output : input.operation === "ban" ? { user: ban(output.user) } : { user: user(output.user), session: session(output.session) },
      storedUser: input.operation === "ban" ? ban(ordinary) : user(ordinary),
      issuedSessions: sessions.map(session),
      responseMatchesStored: input.operation === "ban"
        ? output.user?.id === ordinary.id && (output.user.banExpires == null ? ordinary.banExpires == null : new Date(output.user.banExpires).getTime() === ordinary.banExpires.getTime())
        : sessions.length === 1 && output.session?.id === sessions[0].id && output.session.token === sessions[0].token && new Date(output.session.expiresAt).getTime() === sessions[0].expiresAt.getTime(),
      cookies: response.headers.getSetCookie().map(cookie),
    };
  } finally { database.close(); }
}

if (import.meta.main) {
  const results = [];
  for (const input of cases) results.push(await capture(input));
  console.log(JSON.stringify({ version: "1.7.6", cases: results }, null, 2));
}
