import { Database } from "bun:sqlite";
import { createHmac } from "node:crypto";

const modules = `${import.meta.dir}/../../compat-tests/reference-server/node_modules`;
const { betterAuth } = await import(`${modules}/better-auth/dist/index.mjs`);
const { organization } = await import(`${modules}/better-auth/dist/plugins/organization/index.mjs`);
const { getMigrations } = await import(`${modules}/better-auth/dist/db/get-migration.mjs`);

const origin = "http://organization-duration.test";
const secret = "ordinary-organization-duration-secret-longer-than-32-characters";
const issuedAt = 2_000_000_000_123;
const createdAt = new Date("2025-01-01T00:00:00.000Z");
const validUntil = new Date("2099-01-01T00:00:00.000Z");
const path = "/organization/invite-member";

const record = (row) => ({
  email: row.email,
  role: row.role,
  status: row.status,
  organizationId: row.organizationId,
  inviterId: row.inviterId,
  teamId: row.teamId,
  lifetimeMillis: new Date(row.expiresAt).getTime() - issuedAt,
});

export async function capture(name, seconds, operation) {
  const database = new Database(":memory:");
  const sent = [];
  const options = {
    database, baseURL: origin, secret,
    telemetry: { enabled: false }, logger: { disabled: true }, rateLimit: { enabled: false },
    plugins: [organization({
      teams: { enabled: true },
      ...(name === "omitted" ? {} : { invitationExpiresIn: seconds }),
      sendInvitationEmail(data, request) { sent.push({ data, request }); },
    })],
  };
  try {
    await (await getMigrations(options)).runMigrations();
    const auth = betterAuth(options);
    const { adapter } = await auth.$context;
    const create = (model, data) => adapter.create({ model, forceAllowId: true, data: {
      createdAt, updatedAt: createdAt, ...data,
    } });
    await create("user", { id: "owner", name: "Ordinary Owner", email: "owner@organization-duration.test", emailVerified: true });
    await create("organization", { id: "org", name: "Ordinary Organization", slug: "ordinary-organization" });
    await create("member", { id: "membership", organizationId: "org", userId: "owner", role: "owner" });
    await create("session", { id: "session", userId: "owner", token: "ordinary-session-token", expiresAt: validUntil });
    if (operation === "resend") {
      await create("invitation", {
        id: "existing-invitation", organizationId: "org", inviterId: "owner",
        email: "invitee@organization-duration.test", role: "member", status: "pending",
        expiresAt: validUntil, teamId: null,
      });
    }
    const signature = createHmac("sha256", secret).update("ordinary-session-token").digest("base64");
    const cookie = `better-auth.session_token=${encodeURIComponent(`ordinary-session-token.${signature}`)}`;
    const originalNow = Date.now;
    let response;
    try {
      Date.now = () => issuedAt;
      response = await auth.handler(new Request(`${origin}/api/auth${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", origin, cookie },
        body: JSON.stringify({ organizationId: "org", email: "invitee@organization-duration.test", role: "member", ...(operation === "resend" ? { resend: true } : {}) }),
      }));
    } finally { Date.now = originalNow; }
    const body = await response.json();
    const rows = await adapter.findMany({ model: "invitation" });
    return {
      name, configured: seconds, operation, status: response.status,
      body: response.ok ? record(body) : body,
      records: rows.map(record),
      responseMatchesStored: rows.length === 1 && body.id === rows[0].id && new Date(body.expiresAt).getTime() === rows[0].expiresAt.getTime(),
      resendPreservedRecord: operation === "resend" ? rows.length === 1 && rows[0].id === "existing-invitation" && rows[0].createdAt.getTime() === createdAt.getTime() : null,
      sender: sent.map(({ data, request }) => ({
        invitation: record(data.invitation),
        matchesResponse: data.id === body.id,
        organizationName: data.organization.name,
        inviterName: data.inviter.user.name,
        method: request?.method,
        path: request ? new URL(request.url).pathname : null,
      })),
    };
  } finally { database.close(); }
}

if (import.meta.main) {
  const cases = [];
  for (const [name, seconds] of [["omitted", undefined], ["zero", 0], ["fractional", 1.5]]) {
    for (const operation of ["create", "resend"]) cases.push(await capture(name, seconds, operation));
  }
  console.log(JSON.stringify({ version: "1.7.6", cases }, null, 2));
}
