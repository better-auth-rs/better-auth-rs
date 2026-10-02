import { Database } from "bun:sqlite";
import { createHmac } from "node:crypto";

const modules = `${import.meta.dir}/../../compat-tests/reference-server/node_modules`;
const { betterAuth } = await import(`${modules}/better-auth/dist/index.mjs`);
const { organization } = await import(`${modules}/better-auth/dist/plugins/organization/index.mjs`);
const { memoryAdapter } = await import(`${modules}/@better-auth/memory-adapter/dist/index.mjs`);
const { getMigrations } = await import(`${modules}/better-auth/dist/db/get-migration.mjs`);

export const modes = ["default", "teams", "declared", "display"] as const;
type Mode = typeof modes[number];
const origin = "http://invitation-presence.test";
const secret = "ordinary-invitation-presence-secret-at-least-thirty-two-characters";
const createdAt = new Date("2025-01-01T00:00:00.000Z");
const validUntil = new Date("2099-01-01T00:00:00.000Z");

function invitation(value: Record<string, unknown>) {
  return Object.fromEntries(Object.entries(value)
    .filter(([key]) => !["id", "createdAt", "expiresAt"].includes(key)));
}

export async function capture(backend: "memory" | "sqlite", mode: Mode) {
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const events: unknown[] = [];
  const schema = mode === "declared" || mode === "display" ? {
    invitation: { additionalFields: { teamId: {
      type: "string", required: false,
      ...(mode === "display" ? { transform: { output: (value: unknown) => value === null ? "team-display" : value } } : {}),
    } } },
  } : undefined;
  const options = {
    database: database ?? memoryAdapter({ user: [], session: [], account: [], verification: [],
      organization: [], member: [], invitation: [], team: [], teamMember: [] }),
    baseURL: origin, secret, telemetry: { enabled: false }, logger: { disabled: true },
    rateLimit: { enabled: false }, plugins: [organization({
      ...(mode === "teams" ? { teams: { enabled: true } } : {}),
      schema,
      sendInvitationEmail(data: any) { events.push(["sender", invitation(data.invitation)]); },
      organizationHooks: {
        afterCreateInvitation(data: any) { events.push(["after-create", invitation(data.invitation)]); },
      },
    })],
  };
  try {
    if (database) await (await getMigrations(options)).runMigrations();
    const auth = betterAuth(options);
    const { adapter } = await auth.$context;
    const create = (model: string, data: object) => adapter.create({ model, forceAllowId: true,
      data: { createdAt, updatedAt: createdAt, ...data } });
    for (const [id, name] of [["owner", "Ordinary Owner"], ["recipient", "Ordinary Recipient"]]) {
      await create("user", { id, name, email: `${id}@invitation-presence.test`, emailVerified: true });
    }
    await create("organization", { id: "org", name: "Ordinary Organization", slug: "ordinary-organization" });
    for (const id of ["owner", "recipient"]) {
      await create("session", { id: `${id}-session`, userId: id, token: `${id}-session-token`,
        expiresAt: validUntil, activeOrganizationId: "org" });
    }
    await create("member", { id: "owner-membership", organizationId: "org", userId: "owner", role: "owner" });
    async function request(actor: string, path: string, body?: object, query?: Record<string, string>) {
      const token = `${actor}-session-token`;
      const signature = createHmac("sha256", secret).update(token).digest("base64");
      const url = new URL(`/api/auth/organization/${path}`, origin);
      for (const [key, value] of Object.entries(query ?? {})) url.searchParams.set(key, value);
      const response = await auth.handler(new Request(url, {
        method: body ? "POST" : "GET",
        headers: { "content-type": "application/json", origin,
          cookie: `better-auth.session_token=${encodeURIComponent(`${token}.${signature}`)}` },
        ...(body ? { body: JSON.stringify(body) } : {}),
      }));
      return { status: response.status, body: await response.json() };
    }
    const body = { organizationId: "org", email: "recipient@invitation-presence.test", role: "member" };
    const created = await request("owner", "invite-member", body);
    const createEvents = events.splice(0);
    const resent = await request("owner", "invite-member", { ...body, resend: true });
    const resendEvents = events.splice(0);
    const found = await request("recipient", "get-invitation", undefined, { id: created.body.id });
    const listed = await request("owner", "list-invitations", undefined, { organizationId: "org" });
    const received = await request("recipient", "list-user-invitations");
    const full = await request("owner", "get-full-organization", undefined, { organizationId: "org" });
    const rows = await adapter.findMany({ model: "invitation" });
    return {
      backend, mode,
      create: { status: created.status, body: invitation(created.body), events: createEvents },
      resend: { status: resent.status, body: invitation(resent.body), events: resendEvents },
      get: { status: found.status, body: invitation(found.body) },
      list: { status: listed.status, body: listed.body.map(invitation) },
      received: { status: received.status, body: received.body.map(invitation) },
      full: { status: full.status, invitations: full.body.invitations.map(invitation) },
      onePersistedInvitation: rows.length === 1,
      sameInvitation: rows.length === 1 && rows[0].id === created.body.id && resent.body.id === created.body.id,
    };
  } finally { database?.close(); }
}

if (import.meta.main) {
  const cases = [];
  for (const backend of ["memory", "sqlite"] as const) for (const mode of modes) cases.push(await capture(backend, mode));
  console.log(JSON.stringify({ version: "1.7.6", cases }, null, 2));
}
