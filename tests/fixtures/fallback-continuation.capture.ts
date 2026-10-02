import { Database } from "bun:sqlite";

const modules = `${import.meta.dir}/../../compat-tests/reference-server/node_modules`;
const { betterAuth } = await import(`${modules}/better-auth/dist/index.mjs`);
const { organization } = await import(`${modules}/better-auth/dist/plugins/organization/index.mjs`);
const { getOrgAdapter } = await import(`${modules}/better-auth/dist/plugins/organization/adapter.mjs`);
const { getMigrations } = await import(`${modules}/better-auth/dist/db/get-migration.mjs`);
const { APIError } = await import(`${modules}/better-auth/dist/api/index.mjs`);

type Kind = "session" | "invitation";
type Mode = "sync" | "async" | "read" | "parent-error" | "output-error" | "parent-async" | "parent-read";
export const observations: unknown[] = [];

export async function capture(backend: string, kind: Kind, mode: Mode) {
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const events: unknown[] = [];
  const started = [Promise.withResolvers<void>(), Promise.withResolvers<void>()];
  const released = [Promise.withResolvers<void>(), Promise.withResolvers<void>()];
  const secondFinished = Promise.withResolvers<void>();
  const child = kind === "session" ? "user" : "organization";
  let enabled = false;
  let sequence = 0;
  let adapter: any;
  const failure = new APIError("BAD_REQUEST", { code: "ORDINARY_FIELD_FAILURE", message: "Ordinary display callback failed" });
  const event = (field: string, value: unknown) => { events.push([field, value]); return ++sequence; };
  const display = (field: string, value: unknown) => {
    const index = event(field, value);
    return mode === "sync" ? `${value}:${index}` : `${value}-visible`;
  };
  const first = (value: unknown) => {
    if (!enabled) return value;
    if (mode === "sync") return display("name", value);
    return (async () => {
      event("name", value);
      if (mode === "async") {
        const row = value === "A" ? 0 : 1;
        started[row].resolve();
        await released[row].promise;
      }
      if (mode === "read" && value === "A") {
        await adapter.update({model: child, where: [{field: "id", value: `${child}-b`}], update: {name: "B-after"}});
        event("display-update", "B-after");
      }
      if (mode === "output-error" && value === "A") throw failure;
      return `${value}-visible`;
    })();
  };
  const second = (value: unknown) => {
    if (!enabled) return value;
    const result = display("detail", value);
    if (value === "B-detail") secondFinished.resolve();
    return result;
  };
  const parent = (value: unknown) => {
    if (!enabled) return value;
    if (mode === "parent-error" && value === "A-parent") { event("parent", value); throw failure; }
    if (mode === "parent-async" || mode === "parent-read") return (async () => {
      event("parent", value);
      if (mode === "parent-async") {
        const row = value === "A-parent" ? 0 : 1;
        started[row].resolve();
        await released[row].promise;
      }
      if (mode === "parent-read" && value === "A-parent") {
        await adapter.update({model: child, where: [{field: "id", value: `${child}-a`}], update: {name: "A-before"}});
        event("parent-display-update", "A-before");
      }
      return `${value}-visible`;
    })();
    return display("parent", value);
  };
  const parentDetail = (value: unknown) => enabled ? display("parent-detail", value) : value;
  const field = (output: (value: unknown) => unknown) => ({type: "string", required: false, transform: {output}});
  const childFields = {name: field(first), [kind === "session" ? "image" : "logo"]: field(second)};
  const parentFields = {label: field(parent), marker: field(parentDetail)};
  const plugin = {schema: {organization: {additionalFields: kind === "invitation" ? childFields : {}}, invitation: {additionalFields: parentFields}}};
  const options = {database, secret: "ordinary-fallback-at-least-thirty-two-characters", baseURL: "http://ordinary-fallback.test",
    telemetry: {enabled: false}, logger: {disabled: true},
    user: {additionalFields: kind === "session" ? childFields : {}},
    session: {additionalFields: parentFields}, plugins: [organization(plugin)]};
  try {
    if (database) await (await getMigrations(options)).runMigrations();
    const context = await betterAuth(options).$context;
    adapter = context.adapter;
    const org = getOrgAdapter(context, plugin);
    const createdAt = new Date("2025-01-01T00:00:00Z");
    const expiresAt = new Date("2099-01-01T00:00:00Z");
    const create = (model: string, data: unknown) => adapter.create({model, forceAllowId: true, data: {createdAt, updatedAt: createdAt, ...data as any}});
    for (const label of ["A", "B"]) {
      const suffix = label.toLowerCase();
      await create("user", {id: `user-${suffix}`, name: label, email: `${suffix}@ordinary-fallback.test`, image: `${label}-detail`, emailVerified: true});
      await create("organization", {id: `organization-${suffix}`, name: label, slug: `ordinary-${suffix}`, logo: `${label}-detail`});
      await create("session", {id: `session-${suffix}`, userId: `user-${suffix}`, token: `ordinary-session-${suffix}`, expiresAt, label: `${label}-parent`, marker: `${label}-marker`});
      await create("invitation", {id: `invitation-${suffix}`, organizationId: `organization-${suffix}`, inviterId: "user-a", email: "guest@ordinary-fallback.test", role: "member", status: "pending", expiresAt, label: `${label}-parent`, marker: `${label}-marker`});
    }
    enabled = true;
    let originalError = false;
    const pending = (kind === "session"
      ? context.internalAdapter.findSessions(["ordinary-session-b", "ordinary-session-a"])
      : org.listUserInvitations("GUEST@ordinary-fallback.test"))
      .then((rows: any[]) => ({rows: rows.map(row => kind === "session"
        ? {parent: row.session.label, parentDetail: row.session.marker, name: row.user.name, detail: row.user.image}
        : {parent: row.label, parentDetail: row.marker, name: row.organizationName})}))
      .catch((error: any) => { originalError = error === failure; return {error: {status: error.status, code: error.body?.code, message: error.body?.message}}; });
    if (mode === "async" || mode === "parent-async") {
      await Promise.all(started.map(signal => signal.promise));
      event("controller", "both-started");
      released[1].resolve();
      await secondFinished.promise;
      event("controller", "release-first");
      released[0].resolve();
    }
    const result = await pending;
    if (mode === "parent-error" || mode === "output-error") await secondFinished.promise;
    enabled = false;
    const stored = await adapter.findMany({model: child, sortBy: {field: "name", direction: "asc"}});
    return {backend, kind, mode, events, result, originalError,
      stored: stored.map((row: any) => ({name: row.name, detail: row[kind === "session" ? "image" : "logo"]}))};
  } finally { database?.close(); }
}

if (import.meta.main) {
  for (const backend of ["memory", "sqlite"]) for (const kind of ["session", "invitation"] as const) {
    for (const mode of ["sync", "async", "read", "parent-error", "output-error", "parent-async", "parent-read"] as const) {
      observations.push(await capture(backend, kind, mode));
    }
  }
  console.log(JSON.stringify({version: "1.7.6", joins: "default-fallback", cases: observations}, null, 2));
}
