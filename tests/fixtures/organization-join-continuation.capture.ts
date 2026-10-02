import { Database } from "bun:sqlite";

const modules = `${import.meta.dir}/../../compat-tests/reference-server/node_modules`;
const { betterAuth } = await import(`${modules}/better-auth/dist/index.mjs`);
const { organization } = await import(`${modules}/better-auth/dist/plugins/organization/index.mjs`);
const { getOrgAdapter } = await import(`${modules}/better-auth/dist/plugins/organization/adapter.mjs`);
const { getMigrations } = await import(`${modules}/better-auth/dist/db/get-migration.mjs`);
const { APIError } = await import(`${modules}/better-auth/dist/api/index.mjs`);

type Kind = "organization" | "team";
type Mode = "sync" | "async" | "read" | "parent-error" | "output-error" | "parent-async" | "parent-read";
export const observations: unknown[] = [];

export async function capture(backend: string, kind: Kind, mode: Mode) {
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const events: unknown[] = [];
  const started = [Promise.withResolvers<void>(), Promise.withResolvers<void>()];
  const released = [Promise.withResolvers<void>(), Promise.withResolvers<void>()];
  const secondFinished = Promise.withResolvers<void>();
  let enabled = false;
  let sequence = 0;
  let adapter: any;
  const failure = new APIError("BAD_REQUEST", { code: "ORDINARY_FIELD_FAILURE", message: "Ordinary display callback failed" });
  function record(field: string, value: unknown) {
    events.push([field, value]);
    return `${value}:${++sequence}`;
  }
  const first = (value: unknown) => {
    if (!enabled) return value;
    if (mode === "sync") return record("name", value);
    return (async () => {
      events.push(["name", value]);
      const row = value === "A" ? 0 : 1;
      if (mode === "async") {
        started[row].resolve();
        await released[row].promise;
      }
      if (mode === "read" && value === "A") {
        await adapter.update({ model: kind, where: [{field: "id", value: `${kind}-b`}], update: {name: "B-after"} });
        events.push(["display-update", "B-after"]);
      }
      if (mode === "output-error" && value === "A") throw failure;
      return `${value}-visible`;
    })();
  };
  const second = (value: unknown) => {
    if (!enabled) return value;
    events.push(["detail", value]);
    if (value === "B-detail") secondFinished.resolve();
    return mode === "sync" ? `${value}:${++sequence}` : `${value}-visible`;
  };
  const parent = (value: unknown) => {
    if (!enabled) return value;
    events.push(["member", value]);
    if (mode === "parent-error" && value === "A-member") throw failure;
    if (mode === "parent-async") return (async () => {
      const row = value === "A-member" ? 0 : 1;
      started[row].resolve();
      await released[row].promise;
      return value;
    })();
    if (mode === "parent-read" && value === "A-member") return (async () => {
      await adapter.update({ model: "organization", where: [{field: "id", value: "organization-a"}], update: {name: "A-before"} });
      events.push(["member-display-update", "A-before"]);
      return value;
    })();
    return value;
  };
  const schema = {
    organization: { additionalFields: kind === "organization" ? {
      name: {type: "string", required: true, transform: {output: first}},
      logo: {type: "string", required: false, transform: {output: second}},
    } : {} },
    team: { additionalFields: kind === "team" ? {
      name: {type: "string", required: true, transform: {output: first}},
      label: {type: "string", required: false, transform: {output: second}},
    } : {} },
    member: {additionalFields: {label: {type: "string", required: false, transform: {output: parent}}}},
  };
  const plugin = {teams: {enabled: true}, schema};
  const options = { database, baseURL: "http://ordinary-join.test", secret: "ordinary-join-secret-at-least-thirty-two-characters",
    telemetry: {enabled: false}, logger: {disabled: true}, plugins: [organization(plugin)] };
  try {
    if (database) await (await getMigrations(options)).runMigrations();
    const auth = betterAuth(options);
    const context = await auth.$context;
    adapter = context.adapter;
    const org = getOrgAdapter(context, plugin);
    const createdAt = new Date("2025-01-01T00:00:00.000Z");
    const create = (model: string, data: unknown) => adapter.create({model, forceAllowId: true, data: {createdAt, updatedAt: createdAt, ...data as any}});
    await create("user", {id: "owner", name: "Ordinary Owner", email: "owner@ordinary-join.test", emailVerified: true});
    for (const label of ["A", "B"]) {
      const suffix = label.toLowerCase();
      await create("organization", {id: `organization-${suffix}`, name: label, slug: `ordinary-${suffix}`, logo: `${label}-detail`});
      await create("member", {id: `member-${suffix}`, organizationId: `organization-${suffix}`, userId: "owner", role: "member", label: `${label}-member`});
      await create("team", {id: `team-${suffix}`, organizationId: "organization-a", name: label, label: `${label}-detail`, memberCount: 1});
      await create("teamMember", {id: `team-member-${suffix}`, teamId: `team-${suffix}`, userId: "owner", membershipKey: `ordinary-membership-${suffix}`});
    }
    enabled = true;
    let originalError = false;
    const pending = (kind === "organization" ? org.listOrganizations("owner") : org.listTeamsByUser({userId: "owner"}))
      .then((rows: any[]) => ({rows: rows.map(row => ({name: row.name, detail: kind === "organization" ? row.logo : row.label}))}))
      .catch((error: any) => { originalError = error === failure; return {error: {status: error.status, code: error.body?.code, message: error.body?.message}}; });
    if (mode === "async" || mode === "parent-async") {
      await Promise.all(started.map(signal => signal.promise));
      events.push(["controller", "both-started"]);
      released[1].resolve();
      await secondFinished.promise;
      events.push(["controller", "release-first"]);
      released[0].resolve();
    }
    const result = await pending;
    // Started peer rows may finish after rejection; wait for their actual callback completion.
    if (mode === "parent-error" || mode === "output-error") await secondFinished.promise;
    enabled = false;
    const stored = await adapter.findMany({model: kind, sortBy: {field: "name", direction: "asc"}});
    observations.push({backend, kind, mode, events, result, originalError,
      stored: stored.map((row: any) => ({name: row.name, detail: kind === "organization" ? row.logo : row.label}))});
  } finally { database?.close(); }
}
if (import.meta.main) {
  for (const backend of ["memory", "sqlite"]) for (const kind of ["organization", "team"] as const) {
    for (const mode of ["sync", "async", "read", "output-error"] as const) await capture(backend, kind, mode);
    if (kind === "organization") for (const mode of ["parent-error", "parent-async", "parent-read"] as const) await capture(backend, kind, mode);
  }
  console.log(JSON.stringify({version: "1.7.6", joins: "default-fallback", cases: observations}, null, 2));
}
