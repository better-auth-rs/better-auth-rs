const modules = `${import.meta.dir}/../../compat-tests/reference-server/node_modules`;
const { betterAuth } = await import(`${modules}/better-auth/dist/index.mjs`);
const { organization } = await import(`${modules}/better-auth/dist/plugins/organization/index.mjs`);
const { getOrgAdapter } = await import(`${modules}/better-auth/dist/plugins/organization/adapter.mjs`);
const { memoryAdapter } = await import(`${modules}/@better-auth/memory-adapter/dist/index.mjs`);
const { APIError } = await import(`${modules}/better-auth/dist/api/index.mjs`);

type Path = "member-org" | "member-id" | "full" | "organizations" | "invitations";
type Mode = "read" | "wait" | "error";
export const cases = (["member-org", "member-id", "full", "organizations", "invitations"] as Path[])
  .flatMap(path => (["read", "wait", "error"] as Mode[]).map(mode => ({ path, mode })));

export async function capture(joins: boolean, spec: { path: Path; mode: Mode }) {
  const { path, mode } = spec;
  const database: Record<string, any[]> = {};
  const events: unknown[] = [];
  const blocked = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const peerFinished = Promise.withResolvers<void>();
  let enabled = false;
  let changed = false;
  let adapter: any;
  const failure = new APIError("BAD_REQUEST", {
    code: "ORDINARY_PARENT_DISPLAY_FAILURE", message: "Ordinary parent display callback failed",
  });
  const parent = path === "full" ? "organization.name"
    : path === "invitations" ? "invitation.label" : "member.label";
  const first = path === "full" ? "O-A" : path === "invitations" ? "I-A" : "M-A";
  const isList = path === "organizations" || path === "invitations";

  function injectDetail() {
    changed = true;
    const model = path === "invitations" ? "invitation" : "member";
    const detail = path === "invitations" ? "I-A-detail-after" : "M-A-detail-after";
    const row = database[model].find(row => row.id === `${model}-a`);
    if (!row) throw new Error("Missing ordinary parent fixture");
    // Change only display data in the explicitly supplied Memory database.
    row.detail = detail;
    events.push(["display-write", model, { detail }]);
  }
  async function updateLogo() {
    changed = true;
    await adapter.update({ model: "organization", where: [{ field: "id", value: "organization-a" }],
      update: { logo: "O-A-logo-after" } });
    events.push(["display-write", "organization", { logo: "O-A-logo-after" }]);
  }
  async function updateDisplay() {
    if (path === "full") await updateLogo();
    else injectDetail();
  }
  function field(model: string, key: string) {
    const name = `${model}.${key}`;
    return { type: "string", required: false, transform: { output(value: unknown) {
      if (!enabled) return value;
      events.push([name, value]);
      if (name === "organization.logo" && value === "O-B-logo") peerFinished.resolve();
      const visible = () => `${value}-visible`;
      if (name === parent && value === first && !changed) {
        if (mode === "read") {
          if (path === "full") return updateLogo().then(visible);
          injectDetail();
        } else {
          blocked.resolve();
          return release.promise.then(() => {
            if (mode === "error") throw failure;
            return visible();
          });
        }
      }
      return visible();
    } } };
  }
  const plugin = {
    schema: {
      organization: { additionalFields: { name: field("organization", "name"), logo: field("organization", "logo") } },
      member: { additionalFields: { label: field("member", "label"), detail: field("member", "detail") } },
      invitation: { additionalFields: { label: field("invitation", "label"), detail: field("invitation", "detail") } },
    },
  };
  const context = await betterAuth({
    database: memoryAdapter(database), baseURL: "http://ordinary-parent.test",
    secret: "ordinary-parent-display-secret-at-least-thirty-two-characters",
    telemetry: { enabled: false }, logger: { disabled: true }, rateLimit: { enabled: false },
    advanced: { database: { joins, defaultFindManyLimit: 2 } },
    user: { additionalFields: { name: field("user", "name"), image: field("user", "image") } },
    plugins: [organization(plugin)],
  }).$context;
  adapter = context.adapter;
  const org = getOrgAdapter(context, plugin);
  const createdAt = new Date("2025-01-01T00:00:00.000Z");
  const create = (model: string, data: object) => adapter.create({ model, forceAllowId: true,
    data: { createdAt, updatedAt: createdAt, ...data } });
  await create("user", { id: "user-a", name: "U-A", image: "U-A-image",
    email: "a@ordinary-parent.test", emailVerified: true });
  for (const label of ["A", "B"]) {
    const suffix = label.toLowerCase();
    await create("organization", { id: `organization-${suffix}`, name: `O-${label}`,
      slug: `ordinary-${suffix}`, logo: `O-${label}-logo` });
    await create("member", { id: `member-${suffix}`, organizationId: `organization-${suffix}`,
      userId: "user-a", role: "member", label: `M-${label}`, detail: `M-${label}-detail` });
    await create("invitation", { id: `invitation-${suffix}`, organizationId: `organization-${suffix}`,
      email: "recipient@ordinary-parent.test", role: "member", status: "pending", inviterId: "user-a",
      expiresAt: new Date("2099-01-01T00:00:00.000Z"), label: `I-${label}`, detail: `I-${label}-detail` });
  }
  const parentMember = (row: any) => ({ label: row.label, detail: row.detail,
    user: { name: row.user.name, image: row.user.image } });
  async function query() {
    if (path === "member-org") return parentMember(await org.findMemberByOrgId({ organizationId: "organization-a", userId: "user-a" }));
    if (path === "member-id") return parentMember(await org.findMemberById("member-a"));
    if (path === "organizations") return (await org.listOrganizations("user-a")).map((row: any) => ({ name: row.name, logo: row.logo }));
    if (path === "invitations") return (await org.listUserInvitations("RECIPIENT@ordinary-parent.test"))
      .map((row: any) => ({ label: row.label, detail: row.detail, organizationName: row.organizationName }));
    const row = await org.findFullOrganization({ organizationId: "organization-a", includeTeams: false });
    return { name: row.name, logo: row.logo, members: row.members.map(parentMember),
      invitations: row.invitations.map((row: any) => ({ label: row.label, detail: row.detail })) };
  }
  enabled = true;
  let originalError = false;
  const pending = query().then(result => ({ result })).catch((error: any) => {
    if (error !== failure) throw error;
    originalError = true;
    return { error: { status: error.status, code: error.body?.code, message: error.body?.message } };
  });
  if (mode !== "read") {
    await blocked.promise;
    if (isList) await peerFinished.promise;
    events.push(["controller", isList ? "peer-finished" : "parent-blocked"]);
    await updateDisplay();
    release.resolve();
  }
  const result = await pending;
  enabled = false;
  return { joins, ...spec, events, ...result, originalError,
    stored: { memberDetail: database.member.find(row => row.id === "member-a").detail,
      invitationDetail: database.invitation.find(row => row.id === "invitation-a").detail,
      logo: database.organization.find(row => row.id === "organization-a").logo } };
}

if (import.meta.main) {
  const result = [];
  for (const joins of [false, true]) for (const spec of cases) result.push(await capture(joins, spec));
  console.log(JSON.stringify({ cases: result }, null, 2));
}
