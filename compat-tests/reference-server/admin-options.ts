import { admin } from "better-auth/plugins";
import { createAccessControl } from "better-auth/plugins/access";
import { APIError } from "better-auth/api";

const actions = ["create", "list", "get", "update", "set-role", "ban", "set-email", "impersonate", "impersonate-admins"] as const;
const ac = createAccessControl({ user: actions, session: ["list", "revoke", "delete"] });
const grants = {
  editor: ["create", "get", "update", "impersonate"],
  manager: ["create", "get", "update", "set-role", "ban", "set-email", "impersonate", "impersonate-admins"],
  admin: [...actions],
  user: [],
};

export function createAdminOptionsFixture(profile: string) {
  const enabled = ["admin-default-options", "admin-empty-roles", "admin-options"].includes(profile);
  let mode = "";
  let afterMode = "";
  const events: any[] = [];
  const options: any = profile === "admin-empty-roles" ? { roles: {} } : profile === "admin-options" ? {
    ac,
    adminRoles: ["admin"],
    roles: Object.fromEntries(Object.entries(grants).map(([name, user]) => [name, ac.newRole({ user })])),
    async bannedUserMessage(user: any) {
      await Promise.resolve();
      events.push({ event: "banned-message", email: user.email, reason: user.banReason, secretNote: user.secretNote });
      if (mode === "api-error") throw new APIError("BAD_REQUEST", { code: "ADMIN_CALLBACK_REJECTED", message: "Admin callback rejected" });
      if (mode === "ordinary-error") throw new Error("private admin callback failure");
      return `Blocked: ${user.email}/${user.secretNote}`;
    },
  } : {};
  return {
    plugin: enabled ? admin(options) : undefined,
    userFields: enabled ? { secretNote: { type: "string", returned: false, defaultValue: "admin-hidden" } } : {},
    databaseHooks: enabled ? { user: { update: { async after(user: any, ctx: any) {
      if (ctx?.path !== "/admin/update-user" || ctx.body.data.banned !== true) return;
      const sessions = await ctx.context.internalAdapter.listSessions(user.id);
      events.push({ event: "user-updated", banned: user.banned, sessions: sessions.length });
      if (afterMode === "reject") throw new APIError("BAD_REQUEST", { code: "AFTER_UPDATE_REJECTED", message: "After update rejected" });
    } } } } : undefined,
    reset() { mode = ""; afterMode = ""; events.length = 0; },
    async route(request: Request, auth: any): Promise<Response | null> {
      if (new URL(request.url).pathname !== "/__test/admin-options" || request.method !== "POST") return null;
      const body = await request.json();
      if (typeof body.mode === "string") mode = body.mode;
      if (typeof body.afterMode === "string") afterMode = body.afterMode;
      if (body.clear) events.length = 0;
      if (body.action === "validate") {
        try { admin(body.options); return Response.json({ valid: true }); }
        catch (error: any) { return Response.json({ valid: false, message: error.message }); }
      }
      if (body.action === "native-create" || body.action === "native-sign-in") {
        try {
          const api = body.action === "native-create" ? auth.api.createUser : auth.api.signInEmail;
          const result = await api({ body: body.input, ...(Object.hasOwn(body, "headers") ? { headers: new Headers(body.headers) } : {}) });
          return Response.json({ result });
        } catch (error: any) {
          return Response.json({ error: typeof error.statusCode === "number"
            ? { kind: "api", status: error.statusCode, body: error.body ?? null }
            : { kind: "error", message: error.message } });
        }
      }
      const ctx = await auth.$context;
      let user = body.email ? (await ctx.internalAdapter.findUserByEmail(body.email))?.user : null;
      if (user && body.patch) user = await ctx.internalAdapter.updateUser(user.id, {
        ...body.patch,
        ...(body.patch.banExpires ? { banExpires: new Date(body.patch.banExpires) } : {}),
      });
      const sessions = user ? await ctx.internalAdapter.listSessions(user.id) : [];
      return Response.json({ events, user: user ? { email: user.email, role: user.role, name: user.name, banned: user.banned, banReason: user.banReason, hasBanExpires: !!user.banExpires, secretNote: user.secretNote } : null, sessions: sessions.length });
    },
  };
}
