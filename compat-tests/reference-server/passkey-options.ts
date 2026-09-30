import { APIError } from "better-auth/api";
import type { PasskeyOptions } from "@better-auth/passkey";

export function createPasskeyOptions(profile: string) {
  const enabled = profile.startsWith("passkey-");
  let events: unknown[] = [];
  let control: Record<string, any> = {};
  const fail = (mode: unknown) => {
    if (mode === "api-error") throw APIError.from("FORBIDDEN", { code: "PASSKEY_CALLBACK_REJECTED", message: "Passkey callback rejected" });
    if (mode === "error") throw new Error("Passkey callback failed");
  };
  const endpoint = (ctx: any) => ({ path: ctx.path, hasRequest: Boolean(ctx.request), context: ctx.query?.context ?? null });
  const options: PasskeyOptions | undefined = enabled ? {
    rpID: "localhost", origin: ["https://passkeys.example", "https://secondary.example"],
    advanced: { webAuthnChallengeCookie: "ceremony" },
    authenticatorSelection: { authenticatorAttachment: "platform", residentKey: "required", userVerification: "required" },
    registration: {
      requireSession: profile !== "passkey-first" && profile !== "passkey-no-resolver",
      ...(profile !== "passkey-no-resolver" ? { resolveUser: async ({ ctx, context }: any) => {
        events.push({ event: "resolve", ...endpoint(ctx), context });
        fail(control.resolveMode);
        return { id: control.userId ?? "provisional-user", name: control.invalidUser ? "" : "Resolved User", displayName: "Resolved Display" };
      } } : {}),
      extensions: async ({ ctx }) => {
        events.push({ event: "registration.extensions", ...endpoint(ctx) });
        fail(control.extensionsMode);
        return control.noExtensions ? undefined : { credProps: false, largeBlob: { support: "preferred" } };
      },
      afterVerification: async ({ ctx, user, verification, clientData, context }) => {
        const info = verification.registrationInfo!;
        events.push({ event: "registration.verified", ...endpoint(ctx), context, user,
          verified: verification.verified, name: ctx.body.name ?? null, createSession: ctx.body.createSession ?? null,
          info: { fmt: info.fmt, aaguid: info.aaguid, credentialID: info.credential.id, counter: info.credential.counter,
            publicKeyLength: info.credential.publicKey.length, attestationLength: info.attestationObject.length,
            credentialType: info.credentialType, userVerified: info.userVerified, deviceType: info.credentialDeviceType,
            backedUp: info.credentialBackedUp, origin: info.origin, rpID: info.rpID, transports: info.credential.transports },
          clientID: clientData.id,
        });
        if (control.createUser) {
          const { banned, banExpires, ...input } = control.createUser;
          const created = await ctx.context.internalAdapter.createUser(input);
          if (typeof banned === "boolean") await ctx.context.internalAdapter.updateUser(created.id, { banned, ...(banExpires ? { banExpires: new Date(banExpires) } : {}) });
          if (control.updateUserName) {
            const found = await ctx.context.internalAdapter.findUserByEmail(control.createUser.email);
            const updated = await ctx.context.internalAdapter.updateUser(created.id, { name: control.updateUserName });
            events.push({ event: "users", found: found?.user.id === created.id, name: updated.name });
          }
          if (control.deleteTemporary) {
            const temporary = await ctx.context.internalAdapter.createUser({ ...control.createUser, id: "temporary-user", email: `temporary-${control.createUser.email}` });
            await ctx.context.internalAdapter.deleteUser(temporary.id);
            events.push({ event: "users.deleted", missing: !(await ctx.context.internalAdapter.findUserById(temporary.id)) });
          }
        }
        fail(control.registrationMode);
        return { userId: control.targetUserId, name: control.hookName ?? "  Hook Key  " };
      },
    },
    authentication: {
      extensions: { uvm: true },
      afterVerification: async ({ ctx, verification, clientData }) => {
        events.push({ event: "authentication.verified", ...endpoint(ctx), verified: verification.verified,
          info: verification.authenticationInfo, clientID: clientData.id });
        fail(control.authenticationMode);
      },
    },
  } : undefined;
  return {
    enabled, options,
    authOptions: enabled ? {
      appName: "Passkey Configuration",
      ...(profile === "passkey-stale" ? { session: { freshAge: -1 } } : {}),
      databaseHooks: { session: { create: {
        before: async () => {
          events.push({ event: "session.before" });
          if (control.failSession) throw APIError.from("FORBIDDEN", { code: "SESSION_REJECTED", message: "Session rejected" });
        },
        after: async () => { events.push({ event: "session.after" }); },
      } } },
    } : {},
    reset() { events = []; control = {}; },
    async route(request: Request, auth: any): Promise<Response | null> {
      if (!enabled || new URL(request.url).pathname !== "/__test/passkey-options") return null;
      if (request.method === "POST") {
        const body = await request.json();
        control = { ...control, ...body };
        if (body.clear !== false) events = [];
      }
      const userId = new URL(request.url).searchParams.get("userId");
      if (userId) {
        const ctx = await auth.$context;
        return Response.json({ user: Boolean(await ctx.internalAdapter.findUserById(userId)), passkeys: await ctx.adapter.findMany({ model: "passkey", where: [{ field: "userId", value: userId }] }), events });
      }
      return Response.json({ events });
    },
  };
}
