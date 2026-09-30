import { runWithTransaction } from "@better-auth/core/context";

export function createSecondaryStorageFixture(profile: string, database: any) {
  const enabled = profile.startsWith("secondary-") || profile.startsWith("session-fields") || profile === "verification-identifiers";
  const useSecondary = profile !== "verification-identifiers" && profile !== "session-fields";
  const storeSession = profile !== "secondary-session-only" && profile !== "session-fields-cache";
  const preserve = profile === "secondary-session-preserved";
  const storeVerification = profile !== "secondary-verification-only";
  const entries = new Map<string, { value: string; expires: number | null; ttl: number | null }>();
  let failure: string | null = null;
  const events: string[] = [];
  function check(operation: string) {
    if (failure === operation) throw new Error(`secondary ${operation} failed`);
  }
  const storage = {
    async get(key: string) {
      check("get");
      const entry = entries.get(key);
      return entry && (entry.expires === null || entry.expires > Date.now()) ? entry.value : null;
    },
    async set(key: string, value: string, ttl?: number) {
      check("set");
      entries.set(key, { value, ttl: ttl ?? null, expires: ttl === undefined ? null : Date.now() + ttl * 1000 });
    },
    async delete(key: string) { check("delete"); entries.delete(key); },
    async getAndDelete(key: string) {
      check("getAndDelete");
      const entry = entries.get(key);
      entries.delete(key);
      return entry && (entry.expires === null || entry.expires > Date.now()) ? entry.value : null;
    },
  };
  const hooks = (model: string) => ({
    create: { before: async () => { events.push(`${model}.create.before`); }, after: async () => { events.push(`${model}.create.after`); } },
    delete: { before: async () => { events.push(`${model}.delete.before`); }, after: async () => { events.push(`${model}.delete.after`); } },
  });
  return {
    enabled,
    options: enabled ? {
      ...(useSecondary ? { secondaryStorage: storage } : {}),
      session: { storeSessionInDatabase: storeSession, preserveSessionInDatabase: preserve, additionalFields: {
        deviceLabel: { type: "string" as const, required: false },
        internalNote: { type: "string" as const, required: false, returned: false, input: false },
      } },
      verification: { storeInDatabase: storeVerification, storeIdentifier: { default: "plain" as const, overrides: {
        "hash:": "hashed" as const,
        "reset-password:": "hashed" as const,
        "custom:": { hash: async (identifier: string) => `custom-${identifier}` },
        "custom:specific:": "plain" as const,
      } } },
      databaseHooks: { session: hooks("session"), verification: hooks("verification") },
    } : {},
    skipResetModel(model: string) { return enabled && ((model === "session" && !storeSession) || (model === "verification" && !storeVerification)); },
    reset() { entries.clear(); events.length = 0; failure = null; },
    async route(request: Request, auth: any) {
      if (!enabled || new URL(request.url).pathname !== "/__test/secondary") return null;
      const body = await request.json();
      const context = await auth.$context;
      const adapter = context.internalAdapter;
      if (body.action === "failure") failure = body.operation;
      if (body.action === "evict") entries.delete(body.key);
      if (body.action === "put") await storage.set(body.key, body.value);
      if (body.action === "clear-events") events.length = 0;
      if (body.action === "database-user-name") await context.adapter.update({ model: "user", where: [{ field: "id", value: body.userId }], update: { name: body.name } });
      if (body.action === "seed-verification") {
        const now = new Date();
        const row = { id: body.id, identifier: body.identifier, value: body.value, expiresAt: new Date(Date.now() + (body.seconds ?? 60) * 1000), createdAt: now, updatedAt: now };
        if (storeVerification) await context.adapter.create({ model: "verification", data: row, forceAllowId: true });
        if (useSecondary) await storage.set(`verification:${body.identifier}`, JSON.stringify(row));
        return Response.json({ ok: true });
      }
      if (body.action === "create-verification") {
        const row = await adapter.createVerificationValue({ identifier: body.identifier, value: body.value, expiresAt: new Date(Date.now() + (body.seconds ?? 60) * 1000) });
        return Response.json(row);
      }
      if (body.action === "find-verification") return Response.json(await adapter.findVerificationValue(body.identifier));
      if (body.action === "update-verification") { await adapter.updateVerificationByIdentifier(body.identifier, { value: body.value }); return Response.json({ ok: true }); }
      if (body.action === "delete-verification") { await adapter.deleteVerificationByIdentifier(body.identifier); return Response.json({ ok: true }); }
      if (body.action === "consume-verification") return Response.json(await adapter.consumeVerificationValue(body.identifier));
      if (body.action === "reserve-verification") {
        try { return Response.json({ reserved: await adapter.reserveVerificationValue({ identifier: body.identifier, value: body.value, expiresAt: new Date(Date.now() + 60000) }) }); }
        catch (error) { return Response.json({ error: (error as Error).message }); }
      }
      if (body.action === "transaction-session") {
        try {
          await runWithTransaction(context.adapter, async () => {
            await adapter.createSession(body.userId, false, undefined, false, { deferSecondaryStorageWrites: true });
            if (body.rollback) throw new Error("secondary transaction rollback");
          });
          return Response.json({ committed: true });
        } catch (error) { return Response.json({ error: (error as Error).message }); }
      }
      if (body.action === "end-session") { await adapter.deleteSession(body.token); return Response.json({ ok: true }); }
      const count = (model: string, enabled: boolean) => enabled ? (database.query(`SELECT COUNT(*) AS count FROM "${model}"`).get() as { count: number }).count : 0;
      return Response.json({
        sessions: count("session", storeSession), verifications: count("verification", storeVerification),
        rows: storeSession ? database.query('SELECT token, expiresAt FROM "session"').all().map((row: any) => ({ token: row.token, live: new Date(row.expiresAt).getTime() > Date.now() })) : [],
        entries: [...entries].filter(([, value]) => value.expires === null || value.expires > Date.now()).map(([key, value]) => ({ key, value: value.value, ttl: value.ttl })).sort((a, b) => a.key.localeCompare(b.key)),
        events,
      });
    },
  };
}
