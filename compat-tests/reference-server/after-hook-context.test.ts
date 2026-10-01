import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { getCurrentAuthEndpointContext, queueAfterTransactionHook, runWithEndpointContext, runWithTransaction } from "@better-auth/core/context";

for (const backend of ["memory", "sqlite"] as const) {
  for (const outcome of ["commit", "rollback", "after-error"] as const) {
    test(`shared after context/${backend}/${outcome}`, async () => {
      const database = backend === "sqlite" ? new Database(":memory:") : undefined;
      const events: unknown[] = [];
      const capture = (phase: string, supplied: any) => {
        if (!supplied) return;
        const ambient: any = getCurrentAuthEndpointContext();
        events.push({ phase, supplied: supplied.path, ambient: ambient.path });
      };
      const options: any = {
        database, baseURL: "http://localhost:3000", secret: "after-hook-context-secret-at-least-thirty-two-characters",
        logger: { disabled: true }, rateLimit: { enabled: false },
        databaseHooks: { verification: {
          create: { after: (_: any, context: any) => capture("create", context) },
          update: { after: (_: any, context: any) => capture("update", context) },
          delete: { after: (_: any, context: any) => capture("delete", context) },
        }, user: {
          update: { after: (_: any, context: any) => capture("missing-user", context) },
          delete: { after: (_: any, context: any) => capture("user-delete", context) },
        }, account: { delete: { after: (_: any, context: any) => capture("account-delete", context) } },
        session: { delete: { after: (_: any, context: any) => capture("session-delete", context) } } },
      };
      if (database) await (await getMigrations(options)).runMigrations();
      const context = await betterAuth(options).$context;
      const user = await context.internalAdapter.createUser({ name: "Owner", email: "owner@example.com", emailVerified: false });
      await context.internalAdapter.createAccount({ userId: user.id, providerId: "fixture", accountId: "owner" });
      await context.internalAdapter.createSession(user.id);
      const outer: any = { path: "/flush-operation", body: { scope: "outer" }, context };
      const inner: any = { path: "/captured-operation", body: { scope: "inner" }, context };
      let error: string | null = null;
      try {
        await runWithEndpointContext(outer, () => runWithTransaction(context.adapter, () => runWithEndpointContext(inner, async () => {
          await context.internalAdapter.createVerificationValue({ identifier: "context", value: "original", expiresAt: new Date("2099-01-01") });
          await context.internalAdapter.updateVerificationByIdentifier("context", { value: "updated" });
          await context.internalAdapter.deleteVerificationByIdentifier("context");
          expect(await context.internalAdapter.updateUser("absent", { name: "unused" })).toBeNull();
          await context.internalAdapter.deleteUser(user.id);
          await queueAfterTransactionHook(async () => {
            capture("external", inner);
            if (outcome === "after-error") throw new Error("after-error");
          });
          await queueAfterTransactionHook(async () => capture("tail", inner));
          if (outcome === "rollback") throw new Error("rollback");
        })));
      } catch (caught: any) { error = caught.message; }
      expect(error).toBe(outcome === "commit" ? null : outcome);
      expect(events).toEqual((outcome === "rollback" ? [] : ["create", "update", "delete", "missing-user", "session-delete", "account-delete", "user-delete", "external", ...(outcome === "commit" ? ["tail"] : [])]).map(phase => ({
        phase, supplied: "/captured-operation", ambient: "/flush-operation",
      })));
      expect(await context.internalAdapter.findVerificationValue("context")).toBeNull();
      database?.close();
    });
  }
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const outcome of ["commit", "rollback", "after-error"] as const) {
    test(`secondary after context/${backend}/${outcome}`, async () => {
      const database = backend === "sqlite" ? new Database(":memory:") : undefined;
      const values = new Map<string, string>();
      const events: unknown[] = [];
      const capture = (phase: string, supplied: any) => {
        const ambient: any = getCurrentAuthEndpointContext();
        events.push({ phase, supplied: supplied.path, ambient: ambient.path });
      };
      const options: any = {
        database, baseURL: "http://localhost:3000", secret: "after-hook-context-secret-at-least-thirty-two-characters",
        logger: { disabled: true }, rateLimit: { enabled: false },
        secondaryStorage: {
          get: async (key: string) => values.get(key),
          set: async (key: string, value: string) => { values.set(key, value); },
          delete: async (key: string) => { values.delete(key); },
          getAndDelete: async (key: string) => { const value = values.get(key); values.delete(key); return value; },
        },
        databaseHooks: {
          verification: { create: { after: (_: any, context: any) => capture("create", context) } },
          session: { create: { after: (_: any, context: any) => capture("session-create", context) } },
        },
      };
      if (database) await (await getMigrations(options)).runMigrations();
      const context = await betterAuth(options).$context;
      const user = await context.internalAdapter.createUser({ name: "Owner", email: "owner@example.com", emailVerified: false });
      const outer: any = { path: "/flush-operation", context };
      const inner: any = { path: "/captured-operation", context };
      let error: string | null = null;
      try {
        await runWithEndpointContext(outer, () => runWithTransaction(context.adapter, () => runWithEndpointContext(inner, async () => {
          await context.internalAdapter.createVerificationValue({ identifier: "context", value: "original", expiresAt: new Date("2099-01-01") });
          await context.internalAdapter.createSession(user.id);
          await queueAfterTransactionHook(async () => {
            capture("external", inner);
            if (outcome === "after-error") throw new Error("after-error");
          });
          await queueAfterTransactionHook(async () => capture("tail", inner));
          if (outcome === "rollback") throw new Error("rollback");
        })));
      } catch (caught: any) { error = caught.message; }
      expect(error).toBe(outcome === "commit" ? null : outcome);
      expect(events).toEqual((outcome === "rollback" ? [] : ["create", "session-create", "external", ...(outcome === "commit" ? ["tail"] : [])]).map(phase => ({
        phase, supplied: "/captured-operation", ambient: "/flush-operation",
      })));
      // Both cache writes occur before commit, including the rollback case.
      expect(values.has("verification:context")).toBe(true);
      expect((await context.internalAdapter.listSessions(user.id)).length).toBe(1);
      database?.close();
    });
  }
}
