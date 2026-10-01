import { betterAuth } from "better-auth";
import { multiSession } from "better-auth/plugins";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { Database } from "bun:sqlite";
import { createHmac } from "node:crypto";

const secret = "multi-session-query-secret-at-least-32-characters";
const sign = (token: string) => encodeURIComponent(`${token}.${createHmac("sha256", secret).update(token).digest("base64")}`);
const cookie = ["b", "c", "a", "d"].map(token => `better-auth.session_token_multi-${token}=${sign(token)}`).concat(`better-auth.session_token=${sign("d")}`).join("; ");
const results = [];
for (const backend of ["memory", "sqlite", "secondary"]) {
  for (const limit of [0, 1, 2, 100]) {
    for (const expired of [false, true]) {
     for (const missing of backend === "memory" ? [false, true] : [false]) {
      const rows: Record<string, any[]> = {user: [], session: [], account: [], verification: []};
      const database = backend === "sqlite" ? new Database(":memory:") : undefined;
      const cache = new Map<string, string>();
      const options = {
        database: database ?? memoryAdapter(rows), baseURL: "http://multi.test", secret,
        logger: { disabled: true }, advanced: { database: {defaultFindManyLimit: limit} },
        secondaryStorage: backend === "secondary" ? {
          get: async (key: string) => cache.get(key) ?? null,
          set: async (key: string, value: string) => { cache.set(key, value); },
          delete: async (key: string) => { cache.delete(key); },
        } : undefined,
        session: {storeSessionInDatabase: true}, plugins: [multiSession()],
      };
      if (database) await (await getMigrations(options)).runMigrations();
      const auth = betterAuth(options);
      const context = await auth.$context;
      for (const name of ["c", "a", "b", "d"]) {
        const user = await context.adapter.create({model: "user", data: {
          name, email: `${name}@example.test`, emailVerified: true,
          createdAt: new Date("2020-01-01"), updatedAt: new Date("2020-01-01"),
        }});
        const session = await context.adapter.create({model: "session", data: {
          userId: user.id, token: name, expiresAt: new Date(expired && name === "a" ? "2000-01-01" : "2099-01-01"),
          createdAt: new Date("2020-01-01"), updatedAt: new Date("2020-01-01"),
        }});
        cache.set(name, JSON.stringify({session, user}));
      }
      if (missing) await context.adapter.update({model: "session", where: [{field: "token", value: "c"}], update: {userId: "missing"}});
      // A cache miss and malformed cache data must not read the stored session.
      if (backend === "secondary") {
        cache.delete("c");
        cache.set("b", "invalid json");
      }
      const list = await auth.api.listDeviceSessions({headers: new Headers({cookie})});
      const revoked = await auth.api.revokeDeviceSession({headers: new Headers({cookie}),body: {sessionToken:"d"},returnHeaders:true});
      const sessionCookie = revoked.headers.getSetCookie().find(value => value.startsWith("better-auth.session_token="));
      const active = sessionCookie ? decodeURIComponent(sessionCookie.split(";",1)[0].split("=")[1]).split(".")[0] : null;
      results.push({backend, limit, expired, missing, listed:list.map(value=>value.session.token), revoked:revoked.response, active});
      database?.close();
     }
    }
  }
}
await Bun.write(process.argv[2] ?? "/dev/stdout", JSON.stringify(results, null, 2) + "\n");
