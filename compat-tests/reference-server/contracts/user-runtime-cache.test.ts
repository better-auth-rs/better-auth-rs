import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { cases, date, observe, options, owner, revive, user } from "./user-runtime-contract";

const { setCookieCache, decodeCookieCache } = await import(new URL("./cookies/index.mjs", import.meta.resolve("better-auth")).href);
const session = () => ({
  id: "runtime-session", userId: owner, token: "runtime-token",
  createdAt: new Date(date), updatedAt: new Date(date), expiresAt: new Date("2100-01-01T00:00:00.000Z"),
});

for (const sample of cases.cache) {
  test(`Secondary User cache ${sample.name} preserves values and only converts native dates`, async () => {
    const selected = { ...user(), [sample.field]: revive(sample.value) };
    const encoded = JSON.stringify({ session: session(), user: selected });
    const events: unknown[] = [];
    const auth = betterAuth({
      ...options({ user: [], session: [], account: [], verification: [] }),
      secondaryStorage: {
        async get(key: string) { events.push(["get", key]); return encoded; },
        async set(...args: unknown[]) { events.push(["set", ...args]); },
        async delete(key: string) { events.push(["delete", key]); },
      },
    });
    const { internalAdapter } = await auth.$context;
    const found = await internalAdapter.findSession("runtime-token");
    expect(found).not.toBeNull();
    const expected = "secondaryValue" in sample ? sample.secondaryValue : sample.value;
    expect(observe(found!.user[sample.field])).toStrictEqual(expected);
    expect(events).toStrictEqual([["get", "runtime-token"]]);
  });
}

for (const strategy of ["compact", "jwt", "jwe"] as const) {
  for (const sample of cases.cache) {
    test(`${strategy} User cookie cache ${sample.name} applies the upstream schema`, async () => {
      const auth = betterAuth({
        ...options({ user: [], session: [], account: [], verification: [] }),
        session: { cookieCache: { enabled: true, strategy } },
      });
      const context = await auth.$context;
      const cookies: { name: string; value: string }[] = [];
      const ctx = { context, headers: new Headers(), setCookie(name: string, value: string) { cookies.push({ name, value }); } };
      await setCookieCache(ctx, { session: session(), user: { ...user(), [sample.field]: revive(sample.value) } }, false);
      const cookie = cookies.find(cookie => cookie.name === context.authCookies.sessionData.name);
      expect(cookie).toBeDefined();
      const before = Date.now();
      const decoded = await decodeCookieCache(ctx, cookie!.value);
      const after = Date.now();
      expect(decoded !== null).toBe(strategy === "compact" && "compact" in sample ? sample.compact : sample.cookie);
      if (decoded) {
        const value = decoded.session.user[sample.field];
        if ("cookieDefaultDate" in sample) {
          expect(value).toBeInstanceOf(Date);
          expect(value.getTime()).toBeGreaterThanOrEqual(before);
          expect(value.getTime()).toBeLessThanOrEqual(after);
        } else {
          expect(observe(value)).toStrictEqual("cookieValue" in sample ? sample.cookieValue : undefined);
        }
      }
    });
  }
}
