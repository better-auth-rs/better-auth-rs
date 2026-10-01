import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";

type Options = {
  backend?: string;
  policy?: string;
  window?: string;
  max?: string;
  custom?: boolean;
  secondary?: boolean;
  disabledIp?: boolean;
};

export async function createRateLimitFixture(baseURL: string) {
  const database = new Database(":memory:");
  const counters = new Map<string, { count: number; expires: number }>();
  let events: unknown[] = [];
  let options: Options = {};
  const snapshotRule = (rule: { window: number; max: number }) => ({ window: String(rule.window), max: String(rule.max) });
  const secondaryStorage = {
    async get(_key: string) { return null; },
    async set(_key: string, _value: string, _ttl?: number) {},
    async delete(_key: string) {},
    async getAndDelete(_key: string) { return null; },
    async increment(key: string, ttl: number) {
      events.push({ kind: "increment", key, ttl: String(ttl) });
      const now = Date.now();
      const previous = counters.get(key);
      const entry = previous && now < previous.expires ? previous : { count: 0, expires: now + ttl * 1000 };
      entry.count++;
      counters.set(key, entry);
      return entry.count;
    },
  };
  async function build() {
    const rule = { window: Number(options.window ?? "10"), max: Number(options.max ?? "100") };
    const plugin = (index: number) => ({ id: `fixture-limit-${index}`, rateLimit: [{ window: 21 + index, max: 4 + index,
      pathMatcher(path: string) { events.push({ kind: "matcher", index, path }); return true; },
    }] });
    const customRules = options.policy === "numeric" ? { "/**": rule }
      : ["first", "disabled", "unchanged"].includes(options.policy ?? "") ? {
        "/**": async (request: Request, current: { window: number; max: number }) => {
          const url = new URL(request.url);
          events.push({ kind: "rule", path: url.pathname + url.search, ...snapshotRule(current) });
          await Promise.resolve();
          return options.policy === "disabled" ? false : options.policy === "unchanged" ? null : { window: 7.5, max: 1.5 };
        },
        "/ok": false,
      } : undefined;
    const secondary = options.secondary || ["secondary", "auto", "missing"].includes(options.backend ?? "");
    const { increment: _increment, ...missingIncrement } = secondaryStorage;
    const config = {
      database, baseURL, basePath: "/api/limits", secret: "rate-limit-fixture-secret-at-least-thirty-two-characters",
      advanced: { ipAddress: { disableIpTracking: options.disabledIp === true } },
      logger: { disabled: true },
      ...(secondary ? { secondaryStorage: options.backend === "missing" ? missingIncrement : secondaryStorage } : {}),
      plugins: ["plugins", "first", "disabled", "unchanged"].includes(options.policy ?? "") ? [plugin(0), plugin(1)] : [],
      rateLimit: {
        enabled: true, window: 10, max: 100,
        ...(options.backend === "auto" ? {} : { storage: ["secondary", "missing"].includes(options.backend ?? "") ? "secondary-storage" : options.backend ?? "memory" }),
        customRules,
        ...(options.custom ? { customStorage: { async consume(key: string, current: { window: number; max: number }) {
          events.push({ kind: "consume", key, ...snapshotRule(current) });
          return { allowed: false, retryAfter: null };
        } } } : {}),
      },
    };
    const auth = betterAuth(config as Parameters<typeof betterAuth>[0]);
    await auth.$context;
    return auth;
  }
  await (await getMigrations({ database, rateLimit: { storage: "database" } })).runMigrations();
  let auth = await build();
  return { async handle(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (["/health", "/__health"].includes(path)) return Response.json({ status: "ok" });
    if (path === "/__test/reset-state") {
      database.run('DELETE FROM "rateLimit"'); counters.clear(); events = []; options = {}; auth = await build();
      return Response.json({ success: true });
    }
    if (path === "/__test/rate-limit") {
      if (request.method === "POST") {
        const body = await request.json();
        if (body.config) options = body.config;
        if (body.clearEvents) events = [];
        if (body.config || body.restart) auth = await build();
      }
      return Response.json({ events, rows: database.query('SELECT key, count FROM "rateLimit" ORDER BY key').all() });
    }
    return auth.handler(request);
  } };
}
