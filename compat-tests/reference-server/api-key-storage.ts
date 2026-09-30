function memoryStorage() {
  const entries = new Map<string, { value: string; ttl: number | null; expires: number | null }>();
  let failure: string | null = null;
  let release: (() => void) | undefined;
  let blocked: Promise<void> | undefined;
  const check = (operation: string, key: string) => {
    if (key.startsWith("api-key:") && failure === operation) throw new Error("compat secondary storage failure");
  };
  return {
    async get(key: string) {
      check("get", key);
      const entry = entries.get(key);
      if (!entry || (entry.expires !== null && entry.expires <= Date.now())) return null;
      return entry.value;
    },
    async set(key: string, value: string, ttl?: number) {
      check("set", key);
      if (key.startsWith("api-key:") && blocked) await blocked;
      entries.set(key, { value, ttl: ttl ?? null, expires: ttl === undefined ? null : Date.now() + ttl * 1000 });
    },
    async delete(key: string) { check("delete", key); entries.delete(key); },
    control(body: any) {
      if (body.action === "failure") failure = body.operation ?? null;
      if (body.action === "evict") for (const key of entries.keys()) if (key.startsWith("api-key:")) entries.delete(key);
      if (body.action === "delete") entries.delete(body.key);
      if (body.action === "put") entries.set(body.key, { value: body.value, ttl: null, expires: null });
      if (body.action === "block") {
        if (body.blocked) blocked = new Promise<void>((resolve) => { release = resolve; });
        else { release?.(); blocked = undefined; release = undefined; }
      }
      return [...entries].filter(([key, entry]) => key.startsWith("api-key:") && (entry.expires === null || entry.expires > Date.now()))
        .map(([key, entry]) => ({ key, value: entry.value, ttl: entry.ttl }));
    },
    reset() { release?.(); release = undefined; blocked = undefined; failure = null; entries.clear(); },
  };
}

export function createApiKeyStorageFixture() {
  const global = memoryStorage();
  const custom = memoryStorage();
  const enabled = process.env.COMPAT_PROFILE === "api-key-storage";
  const configurations = enabled ? [
    { configId: "cache", storage: "secondary-storage" as const, enableMetadata: true, keyExpiration: { minExpiresIn: 0 } },
    { configId: "fallback", storage: "secondary-storage" as const, fallbackToDatabase: true, enableMetadata: true },
    { configId: "custom", storage: "secondary-storage" as const, customStorage: custom, enableMetadata: true },
    { configId: "custom-fallback", storage: "secondary-storage" as const, customStorage: custom, fallbackToDatabase: true },
    { configId: "deferred", storage: "secondary-storage" as const, deferUpdates: true },
    { configId: "database-custom", storage: "database" as const, customStorage: custom },
  ] : [];
  return {
    enabled, configurations,
    secondaryStorage: enabled ? global : undefined,
    reset() { global.reset(); custom.reset(); },
    async handle(request: Request, auth: any): Promise<Response | null> {
      if (!enabled || new URL(request.url).pathname !== "/__test/api-key-storage" || request.method !== "POST") return null;
      const body = await request.json();
      const entries = (body.backend === "custom" ? custom : global).control(body);
      const context = await auth.$context;
      if (body.action === "delete-database") await context.adapter.delete({ model: "apikey", where: [{ field: "id", value: body.id }] });
      const rows = body.referenceId ? await context.adapter.findMany({ model: "apikey", where: [{ field: "referenceId", value: body.referenceId }] }) : [];
      return Response.json({ entries, rows });
    },
  };
}
