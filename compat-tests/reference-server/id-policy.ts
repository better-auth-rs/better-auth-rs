import { betterAuth } from "better-auth";

export async function runIdPolicy(input: { mode: string; secondary: boolean }) {
  const calls: { model: string; size: number | null }[] = [];
  const cache = new Map<string, string>();
  const generateId = input.mode === "database" ? false : ({ model, size }: { model: string; size?: number }) => {
    calls.push({ model, size: size ?? null });
    if (input.mode === "callback-disabled") return false;
    return input.mode === "callback-empty" || input.mode === `${model}-missing` ? "" : `${model}-${calls.length}`;
  };
  const auth = betterAuth({
    baseURL: "http://localhost:3000", secret: "runtime-id-probe-secret-at-least-thirty-two-characters",
    logger: { disabled: true }, rateLimit: { enabled: false },
    advanced: { database: { generateId } },
    ...(input.secondary ? { secondaryStorage: {
      get: async (key: string) => cache.get(key) ?? null,
      set: async (key: string, value: string) => { cache.set(key, value); },
      delete: async (key: string) => { cache.delete(key); },
    } } : {}),
    emailAndPassword: { enabled: true, password: {
      hash: async (value: string) => `hashed:${value}`,
      verify: async ({ hash, password }: { hash: string; password: string }) => hash === `hashed:${password}`,
    } },
  });
  let cookie = "";
  const steps = [];
  for (const [path, body] of [
    ["/sign-up/email", { email: "id@example.com", name: "ID", password: "long-enough-password" }],
    ["/get-session", undefined],
    ["/sign-in/email", { email: "id@example.com", password: "long-enough-password" }],
    ["/get-session", undefined],
  ] as const) {
    const response = await auth.handler(new Request(`http://localhost:3000/api/auth${path}`, {
      method: body ? "POST" : "GET",
      headers: { origin: "http://localhost:3000", ...(body ? { "content-type": "application/json" } : cookie ? { cookie } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    }));
    cookie = response.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
    const data = await response.json();
    steps.push({ status: response.status, null: data === null, code: data?.code ?? null,
      userKeys: data?.user ? Object.keys(data.user).sort() : null,
      sessionKeys: data?.session ? Object.keys(data.session).sort() : null,
      email: data?.user?.email ?? null, hasCookie: !!cookie });
  }
  return { steps, calls, cachedMissingUser: cache.has("active-sessions-undefined") };
}
