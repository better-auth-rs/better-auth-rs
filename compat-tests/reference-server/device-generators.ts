import { APIError } from "better-auth/api";
import type { Database } from "bun:sqlite";
export function createDeviceGenerators(profile: string, database: Database) {
  let mode = "", issued = 0;
  const events: string[] = [];
  const generate = async (kind: string) => {
    events.push(`${kind}:start`);
    if (kind === "device") issued++;
    await Bun.sleep(5);
    events.push(`${kind}:end`);
    if (mode === `${kind}-error`) throw new APIError("INTERNAL_SERVER_ERROR", { message: `${kind} generator failed` });
    if (mode === `${kind}-long`) return "😀".repeat(192);
    if (mode === "unicode") return "😀".repeat(191);
    if (mode === "empty") return "";
    if (mode === "collision" && kind === "user") return "same-user";
    return `async-${kind}-${issued}`;
  };
  return {
    options: profile === "device-generators" ? {
      generateDeviceCode: () => generate("device"), generateUserCode: () => generate("user"),
      validateClient: async (client: string) => { events.push("validate"); return client !== "deny"; },
      onDeviceAuthRequest: async () => { events.push("request"); },
    } : {},
    reset() { mode = ""; issued = 0; events.length = 0; },
    async handle(request: Request) {
      if (new URL(request.url).pathname !== "/__test/device-generators") return null;
      const body = await request.json();
      if (body.mode !== undefined) mode = body.mode;
      if (body.clear) events.length = 0;
      return Response.json({ events, rows: (database.query("SELECT COUNT(*) AS count FROM deviceCode").get() as any).count });
    },
  };
}
