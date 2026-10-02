import { Database } from "bun:sqlite";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const reference = fileURLToPath(new URL("../../compat-tests/reference-server", import.meta.url));
const requireReference = createRequire(`${reference}/package.json`);
const upstream = specifier => import(pathToFileURL(requireReference.resolve(specifier)).href);
const { betterAuth } = await upstream("better-auth");
const { deviceAuthorization } = await upstream("better-auth/plugins");
const { memoryAdapter } = await upstream("better-auth/adapters/memory");
const { getMigrations } = await upstream("better-auth/db/migration");

const origin = "http://device-interval.test";
const deviceCode = "ordinary-device-interval";
const userCode = "ABCDEF12";

export async function captureDeviceInterval() {
  const cases = [];
  for (const [backend, name] of [
    ["memory", "default"], ["memory", "fractional"],
    ["sqlite", "default"], ["sqlite", "fractional"],
    ["memory", "negative"], ["sqlite", "negative"],
  ]) {
    const database = backend === "sqlite" ? new Database(":memory:") : undefined;
    const memory = { user: [], session: [], account: [], verification: [], deviceCode: [] };
    const options = {
      database: database ?? memoryAdapter(memory),
      baseURL: origin,
      secret: "ordinary-device-interval-secret-at-least-32-characters",
      telemetry: { enabled: false }, logger: { disabled: true }, rateLimit: { enabled: false },
      plugins: [deviceAuthorization({
        ...(name === "fractional" ? { interval: "0.0015s" } : {}),
        ...(name === "negative" ? { interval: "-0.0015s", expiresIn: "-0.5s" } : {}),
        generateDeviceCode: () => deviceCode,
        generateUserCode: () => userCode,
      })],
    };
    try {
      if (database) await (await getMigrations(options)).runMigrations();
      const auth = betterAuth(options);
      const context = await auth.$context;
      const response = await auth.handler(new Request(`${origin}/api/auth/device/code`, {
        method: "POST",
        headers: { "content-type": "application/json", origin },
        body: JSON.stringify({ client_id: "ordinary-client", scope: "read" }),
      }));
      const body = await response.json();
      const stored = await context.adapter.findOne({
        model: "deviceCode", where: [{ field: "deviceCode", value: deviceCode }],
      });
      const column = database?.query("SELECT type, [notnull] AS required FROM pragma_table_info('deviceCode') WHERE name = 'pollingInterval'").get();
      const raw = database?.query("SELECT typeof(pollingInterval) AS storageClass FROM deviceCode WHERE deviceCode = ?").get(deviceCode);
      cases.push({
        backend, name,
        status: response.status,
        headers: [...response.headers].sort(([a], [b]) => a.localeCompare(b)),
        body,
        storedInterval: stored.pollingInterval,
        sql: database ? { columnType: column.type, nullable: column.required === 0, storageClass: raw.storageClass } : null,
      });
    } finally { database?.close(); }
  }
  return { version: "1.7.6", cases };
}

if (import.meta.main) console.log(JSON.stringify(await captureDeviceInterval(), null, 2));
