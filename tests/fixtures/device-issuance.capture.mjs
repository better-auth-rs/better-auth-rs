import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const reference = fileURLToPath(new URL("../../compat-tests/reference-server", import.meta.url));
const requireReference = createRequire(`${reference}/package.json`);
const upstream = specifier => import(pathToFileURL(requireReference.resolve(specifier)).href);
const { betterAuth } = await upstream("better-auth");
const { deviceAuthorization } = await upstream("better-auth/plugins");
const { memoryAdapter } = await upstream("better-auth/adapters/memory");

const origin = "http://device-issuance.test";
const deviceCode = "ordinary-issuance-device";
const userCode = "ABCD 2345+";

export async function captureDeviceIssuance() {
  const cases = [];
  for (const [name, configuration] of [
    ["uri-omitted", { defaultDeviceCode: false }],
    ["uri-empty", { defaultDeviceCode: false, verificationUri: "" }],
    ["uri-replace", { defaultDeviceCode: false,
      verificationUri: "https://review.example.test/activate?user_code=old&lang=en&user_code=older&empty=&lang=zh&flow=ordinary%20test~#ready" }],
    ["uri-append", { defaultDeviceCode: false,
      verificationUri: "/custom/verify?lang=en&lang=fr#ready" }],
    ["default-short", { defaultDeviceCode: true, deviceCodeLength: 1 }],
    ["default-length", { defaultDeviceCode: true }],
    ["default-long", { defaultDeviceCode: true, deviceCodeLength: 191 }],
  ]) {
    const memory = { user: [], session: [], account: [], verification: [], deviceCode: [] };
    const auth = betterAuth({
      database: memoryAdapter(memory), baseURL: origin,
      secret: "ordinary-device-issuance-secret-at-least-32-characters",
      telemetry: { enabled: false }, logger: { disabled: true }, rateLimit: { enabled: false },
      plugins: [deviceAuthorization({
        ...(Object.hasOwn(configuration, "verificationUri") ? { verificationUri: configuration.verificationUri } : {}),
        ...(Object.hasOwn(configuration, "deviceCodeLength") ? { deviceCodeLength: configuration.deviceCodeLength } : {}),
        ...(!configuration.defaultDeviceCode ? { generateDeviceCode: () => deviceCode } : {}),
        generateUserCode: () => userCode,
      })],
    });
    const context = await auth.$context;
    const response = await auth.handler(new Request(`${origin}/api/auth/device/code`, {
      method: "POST",
      headers: { "content-type": "application/json", origin },
      body: JSON.stringify({ client_id: "ordinary-client", scope: "read" }),
    }));
    const body = await response.json();
    const stored = await context.adapter.findOne({
      model: "deviceCode", where: [{ field: "deviceCode", value: body.device_code }],
    });
    const persistedCodesMatch = {
      deviceCode: stored.deviceCode === body.device_code,
      userCode: stored.userCode === body.user_code,
    };
    if (configuration.defaultDeviceCode) {
      body.device_code = {
        length: Array.from(body.device_code).length,
        asciiAlphanumeric: /^[A-Za-z0-9]+$/.test(body.device_code),
      };
    }
    cases.push({
      name, configuration, status: response.status,
      headers: [...response.headers].sort(([a], [b]) => a.localeCompare(b)),
      body, persistedCodesMatch,
      stored: { clientId: stored.clientId, scope: stored.scope, status: stored.status,
        pollingInterval: stored.pollingInterval },
    });
  }
  return {
    version: (await Bun.file(`${reference}/node_modules/@better-auth/core/package.json`).json()).version,
    cases,
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureDeviceIssuance(), null, 2));
