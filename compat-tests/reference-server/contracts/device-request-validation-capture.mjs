import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { memoryAdapter } from "better-auth/adapters/memory";
import { deviceAuthorization } from "better-auth/plugins";
import { z } from "zod";

const origin = "http://device-request-fields.test";
const deviceCode = "ordinary-request-device";
const userCode = "ABCD2345";
const json = value => JSON.parse(JSON.stringify(value));
const base = { client_id: "ordinary-client", scope: "read" };
const inputs = [
  { name: "trim-and-strip", encoding: "json", translateError: false,
    requestBody: JSON.stringify({ ...base, label: " Desk ", note: "Notes", ignored: "drop" }) },
  { name: "optional-omitted", encoding: "json", translateError: false,
    requestBody: JSON.stringify({ ...base, label: " Desk " }) },
  { name: "display-issues", encoding: "json", translateError: false,
    requestBody: JSON.stringify({ ...base, label: 7, note: true }) },
  { name: "translated-display-issues", encoding: "json", translateError: true,
    requestBody: JSON.stringify({ ...base, label: 7, note: true }) },
  { name: "form-display-fields", encoding: "form", translateError: false,
    requestBody: "client_id=ordinary-client&scope=read&label=+Desk+&note=Notes&ignored=drop" },
];

async function captureSyncCase(input) {
  const requests = [];
  const originalBodies = [];
  const issues = [];
  const transforms = [];
  const hookInputs = [];
  const memory = { user: [], session: [], account: [], verification: [], deviceCode: [] };
  const auth = betterAuth({
    baseURL: origin,
    secret: "ordinary-device-request-fields-secret-at-least-32-characters",
    database: memoryAdapter(memory),
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    plugins: [deviceAuthorization({
      generateDeviceCode: () => deviceCode,
      generateUserCode: () => userCode,
      validateClient: client => client === base.client_id,
      onDeviceAuthRequest(clientId, scope) { hookInputs.push({ clientId, scope }); },
      grant: {
        requestSchemaFields: {
          label: z.string().transform(value => { transforms.push("label"); return value.trim(); }),
          note: z.string().optional(),
        },
        deviceCodeSchemaFields: {
          label: { type: "string", required: false, defaultValue: "Stored display" },
        },
        async authorizeRequest({ ctx, request }) {
          requests.push(json(request));
          originalBodies.push(await ctx.request.clone().text());
          return undefined;
        },
        onRequestValidationError(value) {
          issues.push(json(value));
          if (input.translateError) throw new APIError("BAD_REQUEST", {
            error: "invalid_request", error_description: "Display fields need review",
          });
        },
        assertSessionRedemption() {},
        getVerificationContext() { return undefined; },
      },
    })],
  });
  const context = await auth.$context;
  const response = await auth.handler(new Request(`${origin}/api/auth/device/code`, {
    method: "POST",
    headers: { origin, accept: "application/json", "content-type": input.encoding === "form"
      ? "application/x-www-form-urlencoded" : "application/json" },
    body: input.requestBody,
  }));
  const body = await response.json();
  const row = await context.adapter.findOne({ model: "deviceCode",
    where: [{ field: "deviceCode", value: deviceCode }] });
  return {
    input, status: response.status,
    headers: [...response.headers].sort(([a], [b]) => a.localeCompare(b)),
    body, requests, originalBodies, issues, transforms, hookInputs,
    stored: row ? { clientId: row.clientId, scope: row.scope, status: row.status,
      pollingInterval: row.pollingInterval, label: row.label } : null,
  };
}

async function captureAsyncCase(name, input) {
  const callbacks = [];
  const schema = z.object({
    client_id: z.string(), user_id: z.string().optional(), scope: z.string().optional(),
    label: z.string().transform(async (value, context) => {
      callbacks.push("label:start");
      await Promise.resolve();
      callbacks.push("label:resolved");
      const parsed = value.trim();
      if (parsed.length === 0) {
        context.addIssue({ code: "custom", message: "Display label is required" });
        return z.NEVER;
      }
      return parsed;
    }),
    note: z.string().optional(),
  });
  // Explicit async parsing isolates schema results from Standard Schema's async-detection scheduling.
  const parsed = await schema.safeParseAsync(input);
  return { name, input, callbacks,
    result: parsed.success ? { value: json(parsed.data) } : { issues: json(parsed.error.issues) } };
}

export async function captureDeviceRequestValidation() {
  const metadata = await Bun.file(new URL("../node_modules/better-auth/package.json", import.meta.url)).json();
  assert.equal(metadata.version, "1.7.6");
  const syncCases = [];
  for (const input of inputs) syncCases.push(await captureSyncCase(input));
  const asyncCases = [
    await captureAsyncCase("async-display-transform", { ...base, label: " Desk ", note: "Notes", ignored: "drop" }),
    await captureAsyncCase("async-display-issue", { ...base, label: "   " }),
  ];
  return { version: metadata.version, syncCases, asyncCases };
}

if (import.meta.main) {
  const output = process.argv[2];
  assert.ok(output, "Pass the output fixture path");
  writeFileSync(output, `${JSON.stringify(await captureDeviceRequestValidation(), null, 2)}\n`);
}
