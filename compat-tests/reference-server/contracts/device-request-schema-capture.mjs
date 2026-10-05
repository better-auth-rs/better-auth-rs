import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { betterAuth } from "better-auth/minimal";
import { deviceAuthorization, openAPI } from "better-auth/plugins";
import { z } from "zod";

const deviceOperations = [
  ["/device/code", "post"],
  ["/device/token", "post"],
  ["/device", "get"],
  ["/device/approve", "post"],
  ["/device/deny", "post"],
];

function fieldSchema(kind, calls) {
  switch (kind) {
    case "label":
      return z.string().min(2).max(12).describe("Device label");
    case "optional-count":
      return z.number().optional();
    case "location":
      return z.enum(["desk", "rack"]);
    case "optional-nullable-label":
      return z.string().nullable().optional();
    case "default-label":
      return z.string().default(() => {
        calls.push("default-label");
        return "ordinary-default";
      });
    case "settings":
      return z.object({ enabled: z.boolean(), labels: z.array(z.string()).optional() });
    case "transformed-label":
      return z.string().transform((value) => {
        calls.push("transformed-label");
        return value.length;
      });
    case "optional-async-label":
      return z.string().transform(async (value) => {
        calls.push("optional-async-label");
        return value.length;
      }).optional();
    case "optional-flag":
      return z.boolean().optional();
    default:
      throw new Error(`Unknown request schema kind: ${kind}`);
  }
}

function observeOperations(document) {
  return deviceOperations.map(([path, method]) => {
    const operation = document.paths[path]?.[method];
    assert.ok(operation, `Expected the complete ${method} ${path} operation`);
    assert.ok(operation.responses, `Expected responses for ${path}`);
    const requestSchema = operation.requestBody?.content?.["application/json"]?.schema;
    return {
      path,
      method,
      operation,
      responseKeys: Object.keys(operation.responses),
      requestPropertyKeys: requestSchema?.properties ? Object.keys(requestSchema.properties) : null,
      requestRequired: requestSchema?.required ?? null,
      responsePropertyKeys: Object.entries(operation.responses).map(([status, response]) => ({
        status,
        keys: response.content?.["application/json"]?.schema?.properties
          ? Object.keys(response.content["application/json"].schema.properties)
          : null,
      })),
    };
  });
}

export async function captureDeviceRequestSchema() {
  const version = (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version;
  assert.equal(version, "1.7.6");
  const cases = [];
  for (const [name, fields] of [
    ["mixed-inputs", [
      { name: "tail", kind: "label" },
      { name: "10", kind: "optional-count" },
      { name: "2", kind: "location" },
      { name: "01", kind: "optional-nullable-label" },
      { name: "defaulted", kind: "default-label" },
      { name: "settings", kind: "settings" },
      { name: "normalized", kind: "transformed-label" },
    ]],
    ["optional-inputs", [
      { name: "defaulted", kind: "default-label" },
      { name: "10", kind: "optional-count" },
      { name: "2", kind: "optional-async-label" },
      { name: "01", kind: "optional-nullable-label" },
    ]],
    ["replacement-position", [
      { name: "tail", kind: "label" },
      { name: "10", kind: "optional-count" },
      { name: "2", kind: "location" },
      { name: "tail", kind: "optional-flag" },
      { name: "01", kind: "optional-nullable-label" },
    ]],
  ]) {
    const calls = [];
    const unexpected = (callback) => () => {
      calls.push(callback);
      throw new Error(`Schema generation called ${callback}`);
    };
    const requestSchemaFields = Object.fromEntries(fields.map(({ name: field, kind }) => [field, fieldSchema(kind, calls)]));
    const auth = betterAuth({
      baseURL: "http://device-request-schema.test",
      secret: "ordinary-device-request-schema-secret-at-least-32-characters",
      logger: { disabled: true },
      telemetry: { enabled: false },
      rateLimit: { enabled: false },
      plugins: [deviceAuthorization({ grant: {
        requestSchemaFields,
        deviceCodeSchemaFields: {},
        authorizeRequest: unexpected("authorizeRequest"),
        assertSessionRedemption: unexpected("assertSessionRedemption"),
        getVerificationContext: unexpected("getVerificationContext"),
      } }), openAPI()],
    });
    // Compare the serialized OpenAPI document. JSON omits properties whose value is undefined.
    const document = JSON.parse(JSON.stringify(await auth.api.generateOpenAPISchema()));
    assert.deepEqual(calls, [], "Schema generation must not execute validation, default, transform, or grant callbacks");
    cases.push({ name, fields, operations: observeOperations(document), callbackCalls: calls.length });
  }
  return { version, cases };
}

if (import.meta.main) {
  const output = process.argv[2];
  assert.ok(output, "Pass the output fixture path");
  writeFileSync(output, `${JSON.stringify(await captureDeviceRequestSchema(), null, 2)}\n`);
}
