import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { betterAuth } from "better-auth/minimal";
import { deviceAuthorization, openAPI } from "better-auth/plugins";

const operations = [
  ["/device/code", "post"],
  ["/device/token", "post"],
  ["/device", "get"],
  ["/device/approve", "post"],
  ["/device/deny", "post"],
];

function propertyKeys(schema) {
  return schema?.properties ? Object.keys(schema.properties) : null;
}

function observeOperations(document) {
  return operations.map(([path, method]) => {
    const operation = document.paths[path]?.[method];
    assert.ok(operation, `Expected the complete ${method} ${path} operation`);
    assert.ok(operation.responses, `Expected responses for ${path}`);
    return {
      path,
      method,
      operation,
      responseKeys: Object.keys(operation.responses),
      requestPropertyKeys: propertyKeys(operation.requestBody?.content?.["application/json"]?.schema),
      responsePropertyKeys: Object.entries(operation.responses).map(([status, response]) => ({
        status,
        keys: propertyKeys(response.content?.["application/json"]?.schema),
      })),
    };
  });
}

function configuredGrant(input, calls) {
  const unexpected = (name) => () => {
    calls.push(name);
    throw new Error(`Metadata generation called ${name}`);
  };
  return {
    ...input,
    authorizeRequest: unexpected("authorizeRequest"),
    assertSessionRedemption: unexpected("assertSessionRedemption"),
    getVerificationContext: unexpected("getVerificationContext"),
  };
}

function customMetadata() {
  return {
    requestErrorCodes: ["display_unavailable", "invalid_scope", "display_unavailable"],
    requestOpenAPIResponses: {
      default: { description: "Ordinary default display response" },
      "2XX": { description: "Ordinary successful display response" },
      425: {
        description: "Display is being prepared",
        content: { "application/json": { schema: {
          type: "object",
          properties: {
            detail: { type: "string" },
            retry_hint: { type: "string" },
          },
        } } },
      },
      200: { description: "Configured success response" },
      418: { description: "Ordinary display response" },
      401: { description: "Configured client response" },
      400: { description: "Configured request response" },
      500: { description: "Configured server response" },
    },
    verificationOpenAPIProperties: {
      tail: { type: "string", description: "Display label" },
      10: { type: "string", description: "Display ten" },
      2: { type: "string", description: "Display two" },
      "01": { type: "string", description: "Display leading zero" },
    },
  };
}

export async function captureDeviceGrantMetadata() {
  const version = (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version;
  assert.equal(version, "1.7.6");
  const cases = [];
  for (const [name, grant] of [
    ["no-grant", null],
    ["empty-grant", {}],
    ["custom-metadata", customMetadata()],
  ]) {
    const calls = [];
    const plugin = deviceAuthorization(grant === null ? {} : { grant: configuredGrant(grant, calls) });
    const auth = betterAuth({
      baseURL: "http://device-grant-metadata.test",
      secret: "ordinary-device-grant-metadata-secret-at-least-32-characters",
      logger: { disabled: true },
      telemetry: { enabled: false },
      rateLimit: { enabled: false },
      plugins: [plugin, openAPI()],
    });
    const document = await auth.api.generateOpenAPISchema();
    assert.deepEqual(calls, [], "Metadata must not execute grant callbacks");
    cases.push({ name, grant, operations: observeOperations(document), callbackCalls: calls.length });
  }

  const configurationErrors = [];
  for (const [name, names] of [
    ["reserved-user-code", ["user_code"]],
    ["reserved-status", ["status"]],
    ["reserved-client-id", ["client_id"]],
    ["reserved-scope", ["scope"]],
    ["reserved-declaration-order", ["scope", "label", "user_code", "client_id", "status"]],
  ]) {
    const grant = {
      verificationOpenAPIProperties: Object.fromEntries(names.map((key) => [key, { type: "string" }])),
    };
    const calls = [];
    let error;
    try {
      deviceAuthorization({ grant: configuredGrant(grant, calls) });
    } catch (cause) {
      assert.ok(cause instanceof Error);
      error = cause.message;
    }
    assert.equal(typeof error, "string", "Reserved verification properties must reject plugin configuration");
    assert.deepEqual(calls, [], "Configuration validation must not execute grant callbacks");
    configurationErrors.push({ name, grant, error, callbackCalls: calls.length });
  }
  return { version, cases, configurationErrors };
}

if (import.meta.main) {
  const output = process.argv[2];
  assert.ok(output, "Pass the output fixture path");
  writeFileSync(output, `${JSON.stringify(await captureDeviceGrantMetadata(), null, 2)}\n`);
}
