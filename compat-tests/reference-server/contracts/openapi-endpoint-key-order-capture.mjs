import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { createAuthEndpoint } from "@better-auth/core/api";
import { betterAuth } from "better-auth/minimal";
import { openAPI } from "better-auth/plugins";

const prefix = "/ordinary-endpoint-order/";

export async function captureOpenApiEndpointKeyOrder() {
  const version = (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version;
  assert.equal(version, "1.7.6");
  const endpointKeys = ["tail", "10", "2", "01", "4294967294", "4294967295"];
  let callbackCalls = 0;
  const endpoints = Object.fromEntries(endpointKeys.map((key) => [key, createAuthEndpoint(`${prefix}${key}`, {
    method: "GET",
    metadata: { openapi: {
      operationId: "ordinaryDisplay",
      description: `Display endpoint ${key}`,
      responses: { 200: {
        description: "Ordinary display response",
        content: { "application/json": { schema: {
          type: "object", properties: { label: { type: "string" } }, required: ["label"],
        } } },
      } },
    } },
  }, async () => {
    callbackCalls += 1;
    throw new Error("Schema generation executed an endpoint handler");
  })]));
  const auth = betterAuth({
    baseURL: "http://openapi-endpoint-key-order.test",
    secret: "ordinary-openapi-endpoint-key-order-secret-at-least-32-characters",
    logger: { disabled: true },
    telemetry: { enabled: false },
    rateLimit: { enabled: false },
    plugins: [{ id: "ordinary-endpoint-order", endpoints }, openAPI()],
  });
  // Observe the complete JSON document boundary before reading operation values or key order.
  const document = JSON.parse(JSON.stringify(await auth.api.generateOpenAPISchema()));
  assert.equal(callbackCalls, 0, "Schema generation must not execute endpoint handlers");
  const operations = Object.fromEntries(Object.entries(document.paths).filter(([path]) => path.startsWith(prefix)));
  assert.equal(Object.keys(operations).length, endpointKeys.length, "Every declared endpoint must be documented");
  const operationIds = Object.entries(operations).map(([path, methods]) => {
    assert.ok(methods.get, `Expected the complete GET operation at ${path}`);
    assert.equal(typeof methods.get.operationId, "string");
    return { path, method: "get", operationId: methods.get.operationId };
  });
  return { version, endpointKeys, pathKeys: Object.keys(document.paths), operations, operationIds, callbackCalls };
}

if (import.meta.main) {
  const output = process.argv[2];
  assert.ok(output, "Pass the endpoint key-order fixture output path");
  writeFileSync(output, `${JSON.stringify(await captureOpenApiEndpointKeyOrder(), null, 2)}\n`);
}
