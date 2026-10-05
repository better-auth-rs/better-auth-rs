import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { betterAuth } from "better-auth/minimal";
import { openAPI } from "better-auth/plugins";

export async function captureOpenApiRateLimitModel() {
  const version = (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version;
  assert.equal(version, "1.7.6");
  const cases = [];
  for (const storage of ["database", "memory"]) {
    let callbackCalls = 0;
    const plugin = {
      id: "ordinary-rate-limit-model",
      schema: {
        beforeRateLimit: { fields: { label: { type: "string", required: true } } },
        rateLimit: { fields: {
          count: { type: "string", required: false, defaultValue: "plugin-count" },
          label: {
            type: "string", required: true, input: false,
            defaultValue() {
              callbackCalls += 1;
              return "plugin-label";
            },
          },
        } },
        afterRateLimit: { fields: { label: { type: "string", required: true } } },
      },
    };
    const auth = betterAuth({
      baseURL: "http://openapi-rate-limit-model.test",
      secret: "ordinary-openapi-rate-limit-model-secret-at-least-32-characters",
      logger: { disabled: true },
      telemetry: { enabled: false },
      rateLimit: { enabled: false, storage },
      plugins: [plugin, openAPI()],
    });
    // Observe serialized OpenAPI data; callback objects and own-undefined values are not JSON fields.
    const document = JSON.parse(JSON.stringify(await auth.api.generateOpenAPISchema()));
    assert.equal(callbackCalls, 0, "Schema generation must not execute model field defaults");
    const components = document.components;
    assert.ok(components.schemas.RateLimit, "The declared RateLimit model must be documented");
    cases.push({
      storage, components,
      modelKeys: Object.keys(components.schemas),
      rateLimitPropertyKeys: Object.keys(components.schemas.RateLimit.properties),
      callbackCalls,
    });
  }
  return { version, cases };
}

if (import.meta.main) {
  const output = process.argv[2];
  assert.ok(output, "Pass the RateLimit model fixture output path");
  writeFileSync(output, `${JSON.stringify(await captureOpenApiRateLimitModel(), null, 2)}\n`);
}
