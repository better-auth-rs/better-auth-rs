import type { DBFieldAttribute } from "@better-auth/core/db";
import { betterAuth } from "better-auth/minimal";
import { openAPI } from "better-auth/plugins";

const modelNames = ["tail", "10", "2", "01", "4294967294", "4294967295"];

export async function captureOpenApiModelKeyOrder() {
  const schema: Record<string, { fields: Record<string, DBFieldAttribute> }> = {};
  for (const name of modelNames) {
    schema[name] = {
      fields: { label: { type: "string", required: true, defaultValue: name } },
    };
  }
  const auth = betterAuth({
    baseURL: "http://openapi-model-key-order.test",
    secret: "ordinary-openapi-model-key-order-secret-at-least-32-characters",
    logger: { disabled: true },
    telemetry: { enabled: false },
    rateLimit: { enabled: false },
    plugins: [{ id: "ordinary-model-key-order", schema }, openAPI()],
  });
  const document = await auth.api.generateOpenAPISchema();
  const components = document.components;
  const modelKeys = Object.keys(components.schemas);
  return {
    version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    components,
    modelKeys,
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureOpenApiModelKeyOrder(), null, 2));
