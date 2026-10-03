import type { DBFieldAttribute } from "@better-auth/core/db";
import { betterAuth } from "better-auth/minimal";
import { openAPI } from "better-auth/plugins";

const emptyFields: Record<string, DBFieldAttribute> = {};
const deviceFields = { label: { type: "string" as const, required: true } };
const passkeyFields = { name: { type: "string" as const, required: true } };

export async function captureOpenApiModelPresence() {
  const cases = [];
  for (const name of ["empty-runtime", "runtime-before-explicit", "explicit-before-runtime", "empty-explicit"] as const) {
    const device = {
      id: "ordinary-runtime-device",
      schema: { deviceCode: { fields: name === "empty-runtime" ? emptyFields : deviceFields } },
    };
    const passkey = {
      id: "ordinary-explicit-passkey",
      schema: { passkey: { fields: name === "empty-explicit" ? emptyFields : passkeyFields } },
    };
    const plugins = name === "empty-runtime"
      ? [device, openAPI()]
      : name === "empty-explicit"
        ? [passkey, openAPI()]
        : name === "runtime-before-explicit"
          ? [device, passkey, openAPI()]
          : [passkey, device, openAPI()];
    const auth = betterAuth({
      baseURL: "http://openapi-model-presence.test",
      secret: "ordinary-openapi-model-presence-secret-at-least-32-characters",
      logger: { disabled: true },
      telemetry: { enabled: false },
      rateLimit: { enabled: false },
      plugins,
    });
    const document = await auth.api.generateOpenAPISchema();
    const schemas = document.components.schemas;
    cases.push({ name, schemas, modelKeys: Object.keys(schemas) });
  }
  return {
    version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    cases,
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureOpenApiModelPresence(), null, 2));
