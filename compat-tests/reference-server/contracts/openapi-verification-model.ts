import { betterAuth } from "better-auth/minimal";
import { openAPI } from "better-auth/plugins";

const pluginFields = {
  label: { type: "string" as const, required: true, fieldName: "stored_label" },
};
const applicationFields = {
  caption: {
    type: "string" as const, required: false, fieldName: "stored_caption",
    defaultValue: "application caption",
  },
};
const unexpectedStorage = () => {
  throw new Error("OpenAPI schema generation must not access secondary storage");
};

export async function captureOpenApiVerificationModel() {
  const cases = [];
  for (const name of ["no-secondary", "secondary-only", "secondary-database"] as const) {
    const auth = betterAuth({
      baseURL: "http://openapi-verification-model.test",
      secret: "ordinary-openapi-verification-model-secret-at-least-32-characters",
      logger: { disabled: true },
      telemetry: { enabled: false },
      rateLimit: { enabled: false },
      ...(name !== "no-secondary" ? {
        secondaryStorage: { get: unexpectedStorage, set: unexpectedStorage, delete: unexpectedStorage },
      } : {}),
      verification: {
        additionalFields: applicationFields,
        ...(name === "secondary-database" ? { storeInDatabase: true } : {}),
      },
      plugins: [
        { id: "ordinary-verification-display", schema: { verification: { fields: pluginFields } } },
        openAPI(),
      ],
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

if (import.meta.main) console.log(JSON.stringify(await captureOpenApiVerificationModel(), null, 2));
