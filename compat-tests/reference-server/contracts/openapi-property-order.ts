import { ok } from "node:assert/strict";
import { betterAuth } from "better-auth/minimal";
import { deviceAuthorization, openAPI, organization } from "better-auth/plugins";

const names = ["tail", "10", "2", "01", "4294967294", "4294967295"] as const;
const numericFields = () => Object.fromEntries(names.map((name) => [name, {
  type: "string" as const, required: true, fieldName: `display_${name}`,
}]));
const coreFields = (name: "label" | "note") => ({ [name]: {
  type: "string" as const, required: true,
} });
const corePlugin = (name: "label" | "note") => ({
  id: `ordinary-openapi-${name}`,
  schema: {
    user: { fields: coreFields(name) },
    session: { fields: coreFields(name) },
    account: { fields: coreFields(name) },
    verification: { fields: coreFields(name) },
  },
});

export async function captureOpenApiPropertyOrder() {
  const cases = [];
  for (const name of ["numeric-display-names", "runtime-before-explicit", "explicit-before-runtime"] as const) {
    const numeric = name === "numeric-display-names";
    const options = {
      baseURL: "http://openapi-property-order.test",
      secret: "ordinary-openapi-property-order-secret-at-least-32-characters",
      logger: { disabled: true },
      telemetry: { enabled: false },
      rateLimit: { enabled: false },
      ...(numeric ? {
        user: { additionalFields: numericFields() },
        session: { additionalFields: numericFields() },
        account: { additionalFields: numericFields() },
        verification: { additionalFields: numericFields() },
      } : {}),
    };
    const plugins = numeric
      ? [
        organization({
          teams: { enabled: true },
          dynamicAccessControl: { enabled: true },
          schema: {
            organization: { additionalFields: numericFields() },
            member: { additionalFields: numericFields() },
            invitation: { additionalFields: numericFields() },
            team: { additionalFields: numericFields() },
            organizationRole: { additionalFields: numericFields() },
          },
        }),
        { id: "ordinary-openapi-numeric-fields", schema: { deviceCode: { fields: numericFields() } } },
        deviceAuthorization(),
        openAPI(),
      ]
      : name === "runtime-before-explicit"
        ? [corePlugin("label"), corePlugin("note"), openAPI()]
        : [corePlugin("note"), corePlugin("label"), openAPI()];
    const document = await betterAuth({ ...options, plugins }).api.generateOpenAPISchema();
    const selectedModels = numeric
      ? ["User", "Session", "Account", "Verification", "Organization", "Member", "Invitation", "Team", "OrganizationRole", "DeviceCode"]
      : ["User", "Session", "Account", "Verification"];
    const components = selectedModels.map((model) => {
      const schema = document.components.schemas[model];
      ok(schema?.properties, `Expected complete ${model} component`);
      return { model, schema, propertyKeys: Object.keys(schema.properties) };
    });
    const selectedPaths = numeric
      ? ["/sign-up/email", "/update-user", "/organization/create", "/organization/update", "/organization/create-role", "/organization/update-role"]
      : ["/sign-up/email", "/update-user"];
    const requests = selectedPaths.map((path) => {
      const schema = document.paths[path]?.post?.requestBody?.content["application/json"].schema;
      ok(schema, `Expected complete request schema for ${path}`);
      const fieldSchema = path === "/organization/update"
        ? schema.properties?.data
        : path === "/organization/create-role"
          ? schema.properties?.additionalFields
          : path === "/organization/update-role"
            ? schema.allOf?.[0]?.properties?.data
            : schema;
      ok(fieldSchema?.properties, `Expected display properties for ${path}`);
      return { path, schema, propertyKeys: Object.keys(fieldSchema.properties) };
    });
    cases.push({ name, components, requests });
  }
  return {
    version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    cases,
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureOpenApiPropertyOrder(), null, 2));
