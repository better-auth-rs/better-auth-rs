import { betterAuth } from "better-auth/minimal";
import { openAPI, organization } from "better-auth/plugins";
import type { DBPrimitive } from "@better-auth/core/db";

export async function captureOpenApiRegisteredFields() {
  const cases = [];
  for (const name of [
    "registered-only", "organization-before", "organization-after", "organization-disabled",
  ] as const) {
    const callbackCalls = { default: 0, input: 0, output: 0 };
    const coreNote = {
      type: "string" as const, required: true, defaultValue: "registered-core-note",
      input: false, returned: false,
    };
    const documentationOnly = {
      type: "string" as const, required: false, defaultValue: "documentation-only",
    };
    const custom = {
      id: "ordinary-openapi-registered-fields",
      schema: {
        user: { fields: { coreNote } },
        session: { fields: { coreNote } },
        account: { fields: { coreNote } },
        verification: { fields: { coreNote } },
        deviceCode: { fields: {
          label: { type: "string" as const, required: true, fieldName: "stored_device_label" },
        } },
        jwks: { fields: {
          label: {
            type: "string" as const, required: true, fieldName: "stored_jwk_label",
            defaultValue: "jwk-default", input: false, returned: false,
          },
          docsNote: documentationOnly,
        } },
        walletAddress: { fields: {
          label: {
            type: "string" as const, required: false, fieldName: "stored_wallet_label",
            defaultValue() {
              callbackCalls.default += 1;
              return "wallet-default";
            },
            transform: {
              input(value: DBPrimitive) { callbackCalls.input += 1; return value; },
              output(value: DBPrimitive) { callbackCalls.output += 1; return value; },
            },
          },
        } },
        passkey: { fields: {
          name: { type: "string" as const, required: true, defaultValue: "passkey-name" },
          aaguid: {
            type: "string" as const, required: false, input: false, returned: false,
            defaultValue: "display-aaguid",
          },
        } },
        apikey: { fields: {
          name: {
            type: "string" as const, required: true, input: false, defaultValue: "api-key-name",
          },
        } },
        organization: { fields: {
          label: { type: "string" as const, required: false, defaultValue: "registered-organization-label" },
        } },
        team: { fields: {
          label: { type: "string" as const, required: false, defaultValue: "registered-team-label" },
        } },
        widget: { fields: { label: documentationOnly } },
      },
    };
    const configuredOrganization = organization({
      teams: { enabled: true },
      dynamicAccessControl: { enabled: name !== "organization-disabled" },
      schema: {
        organization: { additionalFields: {
          label: { type: "string", required: true, defaultValue: "builtin-organization-label" },
        } },
        member: { additionalFields: {
          note: { type: "string", required: false, input: false, defaultValue: "member-note" },
        } },
        invitation: { additionalFields: {
          note: { type: "string", required: true, returned: false },
        } },
        team: { additionalFields: {
          label: { type: "string", required: true, defaultValue: "builtin-team-label" },
        } },
        organizationRole: { additionalFields: {
          note: { type: "string", required: true, defaultValue: "role-note" },
        } },
      },
    });
    const plugins = name === "registered-only"
      ? [custom, openAPI()]
      : name === "organization-after"
        ? [custom, configuredOrganization, openAPI()]
        : [configuredOrganization, custom, openAPI()];
    const applicationNote = {
      type: "string" as const, required: false, defaultValue: "application-core-note",
    };
    const auth = betterAuth({
      baseURL: "http://openapi-registered-fields.test",
      secret: "ordinary-openapi-registered-fields-secret-at-least-32-characters",
      logger: { disabled: true },
      telemetry: { enabled: false },
      rateLimit: { enabled: false },
      user: { additionalFields: { coreNote: applicationNote } },
      session: { additionalFields: { coreNote: applicationNote } },
      account: { additionalFields: { coreNote: applicationNote } },
      verification: { additionalFields: { coreNote: applicationNote } },
      plugins,
    });
    const document = await auth.api.generateOpenAPISchema();
    cases.push({ name, schemas: document.components.schemas, callbackCalls });
  }
  return {
    version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    cases,
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureOpenApiRegisteredFields(), null, 2));
