import { betterAuth } from "better-auth/minimal";
import { openAPI } from "better-auth/plugins";
import { organization, username, lastLoginMethod } from "better-auth/plugins";
import { createAccessControl } from "better-auth/plugins/access";
import { defaultStatements } from "better-auth/plugins/organization/access";
import { apiKey } from "@better-auth/api-key";
import { createAuthEndpoint } from "@better-auth/core/api";
import * as z from "zod";

const jsonOracle = JSON.parse('{"4294967295":"last-index","01":"leading-zero","4294967294":1e21,"0":-0.0,"numbers":[0.0,-0.0,1e-7,1e-6,1e20,1e21],"nested":{"2":2.0,"1":1.0,"01":1.0}}');

export type OpenApiInput = {
  profile: "base" | "metadata" | "disabled" | "models-minimal" | "models-full" | "models-secondary" | "models-secondary-database";
  hosts?: string[];
};

export async function runOpenApi(input: OpenApiInput) {
  let defaultCalls = 0;
  const metadata = input.profile === "metadata";
  const disabled = input.profile === "disabled";
  const models = input.profile.startsWith("models-");
  const fullModels = models && input.profile !== "models-minimal";
  const secondary = input.profile.startsWith("models-secondary");
  const modelPlugins = models ? [
    organization({
      teams: { enabled: fullModels }, dynamicAccessControl: { enabled: fullModels },
      ac: createAccessControl(defaultStatements),
      schema: {
        organization: { additionalFields: {
          label: { type: "string", required: true, defaultValue: "org-default" },
          optionalTag: { type: "string", required: false },
          hidden: { type: "string", input: false, returned: false },
          factory: { type: "string", defaultValue: () => { defaultCalls++; return "factory"; } },
        } },
        member: { additionalFields: { badge: { type: "string", required: false } } },
        invitation: { additionalFields: { comment: { type: "string", required: false } } },
        team: { additionalFields: { teamTag: { type: "string", required: true } } },
        organizationRole: { additionalFields: { roleTag: { type: "string", required: true, defaultValue: "role-default" } } },
      },
    }),
    username({ displayUsername: fullModels }),
    lastLoginMethod({ storeInDatabase: fullModels }),
    apiKey(secondary ? [{ configId: "first", rateLimit: { maxRequests: 7, timeWindow: 1234 } }, { configId: "second" }] : { rateLimit: { maxRequests: 7, timeWindow: 1234 } }),
  ] : [];
  const unexpectedStorage = () => { throw new Error("OpenAPI must not access secondary storage"); };
  const plugin: any = {
    id: "docs-probe",
    schema: {
      widget: { modelName: "stored_widgets", fields: {
        title: { type: "string", required: true, input: false },
        hidden: { type: "string", required: true, returned: false },
        payload: { type: "json" }, category: { type: ["staff", "guest"] },
      } },
    },
    endpoints: {
      both: createAuthEndpoint("/docs-probe/:id", {
        method: ["GET", "POST"],
        body: z.object({ optional: z.string().optional() }),
        query: z.object({ page: z.number(), value: z.string().optional() }),
        metadata: { openapi: { operationId: "duplicate", description: "Probe" } },
      }, ctx => ctx.json({ ok: true })),
      same: createAuthEndpoint("/docs-second", {
        method: "GET", query: z.object({ hiddenQuery: z.string() }),
        metadata: { openapi: { operationId: "duplicate", parameters: [], responses: { 400: { description: "Custom failure" } } } },
      }, ctx => ctx.json({ ok: true })),
      third: createAuthEndpoint("/docs-third", {
        method: "GET", metadata: { openapi: { operationId: "duplicate" } },
      }, ctx => ctx.json({ ok: true })),
      mixed: createAuthEndpoint("/docs-methods", {
        method: ["PATCH", "DELETE", "POST", "PUT", "HEAD", "OPTIONS"],
        body: z.object({ value: z.string() }), query: z.object({ filter: z.string() }),
        metadata: { openapi: { operationId: "mixed" } },
      }, ctx => ctx.json({ ok: true })),
      getSession: createAuthEndpoint("/docs-core-collision", { method: "GET" }, ctx => ctx.json({ ok: true })),
      scope: createAuthEndpoint("/docs-scoped", { method: "GET", metadata: { scope: "server" } }, ctx => ctx.json({ ok: true })),
      server: createAuthEndpoint("/docs-server", { method: "GET", metadata: { SERVER_ONLY: true } }, ctx => ctx.json({ ok: true })),
    },
  };
  const referencePath = metadata ? "/docs" : "/reference";
  const auth = betterAuth({
    secret: "openapi-schema-fixture-secret-at-least-thirty-two-characters",
    baseURL: { allowedHosts: ["*.tenant.test"] },
    rateLimit: { enabled: false, ...(secondary ? { storage: "database" } : {}) },
    ...(secondary ? { secondaryStorage: { get: unexpectedStorage, set: unexpectedStorage, delete: unexpectedStorage } } : {}),
    verification: input.profile === "models-secondary-database" ? { storeInDatabase: true } : undefined,
    session: models ? { additionalFields: { tenantLabel: { type: "string", required: true, defaultValue: "session" } } } : undefined,
    logger: { disabled: true },
    disabledPaths: metadata ? ["/ok"] : disabled ? ["/sign-in/email", "/delete-user", "/get-session"] : [],
    user: metadata ? { additionalFields: {
      requiredTag: { type: "string", required: true },
      hidden: { type: "string", required: true, input: false, returned: false },
      factory: { type: "string", required: true, defaultValue: () => { defaultCalls++; return "factory"; } },
      array: { type: "number[]", defaultValue: [1] },
      jsonOracle: { type: "json", defaultValue: jsonOracle },
      payload: { type: "json" }, category: { type: ["staff", "guest"] },
    } } : models ? { additionalFields: { username: { type: "string", required: true, defaultValue: "app-username" } } } : undefined,
    plugins: [
      ...(metadata ? [plugin] : []),
      ...modelPlugins,
      openAPI({ path: referencePath, disableDefaultReference: disabled, ...(metadata ? { theme: "moon", nonce: "probe-nonce" } : {}) }),
    ],
  });
  const calls = await Promise.all((input.hosts ?? ["a.tenant.test"]).map(async host => {
    const url = `https://${host}/api/auth/open-api/generate-schema`;
    const response = await auth.handler(new Request(url));
    const schema = await response.json();
    const native = await auth.api.generateOpenAPISchema({ request: new Request(url), asResponse: false });
    const reference = await auth.handler(new Request(`https://${host}/api/auth${referencePath}`));
    let nativeReference: any;
    try {
      const value = await auth.api.openAPIReference({ request: new Request(`https://${host}/api/auth${referencePath}`) });
      nativeReference = { status: value.status, body: await value.text(), contentType: value.headers.get("content-type") };
    } catch (error: any) {
      nativeReference = { status: error.statusCode, body: "", contentType: null };
    }
    return {
      host, status: response.status, schema, native,
      reference: { status: reference.status, body: await reference.text(), contentType: reference.headers.get("content-type"), csp: reference.headers.get("content-security-policy") },
      nativeReference,
    };
  }));
  return { calls, defaultCalls };
}
