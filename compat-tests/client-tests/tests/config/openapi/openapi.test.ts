import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

for (const profile of ["base", "metadata", "disabled", "models-minimal", "models-full", "models-secondary", "models-secondary-database"] as const) {
  compatScenario(`OpenAPI ${profile} schema and reference preserve HTTP/native and tenant behavior`, async ctx => {
    const response = await fetch(`${ctx.baseURL}/__test/openapi`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ profile, hosts: ["a.tenant.test", "b.tenant.test"] }),
    });
    expect(response.status).toBe(200);
    const result = await response.json();
    expect(result.defaultCalls).toBe(0);
    for (const call of result.calls) {
      expect(call.status).toBe(200);
      expect(call.native).toEqual(call.schema);
      expect(call.schema.openapi).toBe("3.1.1");
      expect(call.schema.info).toEqual({ title: "Better Auth", description: "API Reference for your Better Auth Instance", version: "1.1.0" });
      expect(call.schema.servers).toEqual([{ url: `https://${call.host}/api/auth` }]);
      expect(call.schema.security).toEqual([{ apiKeyCookie: [], bearerAuth: [] }]);
      expect(call.schema.paths).not.toHaveProperty("/open-api/generate-schema");
      expect(call.schema.paths).not.toHaveProperty(profile === "metadata" ? "/docs" : "/reference");
      expect(call.reference.csp).toBeNull();
      expect(call.nativeReference).toEqual({ status: call.reference.status, body: call.reference.body, contentType: call.reference.contentType });
      if (profile === "disabled") {
        expect(call.reference).toEqual({ status: 404, body: "", contentType: "application/json", csp: null });
        for (const path of ["/sign-in/email", "/delete-user", "/get-session"]) expect(call.schema.paths).not.toHaveProperty(path);
        continue;
      }
      expect(call.reference.status).toBe(200);
      expect(call.reference.contentType).toBe("text/html");
      expect(call.schema.paths).toHaveProperty("/delete-user");
      expect(call.schema.paths).toHaveProperty("/sign-in/email");
      expect(Object.keys(call.schema.paths["/get-session"])).toEqual(["get", "post"]);
      const scripts = [...call.reference.body.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)];
      expect(scripts).toHaveLength(3);
      expect(scripts[0][1]).toContain('type="application/json"');
      expect(scripts[0][1]).not.toContain("nonce");
      expect(JSON.parse(scripts[0][2])).toEqual(call.schema);
      for (const script of scripts.slice(1)) expect(script[1].includes('nonce="probe-nonce"')).toBe(profile === "metadata");
      expect(scripts[1][2]).toContain(`theme: "${profile === "metadata" ? "moon" : "default"}"`);
      if (profile.startsWith("models-")) {
        const full = profile !== "models-minimal";
        const secondary = profile.startsWith("models-secondary");
        const models = call.schema.components.schemas;
        expect(Object.keys(models)).toEqual([
          "User", "Session", "Account", ...(profile === "models-secondary" ? [] : ["Verification"]),
          "Organization", ...(full ? ["OrganizationRole", "Team", "TeamMember"] : []),
          "Member", "Invitation", "Apikey", ...(secondary ? ["RateLimit"] : []),
        ]);
        expect(Object.hasOwn(models.User.properties, "displayUsername")).toBe(full);
        expect(Object.hasOwn(models.User.properties, "lastLoginMethod")).toBe(full);
        expect(models.User.properties.username).toEqual({ type: "string", default: "app-username" });
        expect(models.Session.properties.tenantLabel).toEqual({ type: "string", default: "session" });
        expect(models.Apikey.properties.rateLimitMax.default).toBe(secondary ? 10 : 7);
        expect(models.Apikey.properties.rateLimitTimeWindow.default).toBe(secondary ? 86400000 : 1234);
        expect(models.Organization.properties.hidden).toEqual({ type: "string", readOnly: true });
        expect(models.Organization.required).not.toContain("hidden");
        const body = (path: string) => call.schema.paths[path].post.requestBody.content["application/json"].schema;
        expect(body("/sign-up/email").properties.username).toEqual({ type: "string" });
        expect(body("/sign-up/email").required).not.toContain("username");
        const create = body("/organization/create");
        expect(create.properties).not.toHaveProperty("hidden");
        expect(create.properties.label).toEqual({ type: "string" });
        expect(create.properties.optionalTag).toEqual({ type: ["string", "null"] });
        expect(create.required).toEqual(["name", "slug", "label", "factory"]);
        const update = body("/organization/update").properties.data;
        expect(Object.keys(update.properties)).toEqual(["label", "optionalTag", "factory", "name", "slug", "logo", "metadata"]);
        expect(update).not.toHaveProperty("required");
        expect(Object.hasOwn(call.schema.paths, "/organization/create-team")).toBe(full);
        expect(Object.hasOwn(call.schema.paths, "/organization/create-role")).toBe(full);
        if (full) {
          expect(models.OrganizationRole.required).not.toContain("roleTag");
          expect(body("/organization/create-role").properties.additionalFields.required).toEqual(["roleTag"]);
          expect(body("/organization/update-role").allOf[0].properties.data.properties.roleTag).toEqual({ type: ["string", "null"] });
        }
      }
      if (profile === "metadata") {
        const oracle = '{"0":0,"4294967294":1e+21,"4294967295":"last-index","01":"leading-zero","numbers":[0,0,1e-7,0.000001,100000000000000000000,1e+21],"nested":{"1":1,"2":2,"01":1}}';
        expect(scripts[0][2]).toContain(`"jsonOracle":{"type":"json","default":${oracle}}`);
        expect(call.schema.paths).not.toHaveProperty("/ok");
        expect(call.schema.paths).not.toHaveProperty("/docs-server");
        expect(call.schema.paths).not.toHaveProperty("/docs-core-collision");
        expect(Object.keys(call.schema.paths["/docs-methods"])).toEqual(["delete", "patch", "post", "put"]);
        expect(call.schema.paths["/docs-methods"].delete).not.toHaveProperty("requestBody");
        for (const method of ["patch", "post", "put"]) {
          expect(call.schema.paths["/docs-methods"][method].requestBody.content["application/json"].schema.required).toEqual(["value"]);
        }
        expect(call.schema.paths).toHaveProperty("/docs-scoped");
        expect(call.schema.components.schemas.Widget).toEqual({
          type: "object",
          properties: { id: { type: "string", readOnly: true }, title: { type: "string", readOnly: true }, hidden: { type: "string" }, payload: { type: "json" }, category: { type: ["staff", "guest"] } },
          required: ["id", "title"],
        });
        expect(call.schema.components.schemas).not.toHaveProperty("Stored_widgets");
        expect(call.schema.paths["/docs-probe/{id}"].get.operationId).toBe("duplicate");
        expect(call.schema.paths["/docs-probe/{id}"].post.operationId).toBe("duplicatePost");
        expect(call.schema.paths["/docs-second"].get.operationId).toBe("duplicateGet");
        expect(call.schema.paths["/docs-third"].get.operationId).toBe("duplicateGet2");
        expect(call.schema.paths["/docs-second"].get.parameters).toEqual([]);
        expect(call.schema.paths["/docs-second"].get.responses["400"]).toEqual({ description: "Custom failure" });
        expect(call.schema.paths["/docs-probe/{id}"].get.parameters).toEqual([
          { name: "page", in: "query", schema: { type: "number" } },
          { name: "value", in: "query", schema: { type: "string" } },
          { name: "id", in: "path", required: true, schema: { type: "string" } },
        ]);
        const signup = call.schema.paths["/sign-up/email"].post.requestBody.content["application/json"].schema;
        const update = call.schema.paths["/update-user"].post.requestBody.content["application/json"].schema;
        expect(signup.required).toEqual(["name", "email", "password", "requiredTag"]);
        expect(update).not.toHaveProperty("required");
        for (const body of [signup, update]) {
          expect(body.properties).not.toHaveProperty("hidden");
          expect(body.properties.factory).toEqual({ type: "string" });
          expect(body.properties.array).toEqual({ type: "array", items: { type: "number" } });
          expect(body.properties.payload).toEqual({});
          expect(body.properties.category).toEqual({ type: "string", enum: ["staff", "guest"] });
        }
      }
    }
    expect({ ...result.calls[0].schema, servers: [] }).toEqual({ ...result.calls[1].schema, servers: [] });
    return result;
  });
}
