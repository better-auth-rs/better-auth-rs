import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { asArray, asRecord, signUpUser, type CompatContext } from "../../phase6/helpers";

function fixture(ctx: CompatContext) {
  const observations: unknown[] = [];
  return {
    observations,
    async control(json: Record<string, unknown> = {}) {
      const response = await ctx.rawRequest({ path: "/__test/api-key-callbacks/control", method: "POST", json });
      expect(response.status).toBe(200);
    },
    async trace() {
      const response = await ctx.rawRequest({ path: "/__test/api-key-callbacks/control", method: "GET" });
      const events = asArray(asRecord(response.body).events).map(asRecord);
      observations.push({ events });
      return events;
    },
    async call(operation: string, input: Record<string, unknown>) {
      const response = await ctx.rawRequest({ path: "/__test/api-key-callbacks/call", method: "POST", json: { operation, input } });
      expect(response.status).toBe(200);
      observations.push(response.body);
      return asRecord(response.body);
    },
    async session(key: string, header = "x-callback-key") {
      const response = await ctx.rawRequest({ actor: "machine", path: "/api/auth/get-session", method: "GET", headers: { [header]: key } });
      observations.push(response);
      return response;
    },
  };
}

compatScenario("API key generators and dynamic permissions preserve order, context and explicit permissions", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "callback-owner", "Owner");
  const f = fixture(ctx);
  const userId = owner.signup.data!.user.id;
  await f.control();
  const created = asRecord((await f.call("create", { userId, name: "Native", prefix: "custom_", remaining: 5 })).result);
  expect(created.key).toBe("custom_custom_1_kkkkkkkkkkkk");
  expect(created.start).toBe("custom");
  expect(created.permissions).toEqual({ nodes: ["native"] });
  let events = await f.trace();
  expect(events.map((event) => event.event)).toEqual(["get", "generate", "permissions"]);
  expect(events[1]).toEqual({ event: "generate", configId: "default", length: 12, prefix: "custom_" });
  expect(events[2]).toMatchObject({ referenceId: userId, path: "/api-key/create", hasRequest: false, remaining: 5, expiresIn: null });

  await f.control();
  const explicit = asRecord((await f.call("create", { userId, permissions: { jobs: ["run"] } })).result);
  expect(explicit.permissions).toEqual({ jobs: ["run"] });
  expect((await f.trace()).map((event) => event.event)).toEqual(["get", "generate", "permissions"]);

  await f.control();
  const http = await ctx.rawRequest({ actor: "owner", path: "/api/auth/api-key/create", method: "POST", json: { name: "HTTP" } });
  expect(http.status).toBe(200);
  f.observations.push(http);
  events = await f.trace();
  expect(events.map((event) => event.event)).toEqual(["get", "generate", "permissions"]);
  expect(events[2]).toMatchObject({ referenceId: userId, path: "/api-key/create", hasRequest: true, remaining: null, expiresIn: null });

  for (const kind of ["generator", "permissions"]) {
    for (const mode of ["api-error", "error"]) {
    await f.control({ [`${kind}Mode`]: mode });
    const failure = await f.call("create", { userId, permissions: { explicit: ["grant"] } });
    expect(failure).toEqual(mode === "api-error"
      ? { kind: "thrown", status: 403, body: { code: "CALLBACK_REJECTED", message: "Callback rejected" } }
      : { kind: "error", message: "Callback failed" });
    expect((await f.trace()).map((event) => event.event)).toEqual(kind === "generator" ? ["get", "generate"] : ["get", "generate", "permissions"]);
    await f.control();
    const httpFailure = await ctx.rawRequest({ actor: "owner", path: "/api/auth/api-key/create", method: "POST", json: {} });
    expect(httpFailure.status).toBe(mode === "api-error" ? 403 : 500);
    expect(httpFailure.body).toEqual(mode === "api-error" ? { code: "CALLBACK_REJECTED", message: "Callback rejected" } : null);
    f.observations.push(httpFailure);
    expect((await f.trace()).map((event) => event.event)).toEqual(kind === "generator" ? ["get", "generate"] : ["get", "generate", "permissions"]);
    await f.control({ [`${kind}Mode`]: "allow" });
    }
  }
  const listed = await ctx.rawRequest({ actor: "owner", path: "/api/auth/api-key/list", method: "GET" });
  expect(asRecord(listed.body).total).toBe(3);
  f.observations.push(listed);
  return f.observations;
});

compatScenario("API key scoped and discovered validators preserve distinct rejection and exception contracts", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "validation-owner", "Owner");
  const f = fixture(ctx);
  const issued = asRecord((await f.call("create", { userId: owner.signup.data!.user.id, configId: "named", remaining: 10 })).result);
  const key = issued.key as string;
  for (const mode of ["deny", "api-error", "error"]) {
    for (const scoped of [true, false]) {
      await f.control({ validatorMode: mode });
      const output = await f.call("verify", { key, ...(scoped ? { configId: "named" } : {}) });
      const events = await f.trace();
      expect(events.map((event) => event.event)).toEqual(["get", "validate"]);
      expect(events[1]).toMatchObject({ configId: "named", hasRequest: false, path: "virtual:" });
      if (mode === "deny") {
        expect(asRecord(output.result).error).toEqual({ code: "KEY_NOT_FOUND", message: scoped
          ? { code: "INVALID_API_KEY", message: "Invalid API key." } : "API Key not found" });
      } else if (mode === "api-error") {
        expect(scoped ? output : asRecord(output.result).error).toEqual(scoped
          ? { kind: "thrown", status: 403, body: { code: "CALLBACK_REJECTED", message: "Callback rejected" } }
          : { code: "CALLBACK_REJECTED", message: "Callback rejected" });
      } else if (scoped) {
        expect(output).toEqual({ kind: "error", message: "Callback failed" });
      } else {
        expect(asRecord(output.result).error).toEqual({ code: "INVALID_API_KEY", message: { code: "INVALID_API_KEY", message: "Invalid API key." } });
      }
    }
  }
  await f.control({ validatorMode: "allow" });
  const valid = asRecord((await f.call("verify", { key })).result);
  expect(valid.valid).toBe(true);
  expect(asRecord(valid.key).remaining).toBe(9);
  await f.control();
  const mismatch = asRecord((await f.call("verify", { key, configId: "default" })).result);
  expect(asRecord(mismatch.error).code).toBe("INVALID_API_KEY");
  expect((await f.trace())[1]?.configId).toBe("default");
  await f.control({ validatorMode: "deny" });
  await f.call("verify", { key: "unknown-key-with-enough-characters" });
  expect((await f.trace()).map((event) => event.event)).toEqual(["get"]);
  return f.observations;
});

compatScenario("API key getter replaces headers and runs separately for matcher and handler", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "getter-owner", "Owner");
  const f = fixture(ctx);
  const issued = asRecord((await f.call("create", { userId: owner.signup.data!.user.id, configId: "callback-session" })).result);
  const key = issued.key as string;
  await f.control();
  const success = await f.session(key);
  expect(success.status).toBe(200);
  expect(asRecord(asRecord(success.body).user).id).toBe(owner.signup.data!.user.id);
  expect((await f.trace()).map((event) => event.event)).toEqual(["get", "get", "validate"]);
  await f.control({ getterMode: "none" });
  expect((await f.session(key, "x-api-key")).body).toBeNull();
  expect((await f.trace()).map((event) => event.event)).toEqual(["get"]);
  await f.control({ getterMode: "header" });
  expect((await f.session("short")).status).toBe(403);
  expect((await f.trace()).map((event) => event.event)).toEqual(["get", "get"]);
  await f.control({ validatorMode: "deny" });
  const denied = await f.session(key);
  expect(denied.status).toBe(403);
  expect(denied.body).toEqual({ code: "INVALID_API_KEY", message: "Invalid API key." });
  expect((await f.trace()).map((event) => event.event)).toEqual(["get", "get", "validate"]);
  await f.control({ validatorMode: "allow", getterMode: "error" });
  const failed = await f.session(key);
  expect(failed.status).toBe(500);
  expect(failed.body).toEqual({ message: "An error occurred during hook matcher execution. Check the logs for more details." });
  expect((await f.trace()).map((event) => event.event)).toEqual(["get"]);
  await f.control({ getterMode: "second-api-error" });
  const handlerFailed = await f.session(key);
  expect(handlerFailed.status).toBe(403);
  expect(handlerFailed.body).toEqual({ code: "CALLBACK_REJECTED", message: "Callback rejected" });
  expect((await f.trace()).map((event) => event.event)).toEqual(["get", "get"]);
  for (const kind of ["getter", "validator"]) {
    await f.control({ getterMode: kind === "getter" ? "second-error" : "header", validatorMode: kind === "validator" ? "error" : "allow" });
    const httpError = await f.session(key);
    expect(httpError.status).toBe(500);
    expect(httpError.body).toBeNull();
    expect((await f.trace()).map((event) => event.event)).toEqual(kind === "getter" ? ["get", "get"] : ["get", "get", "validate"]);
    await f.control({ nativeKey: key });
    expect(await f.call("create", {})).toEqual({ kind: "error", message: "Callback failed" });
    expect((await f.trace()).map((event) => event.event)).toEqual(kind === "getter" ? ["get", "get"] : ["get", "get", "validate"]);
    await f.control({ nativeKey: null });
  }
  return f.observations;
});

compatScenario("requestless API key hooks consume usage and enforce native creation user matching", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "native-owner", "Owner");
  const other = await signUpUser(ctx, "other", "native-other", "Other");
  const f = fixture(ctx);
  const issued = asRecord((await f.call("create", { userId: owner.signup.data!.user.id, configId: "callback-session", remaining: 20 })).result);
  const key = issued.key as string;
  await f.control({ nativeKey: key });
  const created = await f.call("create", { name: "Hook owner", userId: "" });
  expect(asRecord(created.result).referenceId).toBe(owner.signup.data!.user.id);
  expect((await f.trace()).map((event) => event.event)).toEqual(["get", "get", "validate", "generate", "permissions"]);
  await f.control();
  const updated = await f.call("update", { keyId: asRecord(created.result).id, userId: "", name: "Updated" });
  expect(asRecord(updated.result).name).toBe("Updated");
  expect((await f.trace()).map((event) => event.event)).toEqual(["get", "get", "validate"]);
  await f.control();
  const verified = asRecord((await f.call("verify", { key, configId: "callback-session" })).result);
  expect(asRecord(verified.key).remaining).toBe(16);
  expect((await f.trace()).map((event) => event.event)).toEqual(["get", "get", "validate", "validate"]);
  await f.control();
  expect(await f.call("create", { userId: other.signup.data!.user.id })).toEqual({ kind: "thrown", status: 401,
    body: { code: "UNAUTHORIZED_SESSION", message: "Unauthorized or invalid session" } });
  expect((await f.trace()).map((event) => event.event)).toEqual(["get", "get", "validate"]);
  await f.control();
  const invalid = await f.call("create", { remaining: -1 });
  expect(invalid.kind).toBe("thrown");
  expect(invalid.status).toBe(400);
  expect(asRecord(invalid.body).code).toBe("VALIDATION_ERROR");
  expect((await f.trace()).map((event) => event.event)).toEqual(["get", "get", "validate"]);
  await f.control({ nativeKey: null });
  const remaining = asRecord((await f.call("verify", { key })).result);
  expect(asRecord(remaining.key).remaining).toBe(13);
  return f.observations;
});

compatScenario("API key starting characters preserve UTF-16 through database and custom secondary storage", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "utf16-owner", "Owner");
  const userId = owner.signup.data!.user.id;
  const f = fixture(ctx);
  for (const configId of ["default", "callback-cache"]) {
    for (const [prefix, expected] of [["😀abcdefgh", "😀abcd"], ["abcde😀fgh", configId === "default" ? "abcde���" : "abcde\ud83d"]]) {
      for (const mode of ["native", "http"]) {
        const key = `${prefix}-${configId}-${mode}`;
        await f.control({ generatedKey: key });
        let created: Record<string, unknown>;
        if (mode === "native") {
          created = asRecord((await f.call("create", { userId, configId })).result);
        } else {
          const response = await ctx.rawRequest({ actor: "owner", path: "/api/auth/api-key/create", method: "POST", json: { configId } });
          expect(response.status).toBe(200);
          f.observations.push(response);
          created = asRecord(response.body);
        }
        expect(created.key).toBe(key);
        expect(created.start).toBe(expected);
        const get = await ctx.rawRequest({ actor: "owner", path: `/api/auth/api-key/get?id=${created.id}&configId=${configId}` });
        expect(get.status).toBe(200);
        expect(asRecord(get.body).start).toBe(expected);
        f.observations.push(get);
        const verified = asRecord((await f.call("verify", { key, configId })).result);
        expect(verified.valid).toBe(true);
        expect(asRecord(verified.key).start).toBe(expected);
        const updated = asRecord((await f.call("update", { userId, keyId: created.id, configId, name: "Updated Unicode" })).result);
        expect(updated.start).toBe(expected);
        const list = await ctx.rawRequest({ actor: "owner", path: `/api/auth/api-key/list?configId=${configId}` });
        expect(list.status).toBe(200);
        const entry = asArray(asRecord(list.body).apiKeys).map(asRecord).find((entry) => entry.id === created.id);
        expect(entry?.start).toBe(expected);
        f.observations.push(list);
      }
    }
  }
  await f.control({ generatedKey: "abcde😀-without-start" });
  const noStart = asRecord((await f.call("create", { userId, configId: "no-start" })).result);
  expect(noStart.start).toBeNull();
  expect(noStart.key).toBe("abcde😀-without-start");
  return f.observations;
});
