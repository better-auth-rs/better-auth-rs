import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

async function control(base: string, body: object = {}) {
  const response = await fetch(`${base}/__test/device-generators`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  expect(response.status).toBe(200);
  return response.json();
}
const generated = ["device:start", "device:end", "user:start", "user:end"];
const issue = (ctx: any, client = "client") => ctx.rawRequest({ path: "/api/auth/device/code", method: "POST", json: { client_id: client, scope: "read" } });

compatScenario("async device generators run in order after authorization and before persistence", async ctx => {
  const denied = await issue(ctx, "deny");
  expect(denied.status).toBe(400);
  expect(await control(ctx.baseURL)).toEqual({ events: ["validate"], rows: 0 });
  await control(ctx.baseURL, { clear: true });
  const success = await issue(ctx);
  expect(success.status).toBe(200);
  expect(success.body.device_code).toBe("async-device-1");
  expect(success.body.user_code).toBe("async-user-1");
  expect(new URL(success.body.verification_uri_complete).searchParams.get("user_code")).toBe("async-user-1");
  const stored = await control(ctx.baseURL);
  expect(stored).toEqual({ events: ["validate", "request", ...generated], rows: 1 });
  return { denied, success, stored };
});

compatScenario("generator failures and code length errors stop the remaining work without rows", async ctx => {
  const results = [];
  for (const mode of ["device-error", "user-error", "device-long", "user-long"]) {
    await control(ctx.baseURL, { mode, clear: true });
    const response = await issue(ctx);
    const [kind, cause] = mode.split("-");
    expect(response.status).toBe(cause === "error" ? 500 : 400);
    expect(response.body).toEqual(cause === "error" ? { message: `${kind} generator failed` } : { error: "invalid_request", error_description: `Generated ${kind} code must be at most 191 characters` });
    const state = await control(ctx.baseURL);
    expect(state).toEqual({ events: ["validate", "request", ...(kind === "device" ? generated.slice(0, 2) : generated)], rows: 0 });
    results.push({ response, state });
  }
  return results;
});

compatScenario("collisions await both generators on each retry and preserve existing codes", async ctx => {
  await control(ctx.baseURL, { mode: "collision" });
  expect((await issue(ctx)).status).toBe(200);
  await control(ctx.baseURL, { clear: true });
  const collision = await issue(ctx);
  expect(collision.status).toBe(500);
  expect(collision.body).toEqual({ error: "server_error", error_description: "Failed to generate a unique device code" });
  const state = await control(ctx.baseURL);
  expect(state).toEqual({ events: ["validate", "request", ...generated, ...generated, ...generated], rows: 1 });
  await control(ctx.baseURL, { mode: "", clear: true });
  const next = await issue(ctx);
  expect(next.status).toBe(200);
  expect(next.body.device_code).toBe("async-device-5");
  expect((await control(ctx.baseURL)).rows).toBe(2);
  return { collision, state, next };
});

compatScenario("generated code length counts Unicode scalars and preserves an explicit empty code", async ctx => {
  const results = [];
  for (const mode of ["unicode", "empty"]) {
    await ctx.resetServerState();
    await control(ctx.baseURL, { mode });
    const response = await issue(ctx);
    expect(response.status).toBe(200);
    expect(response.body.device_code).toBe(mode === "unicode" ? "😀".repeat(191) : "");
    expect(response.body.user_code).toBe(response.body.device_code);
    expect((await control(ctx.baseURL)).rows).toBe(1);
    results.push(response);
  }
  return results;
});
