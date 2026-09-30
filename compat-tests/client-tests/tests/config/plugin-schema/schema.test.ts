import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { jwtScenario } from "../../jwt-scenario";

jwtScenario("EdDSA");

compatScenario("mapped plugin columns preserve API key quotas and device approval", async (ctx) => {
  const signup = await ctx.actor().client.signUp.email({ email: ctx.uniqueEmail("mapped"), password: "password123", name: "Mapped" });
  expect(signup.error).toBeNull();
  const key = await ctx.rawRequest({ path: "/__test/api-key/create", method: "POST", json: { userId: signup.data!.user.id, name: "mapped", remaining: 2, rateLimitEnabled: false } });
  expect(key.status).toBe(200);
  const credential = key.body as { key: string; id: string };
  const outcomes = [];
  for (const remaining of [1, 0]) {
    const result = await ctx.rawRequest({ path: "/__test/api-key/verify", method: "POST", json: { key: credential.key } });
    expect(result.status).toBe(200);
    const body = result.body as { valid: boolean; key: { remaining: number } };
    expect(body.valid).toBe(true);
    expect(body.key.remaining).toBe(remaining);
    outcomes.push(body.key.remaining);
  }
  const exhausted = await ctx.rawRequest({ path: "/__test/api-key/verify", method: "POST", json: { key: credential.key } });
  expect((exhausted.body as { valid: boolean }).valid).toBe(false);
  const code = await ctx.rawRequest({ path: "/api/auth/device/code", method: "POST", json: { client_id: "mapped-client" } });
  expect(code.status).toBe(200);
  const userCode = (code.body as { user_code: string }).user_code;
  const found = await ctx.rawRequest({ path: `/api/auth/device?user_code=${encodeURIComponent(userCode)}` });
  expect(found.status).toBe(200);
  const approve = await ctx.rawRequest({ path: "/api/auth/device/approve", method: "POST", json: { userCode } });
  expect(approve.status).toBe(200);
  const replay = await ctx.rawRequest({ path: "/api/auth/device/approve", method: "POST", json: { userCode } });
  expect(replay.status).toBe(400);
  return { outcomes, exhausted: ctx.snapshot(exhausted), approve: ctx.snapshot(approve), replay: ctx.snapshot(replay) };
});
