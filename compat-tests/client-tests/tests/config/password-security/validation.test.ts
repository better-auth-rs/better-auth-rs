import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("email sign-in validates the complete schema before email checks or password hashing", async ctx => {
  await fetch(`${ctx.baseURL}/__test/password-security`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "configure" }) });
  const invalid = [
    {},
    { email: "invalid-email" },
    { password: "password123" },
    { email: 42, password: null, callbackURL: false, rememberMe: "true" },
    { email: "valid@example.com", password: [] },
  ];
  const responses = [];
  for (const json of invalid) {
    const response = await ctx.rawRequest({ path: "/api/auth/sign-in/email", method: "POST", json });
    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({ code: "VALIDATION_ERROR" });
    responses.push(response);
  }
  expect(responses[0].body).toEqual({ code: "VALIDATION_ERROR", message: "[body.email] Invalid input: expected string, received undefined; [body.password] Invalid input: expected string, received undefined" });
  const state = await fetch(`${ctx.baseURL}/__test/password-security`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }).then(response => response.json());
  expect(state).toEqual({ hashes: [], requests: [] });
  return { responses, state };
});
