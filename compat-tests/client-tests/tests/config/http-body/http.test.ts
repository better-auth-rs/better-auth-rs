import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

const profile = process.env.COMPAT_PROFILE;

compatScenario("email signup accepts form data and persists the credential", async ctx => {
  const email = ctx.uniqueEmail("form-signup");
  const password = "FormPassword123!";
  const response = await fetch(`${ctx.baseURL}/api/auth/sign-up/email`, {
    method: "POST",
    body: new URLSearchParams({ email, password, name: "Form User" }),
  });
  const body = await response.json();
  expect(response.status).toBe(200);
  expect(body.user).toMatchObject({ email, name: "Form User" });
  expect(typeof body.token).toBe("string");
  const login = await ctx.actor().client.signIn.email({ email, password });
  expect(login.error).toBeNull();
  return { status: response.status, body, login };
});

if (profile === "http-body") {
  compatScenario("device code and OAuth callbacks retain their form media exceptions", async ctx => {
    const device = await ctx.rawRequest({
      path: "/api/auth/device/code", method: "POST", body: new URLSearchParams({ client_id: "form-client", scope: "read" }),
    });
    expect(device.status).toBe(200);
    const deviceBody = device.body as Record<string, any>;
    expect(deviceBody.device_code).toMatch(/^[A-Za-z0-9_-]{40}$/);
    expect(deviceBody.user_code).toMatch(/^[A-Z0-9]{8}$/);
    expect(new URL(deviceBody.verification_uri_complete).searchParams.get("user_code")).toBe(deviceBody.user_code);
    const callback = await ctx.rawRequest({
      path: "/api/auth/callback/github", method: "POST", redirect: "manual",
      body: new URLSearchParams({ error: "access_denied", state: "form-state" }),
    });
    expect(callback.status).toBe(302);
    expect(callback.location).toContain("/api/auth/callback/github?");
    return {
      device: { status: device.status, location: device.location, expiresIn: deviceBody.expires_in, interval: deviceBody.interval, verification_uri: deviceBody.verification_uri },
      callback,
    };
  });

  compatScenario("core and default plugin routes decode HTTP bodies before origin and authentication", async ctx => {
    const results = [];
    for (const path of ["/update-user", "/api-key/create"]) {
      for (const [contentType, body, status] of [
        ["text/plain", "{}", 415],
        ["application/json", "{", 400],
        ["application/json", "{}", 403],
      ] as const) {
        const response = await fetch(`${ctx.baseURL}/api/auth${path}`, {
          method: "POST",
          headers: { "content-type": contentType, cookie: "unrelated=present", origin: "https://attacker.invalid" },
          body,
        });
        const result = { status: response.status, body: await response.json() };
        expect(result.status, JSON.stringify({ path, contentType, result })).toBe(status);
        if (status === 415) expect(result.body).toEqual({
          code: "UNSUPPORTED_MEDIA_TYPE",
          message: 'Content-Type "text/plain" is not allowed. Allowed types: application/json',
        });
        if (status === 400) expect(result.body).toEqual({ code: "BAD_REQUEST", message: "Invalid JSON in request body" });
        results.push(result);
      }
    }
    return results;
  });
}

compatScenario("explicit CSRF false preserves form navigation protection when origin validation is disabled", async ctx => {
  const email = ctx.uniqueEmail("csrf-form");
  const password = "FormPassword123!";
  expect((await ctx.actor().client.signUp.email({ email, password, name: "CSRF User" })).error).toBeNull();
  const observations = [];
  // Direct fetch leaves Cookie absent, exercising first-login Fetch Metadata validation.
  for (const path of ["/sign-in/email", "/sign-up/email"]) {
    const response = await fetch(`${ctx.baseURL}/api/auth${path}`, {
      method: "POST",
      headers: { "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate" },
      body: new URLSearchParams({ email: path === "/sign-in/email" ? email : ctx.uniqueEmail("csrf-signup"), password, name: "CSRF User" }),
    });
    const body = await response.json();
    expect(response.status).toBe(profile === "http-body-csrf-legacy" ? 200 : 403);
    if (response.status === 403) expect(body.code).toBe("CROSS_SITE_NAVIGATION_LOGIN_BLOCKED");
    observations.push({ status: response.status, body });
  }
  return observations;
}, 30_000);
