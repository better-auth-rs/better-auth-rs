import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

async function control(ctx: any, body: unknown) {
  const response = await fetch(`${ctx.baseURL}/__test/identity-context`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  expect(response.status).toBe(200); return response.json();
}

compatScenario("Magic Link callbacks see parsed input and preserve proof writes across HTTP and native failures", async ctx => {
  const results = [];
  for (const transport of ["http", "native"]) for (const mode of ["success", "api-error", "ordinary-error"]) {
    const result = await control(ctx, { kind: "magic", transport, mode });
    expect(result.proof).toBe(true);
    expect(result.events).toHaveLength(1);
    expect(result.events[0]).toMatchObject({ event: "magic", email: "magic@example.com", metadata: { label: "metadata" }, stored: true,
      context: { path: "/sign-in/magic-link", request: transport === "http", headers: true, tag: "callback-fixture", bodyKeys: ["email", "metadata"], hasReturned: false } });
    if (mode === "ordinary-error") {
      if (transport === "native") expect(result.output).toEqual({ thrown: true, message: "Callback ordinary failure" });
      else expect(result.output).toMatchObject({ status: 500, error: null, header: null, cookies: [] });
    } else {
      expect(result.output).toMatchObject({ status: mode === "success" ? 200 : 400, header: "magic-send", thrown: mode !== "success" && transport === "native" });
      if (mode === "api-error") expect(result.output.error).toEqual({ code: "CALLBACK_REJECTED", message: "Callback rejected" });
    }
    results.push(result);
  }
  return results;
}, 30_000);

compatScenario("Native callback headers retain omission separately from an explicitly empty set", async ctx => {
  const results = [];
  for (const kind of ["magic", "name"]) for (const headers of ["omit", "empty"]) {
    const result = await control(ctx, { kind, transport: "native", headers });
    if (kind === "magic" && headers === "omit") {
      expect(result.output).toMatchObject({ status: 400, thrown: true, error: { code: "VALIDATION_ERROR", message: "Headers is required" } });
      expect(result.events).toEqual([]); expect(result.proof).toBe(false);
    } else {
      expect(result.output.status).toBe(200);
      expect(result.events[0].context).toMatchObject({ request: false, headers: headers !== "omit", tag: null });
    }
    results.push(result);
  }
  return results;
});

compatScenario("Anonymous name callbacks retain arbitrary body fields and abort before identity creation", async ctx => {
  const results = [];
  for (const transport of ["http", "native"]) for (const mode of ["success", "api-error", "ordinary-error"]) {
    const result = await control(ctx, { kind: "name", transport, mode });
    expect(result.events).toHaveLength(1);
    expect(result.events[0]).toMatchObject({ event: "name", context: { path: "/sign-in/anonymous", request: transport === "http", bodyKeys: ["marker"], hasReturned: false } });
    if (mode === "success") expect(result.output).toMatchObject({ status: 200, name: "Anonymous fixture", publicHidden: false });
    else if (mode === "api-error") expect(result.output).toMatchObject({ status: 400, cookies: [], error: { code: "CALLBACK_REJECTED", message: "Callback rejected" } });
    else if (transport === "http") expect(result.output).toMatchObject({ status: 500, cookies: [], header: null });
    else expect(result.output).toEqual({ thrown: true, message: "Callback ordinary failure" });
    results.push(result);
  }
  return results;
}, 30_000);

compatScenario("Anonymous linking uses the issued hidden identity while preserving failure persistence and response headers", async ctx => {
  const results = [];
  for (const transport of ["http", "native"]) for (const mode of ["success", "api-error", "ordinary-error"]) {
    const result = await control(ctx, { kind: "link", transport, mode, mutate: true });
    const linked = result.events.find((event: any) => event.event === "link");
    expect(linked).toMatchObject({ oldHidden: null, oldSessionHidden: null, newHidden: "issued-secret", newSessionHidden: "hidden-session",
      newName: "Original member", storedName: "Changed after issue", storedHidden: "changed-secret", sameSnapshot: true, oldExists: true,
      context: { request: transport === "http", actorAnonymous: true, hasReturned: true, hasSetCookie: true, returnedHidden: null,
        bodyKeys: ["callbackURL", "email", "password", "unknown"], location: "/completed" } });
    expect(result.sessions).toBe(2);
    expect(result.oldExists).toBe(mode !== "success");
    if (mode === "ordinary-error") {
      if (transport === "native") expect(result.output).toEqual({ thrown: true, message: "Callback ordinary failure" });
      else expect(result.output).toMatchObject({ status: 500, cookies: [], header: null });
    } else {
      expect(result.output.header).toBe("anonymous-link");
      expect(result.output.cookies.map((cookie: any) => cookie.name)).toContain("better-auth.session_token");
      expect(result.output.status).toBe(mode === "success" ? 200 : 400);
    }
    results.push(result);
  }
  return results;
}, 30_000);

compatScenario("Signup rememberMe validates its type and controls both persisted lifetime and cookie persistence", async ctx => {
  const results = [];
  for (const transport of ["http", "native"]) for (const input of [{}, { rememberMe: true }, { rememberMe: false }, { rememberMe: null }, { rememberMe: "false" }, { rememberMe: false, autoSignIn: false }]) {
    const result = await control(ctx, { kind: "signup", transport, ...input });
    if (input.rememberMe === null || input.rememberMe === "false") {
      expect(result.output).toMatchObject({ status: 400, cookies: [], error: { code: "VALIDATION_ERROR", message: `[body.rememberMe] Invalid input: expected boolean, received ${input.rememberMe === null ? "null" : "string"}` } });
      expect(result.memberExists).toBe(false); expect(result.sessions).toBe(0);
    } else if (input.autoSignIn === false) {
      expect(result.output.status).toBe(200); expect(result.output.cookies).toEqual([]); expect(result.sessions).toBe(0);
    } else {
      expect(result.output.status).toBe(200); expect(result.sessions).toBe(1); expect(result.output.publicHidden).toBe(false);
      expect(result.lifetime).toBe(input.rememberMe === false ? 86400 : 3600);
      expect(result.output.cookies).toEqual(input.rememberMe === false
        ? [{ name: "better-auth.session_token", persistent: false }, { name: "better-auth.dont_remember", persistent: false }]
        : [{ name: "better-auth.session_token", persistent: true }]);
    }
    results.push(result);
  }
  return results;
}, 30_000);
