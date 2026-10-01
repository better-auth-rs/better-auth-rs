import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { cookies } from "../oauth-proxy/flow";

compatScenario("revoking the final device session clears every cached session chunk", async ctx => {
  const signup = await ctx.actor().fetch(`${ctx.baseURL}/api/auth/sign-up/email`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: ctx.uniqueEmail("multi-chunks"), password: "password123", name: "Chunks" }),
  });
  expect(signup.status).toBe(200);
  const { token } = await signup.json();
  const chunkNames = ["better-auth.session_data.0", "better-auth.session_data.1"];
  const cookie = `${cookies(signup)}; ${chunkNames.map(name => `${name}=stale`).join("; ")}; better-auth.session_data.01=unrelated`;
  const revoked = await ctx.actor().fetch(`${ctx.baseURL}/api/auth/multi-session/revoke`, {
    method: "POST", headers: { cookie, "content-type": "application/json" }, body: JSON.stringify({ sessionToken: token }),
  });
  expect(revoked.status).toBe(200);
  expect(await revoked.json()).toEqual({ status: true });
  for (const name of chunkNames) {
    expect(revoked.headers.getSetCookie().some(value => value.startsWith(`${name}=`) && value.includes("Max-Age=0"))).toBe(true);
  }
  expect(revoked.headers.getSetCookie().some(value => value.startsWith("better-auth.session_data.01="))).toBe(false);
  const session = await ctx.actor().client.getSession();
  expect(session.data).toBeNull();
  return { cleared: chunkNames, session };
});

compatScenario("multi-session switches only signed device sessions and revokes all on sign-out", async (ctx) => {
  const browser = ctx.actor();
  const first = await browser.client.signUp.email({ email: ctx.uniqueEmail("multi-first"), password: "password123", name: "First" });
  const second = await browser.client.signUp.email({ email: ctx.uniqueEmail("multi-second"), password: "password123", name: "Second" });
  expect(first.error).toBeNull();
  expect(second.error).toBeNull();
  const list = await ctx.rawRequest({ path: "/api/auth/multi-session/list-device-sessions" });
  expect(list.status).toBe(200);
  const sessions = list.body as Array<{ user: { id: string; email: string }; session: { token: string } }>;
  expect(sessions.map((value) => value.user.id).sort()).toEqual([first.data!.user.id, second.data!.user.id].sort());
  const stolen = await ctx.rawRequest({ actor: "stranger", path: "/api/auth/multi-session/set-active", method: "POST", json: { sessionToken: first.data!.token } });
  expect(stolen.status).toBe(401);
  expect(stolen.body).toEqual({ code: "INVALID_SESSION_TOKEN", message: "Invalid session token" });
  const active = await ctx.rawRequest({ path: "/api/auth/multi-session/set-active", method: "POST", json: { sessionToken: first.data!.token } });
  expect(active.status).toBe(200);
  expect((await browser.client.getSession()).data!.user.id).toBe(first.data!.user.id);
  const revoked = await ctx.rawRequest({ path: "/api/auth/multi-session/revoke", method: "POST", json: { sessionToken: first.data!.token } });
  expect(revoked.status).toBe(200);
  expect((await browser.client.getSession()).data!.user.id).toBe(second.data!.user.id);
  const signedOut = await browser.client.signOut();
  expect(signedOut.error).toBeNull();
  const empty = await ctx.rawRequest({ path: "/api/auth/multi-session/list-device-sessions" });
  expect(empty.body).toEqual([]);
  const replay = await ctx.rawRequest({ path: "/api/auth/multi-session/set-active", method: "POST", json: { sessionToken: second.data!.token } });
  expect(replay.status).toBe(401);
  // Upstream database adapters do not order findSessions results.
  const ordered = sessions.toSorted((left, right) => left.user.email.localeCompare(right.user.email));
  return { list: { ...list, body: ordered }, stolen, active, revoked, signedOut: ctx.snapshot(signedOut), empty, replay };
});
