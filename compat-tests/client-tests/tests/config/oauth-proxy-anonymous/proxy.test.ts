import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { cookies, start } from "../oauth-proxy/flow";

compatScenario("Proxy restores the anonymous owner from bound OAuth state", async ctx => {
  const anonymous = await ctx.rawRequest({ path: "/api/auth/sign-in/anonymous", method: "POST", json: {} });
  expect(anonymous.status).toBe(200);
  const owner = (anonymous.body as { user: { id: string } }).user.id;
  const flow = await start(ctx);
  const stateCookie = flow.cookie.split("; ").filter(cookie => !cookie.startsWith("better-auth.session_")).join("; ");
  const completion = await fetch(flow.completion, { headers: { cookie: stateCookie }, redirect: "manual" });
  expect(completion.status).toBe(302);
  expect(completion.headers.get("location")).toBe("/welcome");
  expect(completion.headers.getSetCookie().some(cookie => cookie.startsWith("better-auth.state=") && cookie.includes("Max-Age=0"))).toBe(true);
  const session = await ctx.rawRequest({ path: "/api/auth/get-session", headers: { cookie: cookies(completion, stateCookie) } });
  expect(session.status).toBe(200);
  const user = (session.body as { user: { id: string; isAnonymous?: boolean } }).user;
  expect(user.id).not.toBe(owner);
  expect(user.isAnonymous).toBe(false);
  const response = await fetch(`${ctx.baseURL}/__test/identity`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "links" }) });
  expect(response.status).toBe(200);
  const links = await response.json();
  expect(links).toEqual([{ anonymousId: owner, newId: user.id }]);
  return { completion: { status: completion.status, location: completion.headers.get("location") }, session, linked: links.length };
});
