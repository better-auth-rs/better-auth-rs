import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("hashed one-time token response hook works without setting the recipient cookie", async (ctx) => {
  const response = await ctx.actor("owner").fetch("/api/auth/sign-up/email", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: ctx.uniqueEmail("ott-options"), password: "password123", name: "Owner" }) });
  expect(response.status).toBe(200);
  const token = response.headers.get("set-ott");
  expect(token).toMatch(/^[A-Za-z0-9_-]{32}$/);
  expect(response.headers.get("access-control-expose-headers")!.split(",").map((value) => value.trim())).toContain("set-ott");
  const signup = await response.json() as { user: { id: string }; token: string };
  const disabled = await ctx.rawRequest({ actor: "owner", path: "/api/auth/one-time-token/generate" });
  expect(disabled.status).toBe(400);
  expect(disabled.body).toEqual({ message: "Client requests are disabled" });
  const verified = await ctx.rawRequest({ path: "/api/auth/one-time-token/verify", method: "POST", json: { token } });
  expect(verified.status).toBe(200);
  const data = verified.body as { user: { id: string }; session: { token: string } };
  expect(data.user.id).toBe(signup.user.id);
  expect(data.session.token).toBe(signup.token);
  const recipient = await ctx.actor().client.getSession();
  expect(recipient.data).toBeNull();
  const replay = await ctx.rawRequest({ path: "/api/auth/one-time-token/verify", method: "POST", json: { token } });
  expect(replay.status).toBe(400);
  return { disabled, verified, recipient: ctx.snapshot(recipient), replay };
});
