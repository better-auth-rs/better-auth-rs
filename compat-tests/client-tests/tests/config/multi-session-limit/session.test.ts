import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("multi-session enforces its device limit and replaces the same account", async (ctx) => {
  const browser = ctx.actor();
  const email = ctx.uniqueEmail("multi-limit-first");
  const first = await browser.client.signUp.email({ email, password: "password123", name: "First" });
  const second = await browser.client.signUp.email({ email: ctx.uniqueEmail("multi-limit-second"), password: "password123", name: "Second" });
  const third = await browser.client.signUp.email({ email: ctx.uniqueEmail("multi-limit-third"), password: "password123", name: "Third" });
  expect(first.error).toBeNull();
  expect(second.error).toBeNull();
  expect(third.error).toBeNull();
  const list = await ctx.rawRequest({ path: "/api/auth/multi-session/list-device-sessions" });
  const sessions = list.body as Array<{ user: { id: string; email: string }; session: { token: string } }>;
  expect(sessions).toHaveLength(2);
  expect(sessions.map((session) => session.user.id).sort()).toEqual([first.data!.user.id, second.data!.user.id].sort());
  const replaced = await browser.client.signIn.email({ email, password: "password123" });
  expect(replaced.error).toBeNull();
  const updated = await ctx.rawRequest({ path: "/api/auth/multi-session/list-device-sessions" });
  const next = updated.body as typeof sessions;
  expect(next).toHaveLength(2);
  expect(next.find((session) => session.user.id === first.data!.user.id)!.session.token).toBe(replaced.data!.token);
  expect(next.some((session) => session.session.token === first.data!.token)).toBe(false);
  const previous = await ctx.rawRequest({ path: "/api/auth/multi-session/set-active", method: "POST", json: { sessionToken: first.data!.token } });
  expect(previous.status).toBe(401);
  // Upstream database adapters do not order findSessions results.
  const byEmail = (left: (typeof sessions)[number], right: (typeof sessions)[number]) => left.user.email.localeCompare(right.user.email);
  return { list: { ...list, body: sessions.toSorted(byEmail) }, updated: { ...updated, body: next.toSorted(byEmail) }, previous };
});
