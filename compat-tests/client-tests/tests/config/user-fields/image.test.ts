import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("user and administrator image updates distinguish omission from explicit null", async (ctx) => {
  const post = (path: string, json: unknown, actor = "primary") => ctx.rawRequest({ path: `/api/auth${path}`, method: "POST", json, actor });
  const first = "https://image.example/first.png";
  const second = "https://image.example/second.png";
  const email = ctx.uniqueEmail("image");
  const signedUp = await post("/sign-up/email", { email, password: "Password123!", name: "Image", department: "engineering", image: first });
  expect(signedUp.status).toBe(200);
  expect((signedUp.body as any).user.image).toBe(first);
  const results = [signedUp];
  for (const [body, expected] of [[{ name: "Renamed" }, first], [{ image: second }, second], [{ image: null }, null]] as const) {
    const update = await post("/update-user", body);
    expect(update.status).toBe(200);
    const stored = await ctx.rawRequest({ path: "/api/auth/get-session?disableCookieCache=true" });
    expect((stored.body as any).user.image).toBe(expected);
    results.push(update, stored);
  }
  await ctx.promoteAdmin({ email });
  const signedIn = await ctx.actor("admin").client.signIn.email({ email, password: "Password123!" });
  expect(signedIn.error).toBeNull();
  const created = await post("/admin/create-user", { email: ctx.uniqueEmail("managed-image"), name: "Managed", data: { department: "support", image: null } }, "admin");
  expect(created.status).toBe(200);
  const user = (created.body as any).user;
  expect(user.image).toBeNull();
  results.push(created);
  for (const [data, expected] of [[{ image: first }, first], [{ name: "Renamed" }, first], [{ image: null }, null]] as const) {
    const updated = await post("/admin/update-user", { userId: user.id, data }, "admin");
    expect(updated.status).toBe(200);
    expect((updated.body as any).image).toBe(expected);
    results.push(updated);
  }
  return { results };
});
