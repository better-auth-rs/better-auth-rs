import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];
async function control(ctx: Context, body: any = {}) {
  const response = await fetch(`${ctx.baseURL}/__test/oauth-link-id-token`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  expect(response.status).toBe(200);
  return response.json();
}
const post = (ctx: Context, path: string, json: unknown) => ctx.rawRequest({ path: `/api/auth${path}`, method: "POST", json });
async function setup(ctx: Context, suffix: string) {
  const email = ctx.uniqueEmail(suffix);
  const signup = await post(ctx, "/sign-up/email", { name: "Original", email, password: "Password123!" });
  expect(signup.status).toBe(200);
  const provider = { id: ctx.uniqueToken(suffix), email, emailVerified: true, name: "Provider", image: "https://example.com/profile.png", department: "engineering", internalCode: "untrusted" };
  await control(ctx, { provider, clear: true });
  return { email, provider };
}
const link = (ctx: Context, token: any = {}) => post(ctx, "/link-social", { provider: "google", idToken: { token: "id-token", ...token } });

export function linkScenarios(disabled: boolean) {
  compatScenario("owned provider image keeps omission distinct from explicit null", async ctx => {
    const { email, provider } = await setup(ctx, "link-image");
    await control(ctx, { email, seed: true, clear: true });
    const { image: originalImage, ...withoutImage } = provider;
    const observations: unknown[] = [];
    for (const [profile, expected, patch] of [
      [{ ...provider, image: "https://example.com/updated.png" }, "https://example.com/updated.png", { image: "https://example.com/updated.png" }],
      [withoutImage, "https://example.com/updated.png", {}],
      [{ ...provider, image: null }, null, { image: null }],
      [{ ...provider, image: originalImage }, originalImage, { image: originalImage }],
    ] as const) {
      await control(ctx, { provider: profile, clear: true });
      const result = await link(ctx, { accessToken: "image-access" });
      expect(result.status).toBe(200);
      const snapshot = await control(ctx, { email });
      expect(snapshot.user.image).toBe(expected);
      expect(snapshot.imageUpdates).toEqual([patch]);
      expect(snapshot.events).toEqual(["account.update.before", "account.update.after", "user.update.before", "user.update.after"]);
      expect(snapshot.account.accessToken).toBe("image-access");
      const accounts = await ctx.actor().client.listAccounts();
      expect(accounts.error).toBeNull();
      const account = accounts.data!.find(row => row.providerId === "google")!;
      const info = await ctx.rawRequest({ path: `/api/auth/account-info?accountId=${encodeURIComponent(account.id)}` });
      expect(info.status).toBe(200);
      if (Object.hasOwn(patch, "image")) expect((info.body as any).user.image).toBe(expected);
      else expect((info.body as any).user).not.toHaveProperty("image");
      observations.push({ result, snapshot, info });
    }
    return observations;
  });
  compatScenario("owned ID-token link refreshes tokens and profile before linking policy", async ctx => {
    const { email, provider } = await setup(ctx, "owned-link");
    await control(ctx, { email, seed: true, clear: true });
    await control(ctx, { provider: { ...provider, email: "different@example.com", emailVerified: false } });
    const refreshed = await link(ctx, { token: "new-id", accessToken: "new-access", refreshToken: "new-refresh", expiresAt: 123, scopes: ["discarded"] });
    expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
    const first = await control(ctx, { email });
    expect(first.account).toEqual({ accessToken: "new-access", refreshToken: "new-refresh", idToken: "new-id", scope: "seed-scope", accessTokenExpiresAt: null, encrypted: true });
    expect(first.user).toEqual({ name: "Provider", email, emailVerified: false, image: provider.image, department: "engineering", internalCode: "protected" });
    expect(first.events).toEqual(["account.update.before", "account.update.after", "user.update.before", "user.update.after"]);
    expect(first.admissions).toBe(0);
    await control(ctx, { clear: true });
    const omitted = await link(ctx, { token: "omitted-id" });
    expect(omitted.status).toBe(200);
    const second = await control(ctx, { email });
    expect(second.account).toMatchObject({ accessToken: "new-access", refreshToken: "new-refresh", idToken: "omitted-id" });
    const empty = await link(ctx, { token: "empty-id", accessToken: "", refreshToken: "" });
    expect(empty.status).toBe(200);
    const third = await control(ctx, { email });
    expect(third.account).toMatchObject({ accessToken: "", refreshToken: "", idToken: "empty-id", encrypted: false });
    return { refreshed, first, omitted, second, empty, third };
  });
  compatScenario("new ID-token links enforce exact policy errors without writes", async ctx => {
    const { email, provider } = await setup(ctx, "link-policy");
    await control(ctx, { provider: { ...provider, emailVerified: false } });
    const unverified = await link(ctx);
    expect(unverified.status).toBe(401);
    expect(unverified.body).toEqual({ code: "LINKING_NOT_ALLOWED", message: "Account not linked - linking not allowed" });
    await control(ctx, { provider: { ...provider, email: "different@example.com" } });
    const different = await link(ctx);
    expect(different.status).toBe(401);
    expect(different.body).toEqual(disabled ? unverified.body : { code: "LINKING_DIFFERENT_EMAILS_NOT_ALLOWED", message: "Account not linked - different emails not allowed" });
    const snapshot = await control(ctx, { email });
    expect(snapshot.account).toBeNull(); expect(snapshot.events).toEqual([]); expect(snapshot.admissions).toBe(0);
    return { unverified, different, snapshot };
  });
  if (disabled) return;
  compatScenario("nested account cancellation remains a hook error instead of cancelling the outer write", async ctx => {
    const { email } = await setup(ctx, "link-nested-cancel");
    await control(ctx, { failure: "account.create.nested" });
    const result = await link(ctx);
    expect(result.status).toBe(417);
    expect(result.body).toEqual({ code: "LINKING_FAILED", message: "Account not linked - unable to create account" });
    const snapshot = await control(ctx, { email });
    expect(snapshot.account).toBeNull(); expect(snapshot.nestedAccounts).toBe(0);
    expect(snapshot.user.name).toBe("Original");
    expect(snapshot.events).toEqual(["account.create.before", "account.create.nested"]);
    return { result, snapshot };
  });
  for (const operation of ["create", "update"] as const) {
    compatScenario(`account ${operation} cancellation still synchronizes the linked user profile`, async ctx => {
      const { email } = await setup(ctx, `link-cancel-${operation}`);
      if (operation === "update") await control(ctx, { email, seed: true });
      await control(ctx, { clear: true, failure: `account.${operation}.before.cancel` });
      const result = await link(ctx, { accessToken: "ignored-access" });
      expect(result.status).toBe(200);
      const snapshot = await control(ctx, { email });
      if (operation === "create") expect(snapshot.account).toBeNull();
      else expect(snapshot.account.accessToken).toBe("seed-access");
      expect(snapshot.user.name).toBe("Provider");
      expect(snapshot.user.department).toBe("engineering");
      expect(snapshot.events).toEqual([`account.${operation}.before`, "user.update.before", "user.update.after"]);
      expect(snapshot.admissions).toBe(0);
      return { result, snapshot };
    });
  }
  compatScenario("another owner conflicts before email policy and cannot refresh their tokens", async ctx => {
    const { email, provider } = await setup(ctx, "link-first-owner");
    const first = await link(ctx, { accessToken: "owner-access" }); expect(first.status).toBe(200);
    await ctx.actor().client.signOut();
    const other = await setup(ctx, "link-other-owner");
    await control(ctx, { provider, clear: true });
    const rejected = await link(ctx, { accessToken: "attacker-access" });
    expect(rejected.status).toBe(409);
    expect(rejected.body).toEqual({ code: "SOCIAL_ACCOUNT_ALREADY_LINKED", message: "Social account already linked" });
    const owner = await control(ctx, { email }); const attacker = await control(ctx, { email: other.email });
    expect(owner.account.accessToken).toBe("owner-access"); expect(attacker.account).toBeNull(); expect(owner.events).toEqual([]);
    return { first, rejected, owner, attacker };
  });
  for (const phase of ["before", "after"] as const) {
    compatScenario(`account create ${phase} exception returns 417 with upstream persistence order`, async ctx => {
      const { email } = await setup(ctx, `link-account-${phase}`);
      await control(ctx, { failure: `account.create.${phase}` });
      const result = await link(ctx, { accessToken: "created-access", expiresAt: 123, scopes: ["discarded"] });
      expect(result.status).toBe(417);
      expect(result.body).toEqual({ code: "LINKING_FAILED", message: "Account not linked - unable to create account" });
      const snapshot = await control(ctx, { email });
      expect(snapshot.account !== null).toBe(phase === "after");
      if (snapshot.account) expect(snapshot.account).toMatchObject({ accessToken: "created-access", scope: null, accessTokenExpiresAt: null });
      expect(snapshot.user.name).toBe("Original"); expect(snapshot.admissions).toBe(0);
      expect(snapshot.events).toEqual(phase === "before" ? ["account.create.before"] : ["account.create.before", "account.create.after"]);
      return { result, snapshot };
    });
    compatScenario(`profile update ${phase} exception preserves successful account link`, async ctx => {
      const { email } = await setup(ctx, `link-user-${phase}`);
      await control(ctx, { failure: `user.update.${phase}` });
      const result = await link(ctx, { accessToken: "created-access" }); expect(result.status).toBe(200);
      const snapshot = await control(ctx, { email });
      expect(snapshot.account.accessToken).toBe("created-access");
      expect(snapshot.user.name).toBe(phase === "before" ? "Original" : "Provider");
      expect(snapshot.user.department).toBe(phase === "before" ? null : "engineering");
      expect(snapshot.events).toEqual(["account.create.before", "account.create.after", "user.update.before", ...(phase === "after" ? ["user.update.after"] : [])]);
      expect(snapshot.admissions).toBe(0);
      return { result, snapshot };
    });
  }
}
