import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { TS_BASE_URL, RUST_BASE_URL } from "../../../support/config";

async function control(base: string, body: object) {
  const response = await fetch(`${base}/__test/password-security`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}

compatScenario("default credential hashes interoperate across databases and preserve NFKC scrypt semantics", async ctx => {
  const other = ctx.baseURL === TS_BASE_URL ? RUST_BASE_URL : TS_BASE_URL;
  const password = "Ｆｕｌｌｗｉｄｔｈ123!😀";
  const normalized = password.normalize("NFKC");
  const email = ctx.uniqueEmail("scrypt");
  const signup = await ctx.actor().client.signUp.email({ email, password, name: "Scrypt" });
  expect(signup.error).toBeNull();
  const stored = await control(ctx.baseURL, { action: "read", email });
  expect(stored.body.hash).toMatch(/^[0-9a-f]{32}:[0-9a-f]{128}$/);
  expect((await control(other, { action: "verify", hash: stored.body.hash, password: normalized })).body).toEqual({ valid: true });
  expect((await control(ctx.baseURL, { action: "verify", hash: `${stored.body.hash}:ignored`, password: normalized })).body).toEqual({ valid: true });
  expect((await control(ctx.baseURL, { action: "verify", hash: stored.body.hash, password: "wrong" })).body).toEqual({ valid: false });
  const [salt, digest] = stored.body.hash.split(":");
  expect((await control(ctx.baseURL, { action: "verify", hash: `${salt}:${digest.toUpperCase()}`, password })).body).toEqual({ valid: false });
  expect((await control(ctx.baseURL, { action: "verify", hash: "$argon2id$invalid", password })).status).toBe(500);

  const remoteEmail = ctx.uniqueEmail("remote-scrypt");
  const remoteSignup = await fetch(`${other}/api/auth/sign-up/email`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: remoteEmail, password, name: "Remote" }) });
  expect(remoteSignup.status).toBe(200);
  const remoteStored = await control(other, { action: "read", email: remoteEmail });
  expect(remoteStored.body.hash).toMatch(/^[0-9a-f]{32}:[0-9a-f]{128}$/);
  expect((await control(ctx.baseURL, { action: "write", email, hash: remoteStored.body.hash })).body).toEqual({ ok: true });
  const imported = await ctx.actor("imported").client.signIn.email({ email, password: normalized });
  expect(imported.error).toBeNull();
  const rejected = await ctx.actor("wrong").client.signIn.email({ email, password: "WrongPassword123!" });
  expect(rejected.error?.status).toBe(401);
  await control(ctx.baseURL, { action: "write", email, hash: "malformed" });
  const malformed = await ctx.rawRequest({ actor: "malformed", path: "/api/auth/sign-in/email", method: "POST", json: { email, password } });
  expect(malformed).toEqual({ status: 500, location: null, body: null });
  await control(ctx.baseURL, { action: "write", email, hash: "" });
  const empty = await ctx.actor("empty").client.signIn.email({ email, password });
  expect(empty.error?.status).toBe(401);
  return { signup: ctx.snapshot(signup), imported: ctx.snapshot(imported), rejected: ctx.snapshot(rejected), malformed, empty: ctx.snapshot(empty) };
}, 30_000);
