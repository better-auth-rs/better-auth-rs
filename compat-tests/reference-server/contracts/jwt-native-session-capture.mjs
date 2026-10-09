import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { exportJWK, generateKeyPair } from "jose";
import { getJwtToken } from "better-auth/plugins/jwt";
import { createCookieCacheSigner } from "../node_modules/better-auth/dist/plugins/jwt/cookie-cache.mjs";

const baseURL = "http://jwt-native-session.test";

function session(user) {
  return { session: { id: "sid", token: "session-token", userId: "owner" }, user };
}

function observe(value) {
  if (value === undefined) return { undefined: true };
  if (typeof value === "number" && !Number.isFinite(value)) return { number: String(value) };
  if (value instanceof Date) return { date: value.getTime() };
  if (Array.isArray(value)) return value.map(observe);
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([name, entry]) => [name, observe(entry)]));
  return value;
}

function claims(token, cookie) {
  const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString());
  assert(Number.isInteger(payload.iat));
  assert(Number.isInteger(payload.exp));
  if (cookie) {
    // Cookie signing reads the clock separately for iat and exp.
    assert(payload.exp - payload.iat >= 60 && payload.exp - payload.iat <= 61);
  } else assert.equal(payload.exp - payload.iat, 900);
  payload.iat = "now";
  payload.exp = cookie ? "now+60" : "now+900";
  return payload;
}

export async function captureJwtNativeSession() {
  const version = JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")).version;
  const coreVersion = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
  assert.equal(version, "1.7.6");
  assert.equal(coreVersion, "1.7.6");
  const { privateKey, publicKey } = await generateKeyPair("EdDSA", { extractable: true });
  const key = {
    id: "jwt-native-key", alg: "EdDSA", crv: "Ed25519", createdAt: new Date(0),
    publicKey: JSON.stringify(await exportJWK(publicKey)),
    privateKey: JSON.stringify(await exportJWK(privateKey)),
  };
  const users = [
    ["string", { id: "owner", marker: "kept" }],
    ["missing", { marker: "kept" }],
    ["undefined", { id: undefined, marker: "kept" }],
    ["null", { id: null, marker: "kept" }],
    ["false", { id: false, marker: "kept" }],
    ["zero", { id: 0, marker: "kept" }],
    ["empty", { id: "", marker: "kept" }],
    ["number", { id: 7, marker: "kept" }],
    ["nan", { id: NaN, marker: "kept" }],
    ["infinity", { id: Infinity, marker: "kept" }],
    ["many-array", [{ id: "child", marker: "kept" }]],
    ["many-public", { 0: { id: "child", marker: "kept" } }],
    ["null-user", null],
    ["false-user", false],
    ["zero-user", 0],
  ];
  const cases = users.map(([name, user]) => [name, session(user), "none"]);
  cases.push(
    ["missing-callbacks", session({ marker: "kept" }), "both"],
    ["many-callbacks", session([{ id: "child" }]), "both"],
    ["null-user-subject", session(null), "subject"],
    ["absent-session", null, "none"],
    ["absent-session-callbacks", null, "both"],
    ["payload-failure", session({}), "payload-failure"],
    ["subject-failure", session({}), "subject-failure"],
  );
  const captured = [];
  async function capture(name, data, policy, cookie) {
    const events = [];
    const options = {
      jwks: { disablePrivateKeyEncryption: true },
      adapter: { async getJwks(ctx) { events.push(["keys", observe(ctx.context.session)]); return [key]; } },
      jwt: {},
    };
    if (["both", "payload-failure", "subject-failure"].includes(policy)) {
      options.jwt.definePayload = async (value) => {
        events.push(["payload", { native: observe(value), json: JSON.parse(JSON.stringify(value)) }]);
        if (policy === "payload-failure") throw new Error("payload failure");
        return { callback: true };
      };
    }
    if (policy !== "none") {
      options.jwt.getSubject = async (value) => {
        events.push(["subject", { native: observe(value), json: JSON.parse(JSON.stringify(value)) }]);
        if (policy === "subject-failure") throw new Error("subject failure");
        return "callback-subject";
      };
    }
    const ctx = { context: {
      options: { baseURL }, baseURL, adapter: {}, session: cookie ? null : data,
      logger: { debug() {} },
    } };
    let token;
    let result;
    try {
      token = cookie
        ? await createCookieCacheSigner(options).sign(ctx, data, 60)
        : await getJwtToken(ctx, options);
    } catch (error) {
      result = { error: error.message };
    }
    if (token !== undefined) result = { claims: claims(token, cookie) };
    captured.push({ name, result, events });
  }
  for (const [name, data, policy] of cases) await capture(name, data, policy, false);
  for (const [name, user] of users.filter(([name]) => !["null-user", "false-user", "zero-user"].includes(name))) {
    await capture(`cache-${name}`, session(user), "none", true);
  }
  assert.equal(captured.length, 34);
  return { version, cases: captured };
}

if (import.meta.main) {
  const output = `${JSON.stringify(await captureJwtNativeSession(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], output);
  else console.log(output);
}
