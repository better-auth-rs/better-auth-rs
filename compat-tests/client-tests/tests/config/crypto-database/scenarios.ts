import { expect } from "bun:test";
import { EncryptJWT, decodeProtectedHeader } from "jose";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { compatScenario } from "../../../support/scenario";
import { TS_BASE_URL, RUST_BASE_URL } from "../../../support/config";
import { cookies } from "../oauth-proxy/flow";

const current = "current-rotation-key-with-32-characters-123";
const previous = "previous-rotation-key-with-32-characters-456";
const legacy = "compat-test-only-key-not-real-minimum-32chars";
const secrets = [{ version: 2, value: current }, { version: 1, value: previous }];
const peer = (base: string) => base === TS_BASE_URL ? RUST_BASE_URL : TS_BASE_URL;

async function control(base: string, body: object) {
  const response = await fetch(`${base}/__test/crypto`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  expect(response.status).toBe(200);
  return response.json();
}

async function begin(base: string) {
  const response = await fetch(`${base}/api/auth/sign-in/social`, { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ provider: "google", callbackURL: "/return", errorCallbackURL: "/failure?from=oauth", disableRedirect: true }) });
  expect(response.status).toBe(200);
  const state = new URL((await response.json()).url).searchParams.get("state")!;
  expect(state).toMatch(/^[A-Za-z0-9_-]{32}$/);
  return { state, cookie: cookies(response) };
}

const cookieValue = (cookie: string, name: string) => cookie.split("; ").find(pair => pair.startsWith(`${name}=`))!.slice(name.length + 1);
const callback = (base: string, state: string, cookie = "", extra = {}) => fetch(`${base}/api/auth/callback/google?${new URLSearchParams({ state, code: "compat-code", ...extra })}`, { headers: { cookie }, redirect: "manual" });

export function registerCryptoScenarios(cookieState: boolean) {
  compatScenario("XChaCha records interoperate with retained, retired and explicit legacy keys", async ctx => {
    const other = peer(ctx.baseURL);
    const plaintext = "节点🔐\u0000token";
    const produced = await control(ctx.baseURL, { operation: "encrypt", data: plaintext });
    expect(produced.ok).toBe(true);
    expect(produced.value).toMatch(/^\$ba\$2\$[0-9a-f]+$/);
    expect(await control(other, { operation: "decrypt", data: produced.value })).toEqual({ ok: true, value: plaintext });
    const old = await control(other, { operation: "encrypt", secrets: [secrets[1]], data: plaintext });
    expect(await control(ctx.baseURL, { operation: "decrypt", data: old.value })).toEqual({ ok: true, value: plaintext });
    expect(await control(ctx.baseURL, { operation: "decrypt", secrets: [secrets[0]], data: old.value })).toEqual({ ok: false });
    const bare = await control(other, { operation: "encrypt", secret: legacy, data: "\ufeff" + plaintext });
    expect(await control(ctx.baseURL, { operation: "decrypt", data: bare.value })).toEqual({ ok: true, value: plaintext });
    expect(await control(ctx.baseURL, { operation: "decrypt", secrets, data: bare.value })).toEqual({ ok: false });
    expect(await control(ctx.baseURL, { operation: "decrypt", secret: current, data: produced.value })).toEqual({ ok: false });
    expect(await control(ctx.baseURL, { operation: "decrypt", data: produced.value.replace("$2$", "$ +2suffix$") })).toEqual({ ok: true, value: plaintext });
    for (const data of ["$ba$999$00", "$ba$2$0g", "00", produced.value.slice(0, -2)]) {
      expect(await control(ctx.baseURL, { operation: "decrypt", data })).toEqual({ ok: false });
    }
    return { plaintext, version: 2, retained: true, retired: false, legacy: true };
  });

  compatScenario("encrypted JWTs preserve key selection, legacy fallback, purpose and claim checks", async ctx => {
    const other = peer(ctx.baseURL);
    const payload = { marker: "account-secret", nested: { scope: ["read"] } };
    const encoded = await control(ctx.baseURL, { operation: "encode", data: payload });
    expect(decodeProtectedHeader(encoded.value)).toMatchObject({ alg: "dir", enc: "A256CBC-HS512", kid: expect.any(String) });
    const decoded = await control(other, { operation: "decode", data: encoded.value });
    expect(decoded.value).toMatchObject(payload);
    expect(decoded.value.exp - decoded.value.iat).toBe(3600);
    expect(decoded.value.jti).toEqual(expect.any(String));
    expect((await control(other, { operation: "decode", data: encoded.value, salt: "wrong-purpose" })).value).toBeNull();
    const old = await control(other, { operation: "encode", data: payload, secrets: [secrets[1]] });
    expect((await control(ctx.baseURL, { operation: "decode", data: old.value })).value).toMatchObject(payload);
    expect((await control(ctx.baseURL, { operation: "decode", secrets: [secrets[0]], data: old.value })).value).toBeNull();
    const bare = await control(other, { operation: "encode", data: payload, secret: legacy });
    expect((await control(ctx.baseURL, { operation: "decode", data: bare.value })).value).toMatchObject(payload);
    for (const secret of [previous, legacy]) {
      const key = hkdf(sha256, new TextEncoder().encode(secret), new TextEncoder().encode("better-auth-account"), new TextEncoder().encode("BetterAuth.js Generated Encryption Key"), 64);
      const token = await new EncryptJWT(payload).setProtectedHeader({ alg: "dir", enc: "A256CBC-HS512" }).encrypt(key);
      expect((await control(ctx.baseURL, { operation: "decode", data: token })).value).toEqual(payload);
      const unknown = await new EncryptJWT(payload).setProtectedHeader({ alg: "dir", enc: "A256CBC-HS512", kid: "unknown" }).encrypt(key);
      expect((await control(ctx.baseURL, { operation: "decode", data: unknown })).value).toBeNull();
    }
    for (const claims of [{ nbf: Math.floor(Date.now()/1000)+1000 }, { nbf: "invalid" }, { iat: "invalid" }]) {
      const key = hkdf(sha256, new TextEncoder().encode(current), new TextEncoder().encode("better-auth-account"), new TextEncoder().encode("BetterAuth.js Generated Encryption Key"), 64);
      const token = await new EncryptJWT(claims as any).setProtectedHeader({ alg: "dir", enc: "A256CBC-HS512" }).encrypt(key);
      expect((await control(ctx.baseURL, { operation: "decode", data: token })).value).toBeNull();
    }
    const expired = await control(other, { operation: "encode", data: payload, expiresIn: -30 });
    expect((await control(ctx.baseURL, { operation: "decode", data: expired.value })).value).toBeNull();
    return payload;
  });

  compatScenario("OAuth state and account cookies complete across runtimes with encrypted stored tokens", async ctx => {
    const other = peer(ctx.baseURL);
    await fetch(`${other}/__test/reset-state`, { method: "POST" });
    const flow = await begin(ctx.baseURL);
    if (cookieState) {
      const decoded = await control(other, { operation: "decrypt", data: decodeURIComponent(cookieValue(flow.cookie, "better-auth.oauth_state")) });
      const payload = JSON.parse(decoded.value);
      expect(payload.oauthState).toBe(flow.state);
      expect(payload.codeVerifier).toHaveLength(128);
    } else {
      const stored = await control(ctx.baseURL, { operation: "state", state: flow.state });
      const payload = JSON.parse(stored.value);
      expect(payload.oauthState).toBe(flow.state);
      expect(payload.codeVerifier).toHaveLength(128);
      await control(other, { operation: "state", state: flow.state, value: stored.value });
      expect(decodeURIComponent(cookieValue(flow.cookie, "better-auth.state")).startsWith(`${flow.state}.`)).toBe(true);
    }
    const response = await callback(other, flow.state, flow.cookie);
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/return");
    const cookie = cookies(response, flow.cookie);
    const session = await fetch(`${other}/api/auth/get-session`, { headers: { cookie } }).then(r => r.json());
    expect(session.user.email).toBe("google@example.com");
    const stored = await control(other, { operation: "accounts", email: "google@example.com" });
    expect(stored).toHaveLength(1);
    expect(stored[0].accessToken).toMatch(/^\$ba\$2\$/);
    expect(stored[0].refreshToken).toMatch(/^\$ba\$2\$/);
    expect(stored[0].idToken).toBe("google-id-token");
    const accountToken = cookieValue(cookie, "better-auth.account_data");
    const account = await control(ctx.baseURL, { operation: "decode", data: accountToken });
    expect(account.value.userId).toBe(session.user.id);
    const reencoded = await control(ctx.baseURL, { operation: "encode", data: account.value, expiresIn: 300 });
    const importedCookie = cookie.replace(accountToken, reencoded.value);
    const accessResponse = await fetch(`${other}/api/auth/get-access-token`, { method: "POST", headers: { cookie: importedCookie, origin: other, "content-type": "application/json" }, body: JSON.stringify({ useAccountCookie: true }) });
    expect(accessResponse.status).toBe(200);
    const access = await accessResponse.json();
    const clearAccess = await control(ctx.baseURL, { operation: "decrypt", data: stored[0].accessToken });
    expect(access.accessToken).toBe(clearAccess.value);
    expect(access.idToken).toBe("google-id-token");
    if (!cookieState) expect((await control(other, { operation: "state", state: flow.state })).value).toBeNull();
    return { completed: true, stateStrategy: cookieState ? "cookie" : "database", encrypted: true, idToken: stored[0].idToken };
  });

  compatScenario("account cookie chunks cross runtimes and expire when replaced or signed out", async ctx => {
    const other = peer(ctx.baseURL);
    await fetch(`${other}/__test/reset-state`, { method: "POST" });
    const flow = await begin(ctx.baseURL);
    const login = await callback(ctx.baseURL, flow.state, flow.cookie);
    expect(login.status).toBe(302);
    let cookie = cookies(login, flow.cookie);
    const session = await fetch(`${ctx.baseURL}/api/auth/get-session`, { headers: { cookie } }).then(r => r.json());
    // Share only the persisted user identity. Both runtimes create their own real OAuth sessions.
    expect(await control(other, { operation: "user", id: session.user.id, email: session.user.email })).toEqual({ id: session.user.id });
    const otherFlow = await begin(other);
    const otherLogin = await callback(other, otherFlow.state, otherFlow.cookie);
    expect(otherLogin.status).toBe(302);
    const otherCookie = cookies(otherLogin, otherFlow.cookie);
    const accountName = "better-auth.account_data";
    const scope = "scope-" + "x".repeat(5000);
    const accountId = await ctx.seedOAuthAccount({ email: session.user.email, providerId: "google", accountId: "chunk-account", scope });
    const request = (base: string, cookie: string, selection: object) => fetch(`${base}/api/auth/get-access-token`, {
      method: "POST", headers: { cookie, origin: base, "content-type": "application/json" }, body: JSON.stringify(selection),
    });
    const large = await request(ctx.baseURL, cookie, { accountId });
    expect(large.status).toBe(200);
    const largeBody = await large.json();
    expect(largeBody.accessToken).toBe("google-access-token");
    expect(largeBody.scopes).toEqual([scope]);
    const headers = large.headers.getSetCookie().filter(value => value.startsWith(accountName));
    expect(headers.every(value => value.length <= 4050)).toBe(true);
    expect(headers.some(value => value.startsWith(`${accountName}=`) && value.includes("Max-Age=0"))).toBe(true);
    const chunkNames = headers.filter(value => !value.includes("Max-Age=0")).map(value => value.split("=")[0]);
    expect(chunkNames.length).toBeGreaterThan(1);
    expect(chunkNames).toEqual(chunkNames.map((_, index) => `${accountName}.${index}`));
    cookie = cookies(large, cookie);
    const accountPairs = cookie.split("; ").filter(value => value.startsWith(`${accountName}.`));
    const transferred = [...otherCookie.split("; ").filter(value => !value.startsWith(accountName)), ...accountPairs].join("; ");
    const imported = await request(other, transferred, { useAccountCookie: true });
    expect(imported.status).toBe(200);
    expect(await imported.json()).toEqual(largeBody);
    const logout = await fetch(`${other}/api/auth/sign-out`, { method: "POST", headers: { cookie: transferred, origin: other, "content-type": "application/json" }, body: "{}" });
    expect(logout.status).toBe(200);
    for (const name of chunkNames) {
      expect(logout.headers.getSetCookie().some(value => value.startsWith(`${name}=`) && value.includes("Max-Age=0"))).toBe(true);
    }
    expect(cookies(logout, transferred).split("; ").some(value => value.startsWith(accountName))).toBe(false);
    const smallAccountId = await ctx.seedOAuthAccount({ email: session.user.email, providerId: "google", accountId: "compact-account", scope: "openid" });
    const small = await request(ctx.baseURL, cookie, { accountId: smallAccountId });
    const smallBody = await small.json();
    expect({ status: small.status, body: smallBody }).toMatchObject({ status: 200, body: { scopes: ["openid"] } });
    expect(small.headers.getSetCookie().some(value => value.startsWith(`${accountName}=`) && !value.includes("Max-Age=0"))).toBe(true);
    for (const name of chunkNames) {
      expect(small.headers.getSetCookie().some(value => value.startsWith(`${name}=`) && value.includes("Max-Age=0"))).toBe(true);
    }
    const compactCookie = cookies(small, cookie);
    expect(compactCookie.split("; ").filter(value => value.startsWith(accountName))).toHaveLength(1);
    const final = await request(ctx.baseURL, compactCookie, { useAccountCookie: true });
    expect(final.status).toBe(200);
    expect((await final.json()).accessToken).toBe("google-access-token");
    return { chunks: chunkNames.length, transfer: true, compact: true, signedOut: true };
  });

  compatScenario("access token retrieval decrypts only necessary credentials and preserves its failure boundary", async ctx => {
    const flow = await begin(ctx.baseURL);
    const login = await callback(ctx.baseURL, flow.state, flow.cookie);
    expect(login.status).toBe(302);
    const cookie = cookies(login, flow.cookie);
    const validAccess = (await control(ctx.baseURL, { operation: "encrypt", data: "valid-access" })).value;
    const validRefresh = (await control(ctx.baseURL, { operation: "encrypt", data: "valid-refresh" })).value;
    const retired = (await control(peer(ctx.baseURL), { operation: "encrypt", data: "retired-token", secrets: [{ version: 99, value: previous }] })).value;
    const retained = (await control(peer(ctx.baseURL), { operation: "encrypt", data: "retained-access", secrets: [secrets[1]] })).value;
    const outcomes: object[] = [];
    const attempt = async (accessToken: string, refreshToken: string, expired: boolean, expected: number, expectedToken?: string, endpoint = "get-access-token") => {
      const accountId = await ctx.seedOAuthAccount({ email: "google@example.com", providerId: "google", accountId: "cipher-boundary", accessToken, refreshToken, scope: " scope one , scope-two ",
        accessTokenExpiresAt: new Date(Date.now() + (expired ? -60_000 : 3600_000)).toISOString() });
      const response = await fetch(`${ctx.baseURL}/api/auth/${endpoint}`, { method: "POST", headers: { cookie, origin: ctx.baseURL, "content-type": "application/json" }, body: JSON.stringify({ accountId }) });
      expect(response.status).toBe(expected);
      const body = await response.json();
      if (expected === 400) expect(body).toEqual(endpoint === "get-access-token"
        ? { code: "FAILED_TO_GET_ACCESS_TOKEN", message: "Failed to get a valid access token" }
        : refreshToken === "" ? { code: "REFRESH_TOKEN_NOT_FOUND", message: "Refresh token not found" }
        : { code: "FAILED_TO_REFRESH_ACCESS_TOKEN", message: "Failed to refresh access token" });
      else {
        expect(body.accessToken).toBe(expectedToken);
        if (endpoint === "get-access-token") expect(body.scopes).toEqual(["scope one", "scope-two"]);
        else expect(body.scope).toBe(" scope one , scope-two ");
      }
      const listing = await fetch(`${ctx.baseURL}/api/auth/list-accounts`, { headers: { cookie } });
      expect(listing.status).toBe(200);
      expect((await listing.json()).find((account: any) => account.id === accountId).scopes).toEqual(["scope one", "scope-two"]);
      outcomes.push({ endpoint, status: response.status, ...(expected === 400 ? body : { accessToken: body.accessToken }) });
    };
    for (const invalid of ["00", retired]) {
      await attempt(validAccess, invalid, false, 200, "valid-access");
      await attempt(validAccess, invalid, true, 400);
      await attempt(invalid, validRefresh, false, 400);
      await attempt(invalid, validRefresh, true, 200, "google-access-token");
      await attempt(validAccess, invalid, false, 400, undefined, "refresh-token");
      await attempt(invalid, validRefresh, false, 200, "google-access-token", "refresh-token");
    }
    await attempt(validAccess, "", false, 400, undefined, "refresh-token");
    await attempt(retained, validRefresh, false, 200, "retained-access");
    return outcomes;
  });

  compatScenario("empty refreshed tokens preserve stored refresh and ID tokens with endpoint-specific responses", async ctx => {
    const flow = await begin(ctx.baseURL);
    const login = await callback(ctx.baseURL, flow.state, flow.cookie);
    expect(login.status).toBe(302);
    const cookie = cookies(login, flow.cookie);
    const oldRefresh = (await control(ctx.baseURL, { operation: "encrypt", data: "prior-refresh" })).value;
    const mode = (mode: string) => fetch(`${ctx.baseURL}/__test/set-oauth-refresh-mode`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ mode }) });
    expect((await mode("empty")).status).toBe(200);
    const outcomes: object[] = [];
    try {
      for (const endpoint of ["get-access-token", "refresh-token"]) {
        const accountId = await ctx.seedOAuthAccount({ email: "google@example.com", providerId: "google", accountId: `empty-${endpoint}`, refreshToken: oldRefresh, idToken: "prior-id" });
        const response = await fetch(`${ctx.baseURL}/api/auth/${endpoint}`, { method: "POST", headers: { cookie, origin: ctx.baseURL, "content-type": "application/json" }, body: JSON.stringify({ accountId }) });
        const body = await response.json();
        expect({ status: response.status, body }).toMatchObject({ status: 200, body: { accessToken: "", idToken: endpoint === "get-access-token" ? "" : "prior-id" } });
        if (endpoint === "refresh-token") expect(body.refreshToken).toBe("");
        const stored = (await control(ctx.baseURL, { operation: "accounts", email: "google@example.com" })).find((account: any) => account.id === accountId);
        expect(stored).toMatchObject({ accessToken: "", refreshToken: oldRefresh, idToken: "prior-id" });
        if (endpoint === "get-access-token") {
          const accountCookie = cookieValue(cookies(response, cookie), "better-auth.account_data");
          const decoded = await control(peer(ctx.baseURL), { operation: "decode", data: accountCookie });
          expect(decoded.value).toMatchObject({ accessToken: "", refreshToken: oldRefresh, idToken: "prior-id" });
        }
        outcomes.push({ endpoint, accessToken: body.accessToken, idToken: body.idToken, refreshToken: body.refreshToken });
      }
    } finally {
      expect((await mode("success")).status).toBe(200);
    }
    return outcomes;
  });

  compatScenario("state parsing preserves bound errors and consumes only validated state", async ctx => {
    const flow = await begin(ctx.baseURL);
    const name = cookieState ? "better-auth.oauth_state" : "better-auth.state";
    const original = cookieState ? JSON.parse((await control(ctx.baseURL, { operation: "decrypt", data: decodeURIComponent(cookieValue(flow.cookie, name)) })).value)
      : JSON.parse((await control(ctx.baseURL, { operation: "state", state: flow.state })).value);
    const outcomes: string[] = [];
    const attempt = async (payload: any, expected: string, useCookie = true) => {
      let cookie = flow.cookie;
      if (cookieState) {
        const encoded = await control(ctx.baseURL, { operation: "encrypt", data: typeof payload === "string" ? payload : JSON.stringify(payload) });
        cookie = `${name}=${encodeURIComponent(encoded.value)}`;
      } else await control(ctx.baseURL, { operation: "state", state: flow.state, value: payload });
      const response = await callback(ctx.baseURL, flow.state, useCookie ? cookie : "", { error: "provider_error" });
      expect(response.status).toBe(302);
      expect(response.headers.get("location")).toBe(expected);
      outcomes.push(response.headers.get("location")!);
      return response;
    };
    const mismatch = await attempt({ ...original, oauthState: "wrong" }, "/failure?from=oauth&error=state_mismatch");
    expect(mismatch.headers.getSetCookie()).toHaveLength(0);
    if (!cookieState) expect((await control(ctx.baseURL, { operation: "state", state: flow.state })).value).not.toBeNull();
    await attempt("not-json", `${ctx.baseURL}/api/auth/error?error=${cookieState ? "state_invalid" : "internal_server_error"}`);
    await attempt({ ...original, oauthState: 42 }, `${ctx.baseURL}/api/auth/error?error=${cookieState ? "state_invalid" : "internal_server_error"}`);
    await attempt({ ...original, errorURL: null }, `${ctx.baseURL}/api/auth/error?error=${cookieState ? "state_invalid" : "internal_server_error"}`);
    await attempt({ ...original, expiresAt: Date.now()+60_000.5 }, "/failure?from=oauth&error=provider_error");
    const expired = await attempt({ ...original, expiresAt: Date.now()-1000 }, "/failure?from=oauth&error=state_mismatch");
    expect(expired.headers.getSetCookie().some(cookie => cookie.startsWith(`${name}=`) && cookie.includes("Max-Age=0"))).toBe(true);
    if (!cookieState) expect((await control(ctx.baseURL, { operation: "state", state: flow.state })).value).toBeNull();
    if (!cookieState) {
      await attempt(original, "/failure?from=oauth&error=state_mismatch", false);
      const { oauthState, ...legacyPayload } = original;
      await attempt(legacyPayload, "/failure?from=oauth&error=provider_error");
    }
    return outcomes.map(location => ({ location }));
  });
}
