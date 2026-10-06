import assert from "node:assert/strict";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";

export async function captureAppleFlows({ sign, jwk, metadata, normalized }) {
  const output = [];
  const claims = { sub: "ordinary-flow-user", name: "Token Name", email: "apple-flow@example.test", email_verified: "true", iss: metadata.issuer, aud: metadata.clientId, nonce: "ordinary-flow-nonce" };
  const userInput = { name: { firstName: "Callback", lastName: "Owner" }, email: "ignored@example.test" };
  const token = await sign(claims);
  const originalFetch = globalThis.fetch;
  try {
    for (const mode of ["direct", "form_post"]) {
      const database = { user: [], account: [], session: [], verification: [] };
      const requests = [], mapperInputs = [], status = [];
      globalThis.fetch = Object.assign(async (input, init) => {
        const request = new Request(input, init), url = new URL(request.url);
        requests.push(url.pathname);
        if (request.url === metadata.jwksEndpoint) return Response.json({ keys: [jwk] });
        assert.equal(request.url, metadata.tokenEndpoint);
        return Response.json({ id_token: token, access_token: "normal-access", expires_in: 3600 });
      }, originalFetch);
      const auth = betterAuth({
        baseURL: "http://localhost:3000", secret: "ordinary-apple-secret-at-least-32-characters",
        database: memoryAdapter(database), telemetry: { enabled: false }, logger: { disabled: true },
        socialProviders: { apple: {
          clientId: metadata.clientId, clientSecret: metadata.clientSecret,
          mapProfileToUser: async profile => { mapperInputs.push(normalized(profile)); return { name: "Mapped Flow Owner" }; },
        } },
      });
      const body = mode === "direct"
        ? { provider: "apple", idToken: { token, nonce: "ordinary-flow-nonce", user: userInput } }
        : { provider: "apple", callbackURL: "http://localhost:3000/welcome", disableRedirect: true };
      const start = await auth.handler(new Request("http://localhost:3000/api/auth/sign-in/social", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }));
      status.push(start.status);
      assert.equal(start.status, 200);
      let location = null;
      if (mode === "form_post") {
        const state = new URL((await start.json()).url).searchParams.get("state");
        assert.ok(state);
        const cookie = start.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
        assert.ok(cookie);
        const callback = await auth.handler(new Request("http://localhost:3000/api/auth/callback/apple", {
          method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", origin: "http://localhost:3000", cookie },
          body: new URLSearchParams({ state, code: "ordinary-code", user: JSON.stringify(userInput) }),
        }));
        status.push(callback.status);
        assert.equal(callback.status, 302);
        assert.deepEqual(requests, []);
        const redirect = callback.headers.get("location");
        assert.ok(redirect);
        const callbackURL = new URL(redirect);
        assert.equal(callbackURL.pathname, "/api/auth/callback/apple");
        assert.equal(callbackURL.searchParams.get("state"), state);
        assert.equal(callbackURL.searchParams.get("code"), "ordinary-code");
        assert.equal(callbackURL.searchParams.get("user"), JSON.stringify(userInput));
        const result = await auth.handler(new Request(redirect, { headers: { cookie } }));
        status.push(result.status);
        assert.equal(result.status, 302);
        location = result.headers.get("location");
        assert.equal(location, "http://localhost:3000/welcome");
      }
      assert.equal(database.user.length, 1);
      assert.equal(database.account.length, 1);
      assert.equal(database.session.length, 1);
      const user = database.user[0], account = database.account[0], session = database.session[0];
      output.push({ mode, claims, userInput, status, location, mapperInputs, requests,
        result: { name: user.name, email: user.email, emailVerified: user.emailVerified, image: user.image ?? null,
          provider: account.providerId, subject: account.accountId, accountCount: database.account.length,
          sessionCount: database.session.length, sessionMatchesUser: session.userId === user.id },
      });
    }
    return output;
  } finally { globalThis.fetch = originalFetch; }
}
