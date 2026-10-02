import { writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";

export async function captureCookieSessionPrecision() {
const result = {};
const ages = { boundary: 34560000, beyondFraction: 34560000.25, ordinaryFraction: 300.75 };
const now = new Date();
const data = {
  user: { id: "ordinary-user", name: "Ordinary", email: "ordinary@cookie-precision.test", emailVerified: true, createdAt: now, updatedAt: now },
  session: { id: "ordinary-session", userId: "ordinary-user", token: "ordinary-output-only", expiresAt: new Date(now.getTime() + 300000), createdAt: now, updatedAt: now },
};
for (const [name, expiresIn] of Object.entries(ages)) {
  for (const dontRemember of [false, true]) {
    const auth = betterAuth({
      baseURL: "https://cookie-precision.test",
      secret: "ordinary-cookie-precision-fixture-secret-more-than-32-characters",
      logger: { disabled: true }, telemetry: { enabled: false },
      advanced: { useSecureCookies: false },
      session: { expiresIn, cookieCache: { enabled: false } },
      plugins: [{ id: "ordinary-cookie-precision", endpoints: {
        cookiePrecision: createAuthEndpoint("/cookie-precision", { method: "GET" }, async ctx => {
          let error = null;
          try { await setSessionCookie(ctx, data, dontRemember); }
          catch (caught) { error = caught.message; }
          return ctx.json({ error, resolvedExpiresIn: ctx.context.sessionConfig.expiresIn, newSession: Boolean(ctx.context.newSession) });
        }),
      } }],
    });
    const response = await auth.handler(new Request("https://cookie-precision.test/api/auth/cookie-precision"));
    const headers = response.headers.getSetCookie().map(raw => {
      const [pair, ...attributes] = raw.split("; ");
      return { name: pair.slice(0, pair.indexOf("=")), attributes };
    });
    result[`${name}-${dontRemember ? "browser" : "remember"}`] = {
      input: { expiresIn, dontRemember }, status: response.status,
      body: await response.json(), headers,
    };
  }
}
return result;
}

if (process.env.COOKIE_SESSION_PRECISION_OUTPUT) {
  const result = await captureCookieSessionPrecision();
  writeFileSync(process.env.COOKIE_SESSION_PRECISION_OUTPUT, JSON.stringify(result, null, 2) + "\n");
  console.log(`Captured ${Object.keys(result).length} ordinary session cookie lifetime results`);
}
