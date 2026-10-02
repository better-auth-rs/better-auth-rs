import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const reference = fileURLToPath(new URL("../../compat-tests/reference-server", import.meta.url));
const requireReference = createRequire(`${reference}/package.json`);
const upstream = specifier => import(pathToFileURL(requireReference.resolve(specifier)).href);
const { betterAuth } = await upstream("better-auth");
const cookiesURL = pathToFileURL(requireReference.resolve("better-auth/cookies"));
const { createSessionStore, expireCookie } = await import(cookiesURL.href);
const { createAccountStore } = await import(new URL("session-store.mjs", cookiesURL).href);
const { serializeCookie } = await upstream("better-call");

export async function captureCookieCacheCleanup() {
  const auth = betterAuth({
    baseURL: "https://cookie-cache-cleanup.test",
    secret: "ordinary-cookie-cache-cleanup-secret-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    advanced: {
      useSecureCookies: false,
      defaultCookieAttributes: { secure: true, httpOnly: true, sameSite: "lax", path: "/ordinary", domain: ".cookie-cache-cleanup.test", partitioned: true },
    },
  });
  const context = await auth.$context;
  const cases = [];
  for (const action of ["existing", "base", "baseThenExisting"]) {
    const logical = action === "baseThenExisting" ? "account_data" : "session_data";
    for (const present of [false, true]) {
      const incoming = present ? [
        [`${logical}.2`, "display-two"], [logical, "display-base"],
        [`${logical}.0`, "display-zero"], [`${logical}.2`, "display-repeat"],
      ] : [];
      const issued = ["ordinary_prior", logical, `${logical}.7`, "ordinary_after"];
      const responseHeaders = new Headers();
      const headers = new Headers();
      if (incoming.length) headers.set("cookie", incoming.map(([name, value]) => `better-auth.${name}=${value}`).join("; "));
      const ctx = {
        headers,
        responseHeaders,
        context: { ...context, responseHeaders },
        setCookie(name, value, attributes) {
          const header = serializeCookie(name, value, attributes);
          responseHeaders.append("set-cookie", header);
          return header;
        },
      };
      for (const name of issued) {
        const cookie = context.createAuthCookie(name);
        ctx.setCookie(cookie.name, "display", cookie.attributes);
      }
      const cookie = context.createAuthCookie(logical);
      if (action !== "existing") expireCookie(ctx, cookie);
      if (action !== "base") {
        const store = (action === "baseThenExisting" ? createAccountStore : createSessionStore)(cookie.name, cookie.attributes, ctx);
        store.setCookies(store.clean());
      }
      cases.push({ input: { action, logical, incoming, issued }, headers: responseHeaders.getSetCookie() });
    }
  }
  return cases;
}

if (import.meta.main) console.log(JSON.stringify(await captureCookieCacheCleanup(), null, 2));
