import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const reference = fileURLToPath(new URL("../../compat-tests/reference-server", import.meta.url));
const requireReference = createRequire(`${reference}/package.json`);
const upstream = specifier => import(pathToFileURL(requireReference.resolve(specifier)).href);
const { betterAuth } = await upstream("better-auth");
const { createAuthEndpoint } = await upstream("better-auth/api");
const { deleteSessionCookie } = await upstream("better-auth/cookies");

export async function captureCookieCleanup() {
  const cases = [];
  const incoming = [
    ["session_data.2", "display-two"], ["account_data.1", "display-one"],
    ["session_data", "display-base"], ["session_data.0", "display-zero"],
    ["account_data", "display-base"], ["session_data.2", "display-repeat"],
    ["account_data.0", "display-zero"], ["account_data.1", "display-repeat"],
  ];
  const issued = [
    "ordinary_prior", "session_token", "session_data", "session_data.7",
    "account_data", "account_data.7", "oauth_state", "dont_remember", "ordinary_after",
  ];
  for (const account of [false, true]) {
    for (const state of [false, true]) {
      for (const skip of [false, true]) {
        const input = { account, state, skip, incoming, issued };
        const auth = betterAuth({
          baseURL: "https://cookie-cleanup.test",
          secret: "ordinary-cookie-cleanup-secret-at-least-32-characters",
          logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
          session: { cookieCache: { enabled: false } },
          account: { storeAccountCookie: account, storeStateStrategy: state ? "cookie" : "database" },
          advanced: {
            useSecureCookies: false,
            defaultCookieAttributes: { secure: true, httpOnly: true, sameSite: "lax", path: "/ordinary", domain: ".cookie-cleanup.test", partitioned: true },
          },
          plugins: [{ id: "ordinary-cookie-cleanup", endpoints: {
            cleanup: createAuthEndpoint("/cookie-cleanup", { method: "GET" }, async ctx => {
              for (const logical of issued) {
                const cookie = ctx.context.createAuthCookie(logical);
                ctx.setCookie(cookie.name, "display", cookie.attributes);
              }
              deleteSessionCookie(ctx, skip);
              return ctx.json({ ok: true });
            }),
          } }],
        });
        const cookie = incoming.map(([name, value]) => `better-auth.${name}=${value}`).join("; ");
        const response = await auth.handler(new Request("https://cookie-cleanup.test/api/auth/cookie-cleanup", { headers: { cookie } }));
        cases.push({ input, response: { status: response.status, body: await response.json(), headers: response.headers.getSetCookie() } });
      }
    }
  }
  return cases;
}

if (import.meta.main) console.log(JSON.stringify(await captureCookieCleanup(), null, 2));
