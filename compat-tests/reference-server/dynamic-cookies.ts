import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";

function cookies(response: Response) {
  return response.headers.getSetCookie().map(value => {
    const [pair, ...attributes] = value.split(";");
    return { name: pair!.split("=")[0], attributes: Object.fromEntries(attributes
      .map(attribute => attribute.trim().split("="))
      .filter(([name]) => name!.toLowerCase() !== "expires")
      .map(([name, value]) => [name!.toLowerCase(), value?.toLowerCase() ?? true])) };
  }).sort((a,b) => a.name!.localeCompare(b.name!));
}

export async function runDynamicCookies() {
  const database = new Database(":memory:");
  const options: any = {
    database, secret: "dynamic-cookie-fixture-secret-at-least-thirty-two-characters",
    baseURL: "https://auth.example.test", rateLimit: { enabled: false },
    emailAndPassword: { enabled: true },
    session: { cookieCache: { enabled: true, maxAge: 300 } },
    advanced: {
      cookiePrefix: "tenant",
      defaultCookieAttributes: { path: "/global", domain: ".example.test", maxAge: 7, secure: false },
      cookies: {
        session_token: { name: "custom-token", attributes: { path: "/auth", httpOnly: false, maxAge: 180 } },
        session_data: { name: "custom-cache", attributes: { path: "/cache", maxAge: 90 } },
      },
    },
  };
  await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  const signup = await auth.handler(new Request("https://auth.example.test/api/auth/sign-up/email", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "cookies@example.test", password: "password123", name: "x".repeat(6000) }),
  }));
  const cookie = signup.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
  const session = await auth.handler(new Request("https://auth.example.test/api/auth/get-session", { headers: { cookie } }));
  const data = await session.json();
  const logout = await auth.handler(new Request("https://auth.example.test/api/auth/sign-out", { method: "POST", headers: { cookie, origin: "https://auth.example.test", "content-type": "application/json" }, body: "{}" }));
  database.close();
  return { signup: { status: signup.status, cookies: cookies(signup) }, session: { status: session.status, email: data?.user?.email }, logout: { status: logout.status, cookies: cookies(logout) } };
}
