import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("email form sign-in preserves HTTP media, schema, and form origin checks", async ctx => {
  await fetch(`${ctx.baseURL}/__test/password-security`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "configure" }) });
  const email = ctx.uniqueEmail("form-signin");
  const password = "FormPassword123!";
  expect((await ctx.actor().client.signUp.email({ email, password, name: "Form" })).error).toBeNull();

  // The tracing client adds Origin; direct fetch preserves truly absent HTTP headers.
  async function submit(headers: HeadersInit = {}, extra: Record<string, string> = {}) {
    const response = await fetch(`${ctx.baseURL}/api/auth/sign-in/email`, {
      method: "POST", headers, body: new URLSearchParams({ email, password, ...extra }),
    });
    const text = await response.text();
    return { status: response.status, body: text ? JSON.parse(text) : null };
  }
  const programmatic = await submit();
  expect(programmatic.status).toBe(200);
  expect(programmatic.body.user.email).toBe(email);
  expect(typeof programmatic.body.token).toBe("string");
  const sameOrigin = await submit({ origin: ctx.baseURL });
  expect(sameOrigin.status).toBe(200);
  const nullOrigin = await submit({ origin: "null", "sec-fetch-site": "same-origin" });
  expect(nullOrigin.status).toBe(200);
  const remember = await submit({}, { rememberMe: "false" });
  expect(remember.status).toBe(400);
  expect(remember.body).toMatchObject({ code: "VALIDATION_ERROR" });
  const untrusted = await submit({ origin: "https://attacker.invalid" });
  expect(untrusted.status).toBe(403);
  const navigation = await submit({ "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate" });
  expect(navigation.status).toBe(403);
  const unsupported = await submit({ "content-type": "text/plain" });
  expect(unsupported.status).toBe(415);
  return { programmatic, sameOrigin, nullOrigin, remember, untrusted, navigation, unsupported };
}, 30_000);
