import { expect, test } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { parseSetCookie } from "set-cookie-parser";
import { RUST_BASE_URL, TS_BASE_URL, requireHealthy } from "../../support/config";
import { resetServerState } from "../../support/controls";
import { createTracingFetch } from "../../support/trace";

test.serial("Set-Cookie Domain serialization matches across signup, signin, and signout", async () => {
  const configuredDomain = process.env.COMPAT_COOKIE_DOMAIN;
  const observations = [];

  for (const [label, baseURL] of [["TS", TS_BASE_URL], ["Rust", RUST_BASE_URL]]) {
    const expectedDomain = configuredDomain === undefined
      ? undefined
      : configuredDomain || new URL(baseURL).hostname;
    await requireHealthy(baseURL, label);
    await resetServerState(baseURL);

    const responses: Response[] = [];
    const client = createAuthClient({
      baseURL,
      fetchOptions: {
        // This jar forwards cookies regardless of domain so localhost servers
        // can exercise header serialization with .example.com. This scenario
        // does not verify browser acceptance or cross-subdomain delivery.
        customFetchImpl: createTracingFetch(baseURL, label, []),
        onResponse({ response }) {
          responses.push(response);
        },
      },
    });
    const credentials = {
      email: `cookie-domain-${crypto.randomUUID()}@test.com`,
      password: "password123",
    };

    expect((await client.signUp.email({ ...credentials, name: "Cookie Domain User" })).error).toBeNull();
    expect((await client.signIn.email({ ...credentials, rememberMe: true })).error).toBeNull();
    expect((await client.signIn.email({ ...credentials, rememberMe: false })).error).toBeNull();
    expect((await client.signOut()).error).toBeNull();
    expect(responses).toHaveLength(4);

    const cookiesByResponse = responses.map((response) => {
      const cookies = parseSetCookie(response, { map: true, silent: true });
      expect(cookies["better-auth.session_token"]).toBeDefined();
      for (const cookie of Object.values(cookies)) {
        expect(cookie.domain).toBe(expectedDomain);
      }
      return cookies;
    });

    expect(cookiesByResponse[0]["better-auth.session_token"].maxAge).toBeGreaterThan(0);
    expect(cookiesByResponse[1]["better-auth.session_token"].maxAge).toBeGreaterThan(0);
    expect(cookiesByResponse[2]["better-auth.session_token"].maxAge).toBeUndefined();

    const clearedCookies = cookiesByResponse[3];
    for (const suffix of ["session_token", "session_data", "dont_remember"]) {
      expect(clearedCookies[`better-auth.${suffix}`]).toBeDefined();
    }
    for (const cookie of Object.values(clearedCookies)) {
      expect(cookie.maxAge).toBe(0);
    }

    // Compare this regression's domain contract independently of existing
    // rememberMe=false cookie-count differences between the runtimes.
    observations.push({
      sessionDomains: cookiesByResponse.map((cookies) => cookies["better-auth.session_token"].domain ?? null),
      clearedDomains: Object.fromEntries(
        Object.entries(clearedCookies).map(([name, cookie]) => [name, cookie.domain ?? null]),
      ),
    });
  }

  expect(observations[1]).toEqual(observations[0]);
});
