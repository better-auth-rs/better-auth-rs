import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import fixture from "../../../tests/fixtures/social-redirect-uri-1.7.6.json";

for (const id of ["google", "github", "discord", "gitlab", "spotify", "huggingface", "polar", "vercel", "figma", "dropbox", "kick", "cloudflare", "linkedin", "slack", "naver", "linear"]) {
  for (const entry of fixture.cases) {
    test(`${id} ${entry.name} callback URI matches authorization and code exchange`, async () => {
      const bodies: URLSearchParams[] = [];
      const server = Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        async fetch(request) {
          bodies.push(new URLSearchParams(await request.text()));
          return Response.json({ access_token: "ordinary-access", token_type: "Bearer" });
        },
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = Object.assign(
        (_input: Parameters<typeof fetch>[0], init?: RequestInit) => originalFetch(server.url, init),
        originalFetch,
      );
      try {
        const core = await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json();
        expect(core.version).toBe(fixture.version);
        const context = await betterAuth({
          secret: "ordinary-redirect-uri-contract-secret-at-least-32-characters",
          baseURL: "https://app.example.test",
          logger: { disabled: true },
          telemetry: { enabled: false },
          socialProviders: {
            [id]: {
              clientId: "ordinary-client",
              clientSecret: "ordinary-secret",
              ...("configured" in entry ? { redirectURI: entry.configured } : {}),
            },
          },
        }).$context;
        const provider = context.socialProviders.find(value => value.id === id)!;
        const authorization = await provider.createAuthorizationURL({
          state: "ordinary-state",
          codeVerifier: "ordinary-code-verifier-at-least-forty-three-characters",
          redirectURI: fixture.routeURI,
        });
        expect(authorization.searchParams.get("redirect_uri")).toBe(entry.expected);
        const result = await provider.validateAuthorizationCode({
          code: "ordinary-code",
          codeVerifier: "ordinary-code-verifier-at-least-forty-three-characters",
          redirectURI: fixture.routeURI,
        });
        expect(result.accessToken).toBe("ordinary-access");
        expect(bodies).toHaveLength(1);
        expect(bodies[0]!.get("redirect_uri")).toBe(entry.expected);
        expect(bodies[0]!.get("code")).toBe("ordinary-code");
        expect(bodies[0]!.get("code_verifier")).toBe(["discord", "linkedin", "slack", "naver", "linear"].includes(id) ? null : "ordinary-code-verifier-at-least-forty-three-characters");
      } finally {
        globalThis.fetch = originalFetch;
        await server.stop(true);
      }
    });
  }
}
