import { beforeAll, expect, test } from "bun:test";
import {
  dropbox,
  figma,
  github,
  gitlab,
  google,
  huggingface,
  kick,
  linear,
  linkedin,
  polar,
  spotify,
  vercel,
} from "@better-auth/core/social-providers";

beforeAll(async () => {
  const core = await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json();
  expect(core.version).toBe("1.7.6");
});

for (const [id, constructor, forwardsHint] of [
  ["google", google, true],
  ["github", github, true],
  ["gitlab", gitlab, true],
  ["spotify", spotify, false],
  ["huggingface", huggingface, false],
  ["polar", polar, false],
  ["vercel", vercel, false],
  ["figma", figma, false],
  ["dropbox", dropbox, false],
  ["kick", kick, false],
  ["linkedin", linkedin, true],
  ["linear", linear, true],
] as const) {
  test(`${id} authorization omits nonce and preserves provider login hint behavior`, async () => {
    const provider = constructor({ clientId: "client", clientSecret: "secret" });
    const request = {
      state: "ordinary-state",
      codeVerifier: "ordinary-code-verifier-at-least-forty-three-characters",
      redirectURI: "https://app.example.test/callback/provider",
    };
    const baseline = await provider.createAuthorizationURL(request);
    const actual = await provider.createAuthorizationURL({
      ...request,
      loginHint: "reader@example.test",
      idTokenNonce: "ordinary-nonce",
    });
    const expected = [...baseline.searchParams];
    if (forwardsHint) expected.push(["login_hint", "reader@example.test"]);
    expect(actual.searchParams.has("nonce")).toBe(false);
    expect([...actual.searchParams].sort()).toEqual(expected.sort());
  });
}
