import { expect, test } from "bun:test";
import { readFileSync, writeFileSync } from "node:fs";
import { auth0, keycloak, okta } from "better-auth/plugins/generic-oauth";

test("OIDC preset URL normalization matches the Rust fixture", () => {
  const inputs = [
    { provider: "auth0", address: "tenant.example.test" },
    { provider: "auth0", address: "http://tenant.example.test:8080/path?query=yes" },
    { provider: "auth0", address: "https://tenant.example.test:443/" },
    { provider: "auth0", address: "https://[::1]:8443/path" },
    { provider: "auth0", address: "https://tenant.example.test", overrideScopes: [] },
    { provider: "auth0", address: "http://" },
    { provider: "auth0", address: "bad host" },
    { provider: "keycloak", address: "https://identity.example.test/realms/app" },
    { provider: "keycloak", address: "https://identity.example.test/realms/app/" },
    { provider: "keycloak", address: "https://identity.example.test/realms/app//" },
    { provider: "okta", address: "https://identity.example.test/oauth2/default" },
    { provider: "okta", address: "https://identity.example.test/oauth2/default/" },
    { provider: "okta", address: "https://identity.example.test/oauth2/default//", overrideScopes: ["profile"] },
  ];
  const results = inputs.map((input) => {
    const credentials = { clientId: "client", clientSecret: "secret", scopes: input.overrideScopes };
    try {
      const config = input.provider === "auth0"
        ? auth0({ ...credentials, domain: input.address })
        : input.provider === "keycloak"
          ? keycloak({ ...credentials, issuer: input.address })
          : okta({ ...credentials, issuer: input.address });
      return { ...input, expected: { discoveryUrl: config.discoveryUrl, scopes: config.scopes } };
    } catch (error) {
      if (!(error instanceof TypeError)) throw error;
      return { ...input, expected: null };
    }
  });
  const output = process.env.GENERIC_OIDC_PRESETS_OUTPUT;
  if (output) writeFileSync(output, JSON.stringify(results, null, 2) + "\n");
  else expect(results).toEqual(JSON.parse(readFileSync(new URL("../../../tests/fixtures/generic-oidc-presets-1.7.6.json", import.meta.url), "utf8")));
});
