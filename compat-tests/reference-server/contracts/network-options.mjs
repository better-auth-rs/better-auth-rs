import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { getIP } from "@better-auth/core/utils/ip";
import { getTelemetryAuthConfig } from "@better-auth/telemetry";
import { createCookieGetter } from "better-auth/cookies";

const cases = {
  omitted: {},
  empty: { cookies: {}, ipAddress: {}, crossSubDomainCookies: {} },
  defaults: { cookies: {}, ipAddress: { disableIpTracking: false, ipAddressHeaders: ["x-forwarded-for"] }, crossSubDomainCookies: { enabled: false, additionalCookies: [] } },
  values: { cookies: { session_token: { name: "session.custom", attributes: { path: "/auth" } } }, ipAddress: { disableIpTracking: true, ipAddressHeaders: [] }, crossSubDomainCookies: { enabled: true, domain: "parent.test", additionalCookies: ["custom"] } },
  headerOrder: { ipAddress: { ipAddressHeaders: ["x-real-ip", "x-forwarded-for"] }, crossSubDomainCookies: { enabled: true } },
  emptyHeaders: { ipAddress: { ipAddressHeaders: [] }, crossSubDomainCookies: { enabled: false, domain: "parent.test" } },
};
const headers = new Headers({ "x-forwarded-for": "192.0.2.1", "x-real-ip": "192.0.2.2" });
const results = {};
for (const [name, advanced] of Object.entries(cases)) {
  const options = { baseURL: "https://example.test", advanced };
  const cookie = createCookieGetter(options)("session_token");
  results[name] = {
    advanced: (await getTelemetryAuthConfig(options)).advanced,
    cookie: { name: cookie.name, path: cookie.attributes.path, domain: cookie.attributes.domain ?? null },
    ip: getIP(headers, options),
  };
}
const serializable = JSON.parse(JSON.stringify(results));
const fixture = new URL("../../../tests/fixtures/network-options-1.7.6.json", import.meta.url);
if (process.env.NETWORK_REFERENCE_OUTPUT) {
  writeFileSync(process.env.NETWORK_REFERENCE_OUTPUT, JSON.stringify(serializable, null, 2) + "\n");
  console.log("Wrote 6 upstream network-option cases");
} else {
  assert.deepEqual(serializable, JSON.parse(readFileSync(fixture, "utf8")));
  console.log("6 upstream network-option cases match the Rust fixture");
}
