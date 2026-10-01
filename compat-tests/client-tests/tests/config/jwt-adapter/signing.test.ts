import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("JWT signing retains falsy claims and parses JOSE NumericDates after key creation", async ctx => {
  const cases: Array<{claims: Record<string, unknown>; expected?: Record<string, unknown>; relative?: Record<string, number>; error?: string}> = [
    {claims: {sub: "user", iat: -1, nbf: -1, exp: 0}},
    {claims: {sub: 0, jti: false, iat: 0, nbf: null, exp: -1}},
    {claims: {sub: null, jti: 0, iat: null, nbf: false}, relative: {exp: 900}},
    {claims: {sub: false, jti: ""}, relative: {exp: 900}},
    {claims: {iat: false}, expected: {iat: false, exp: 900}},
    {claims: {sub: 7}, error: '"sub" claim must be a string'},
    {claims: {sub: ["u"]}, error: '"sub" claim must be a string'},
    {claims: {sub: "u", jti: 7}, error: '"jti" claim must be a string'},
    {claims: {iss: 0}, error: '"iss" claim must be a string'},
    {claims: {aud: ["a", 7]}, error: '"aud" claim must be a string or an array of strings'},
    {claims: {iat: "1h"}, error: "Invalid time period format"},
    {claims: {iat: "1h", exp: 123}, relative: {iat: 3600}},
    {claims: {iat: "0s", exp: 123, nbf: "2 seconds ago"}, relative: {iat: 0, nbf: -2}},
    {claims: {exp: "1h"}, relative: {exp: 3600}},
    {claims: {exp: false}, error: "Invalid time period format"},
    {claims: {nbf: []}, error: "Invalid time period format"},
    {claims: {iat: [], exp: 123}, error: "Invalid time period format"},
  ];
  const observations = [];
  for (const entry of cases) {
    const before = Math.floor(Date.now() / 1000);
    const response = await fetch(`${ctx.baseURL}/__test/jwt-adapter`, {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify({operation: "sign-claims", claims: entry.claims})});
    expect(response.status).toBe(200);
    const result = await response.json();
    expect(result.rows).toBe(1);
    expect(result.events.map((event: any) => event.event)).toEqual(["get", "get", "create"]);
    if (entry.error) {
      expect(result.output).toEqual({thrown: true, message: entry.error});
    } else {
      const expected: Record<string, unknown> = {...entry.claims, ...entry.expected, iss: ctx.baseURL, aud: ctx.baseURL};
      for (const [claim, seconds] of Object.entries(entry.relative ?? {})) {
        expect(result.output.claims[claim]).toBeGreaterThanOrEqual(before + seconds);
        expect(result.output.claims[claim]).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + seconds);
        delete result.output.claims[claim];
        delete expected[claim];
      }
      expect(result.output).toEqual({claims: expected});
      result.output.claims.iss = "<server>";
      result.output.claims.aud = "<server>";
    }
    observations.push(result);
  }
  return observations;
});
