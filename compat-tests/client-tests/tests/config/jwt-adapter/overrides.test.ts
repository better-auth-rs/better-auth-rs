import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("JWT native overrides replace whole groups and restore registered callbacks on the next call", async ctx => {
  const observations = [];
  for (const entry of [
    {overrides: {}},
    {overrides: {jwt: {issuer: "override-issuer"}}},
    {overrides: {jwks: {}}},
    {overrides: {adapter: {}}},
    {overrides: {}, overrideCreate: true},
  ]) {
    const response = await fetch(`${ctx.baseURL}/__test/jwt-adapter`, {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify({operation: "override", ...entry})});
    expect(response.status).toBe(200);
    const result = await response.json();
    const token = "jwt" in entry.overrides;
    const keys = "jwks" in entry.overrides;
    expect(result.output.claims).toEqual({sub: "user", iat: 100, exp: token ? 1000 : 2000000000, iss: token ? "override-issuer" : "registered-issuer", aud: token ? ctx.baseURL : "registered-audience"});
    expect(result.output.algorithm).toBe(keys ? "EdDSA" : "ES256");
    expect(result.output.encrypted).toBe(keys);
    expect(result.output.rotating).toBe(!keys);
    expect(result.output.firstEvents.map((event: any) => event.event)).toEqual(entry.overrideCreate ? ["override-create"] : "adapter" in entry.overrides ? [] : ["get", "get", "create"]);
    for (const event of result.output.firstEvents) expect(event.context.bodyKeys).toEqual(["overrideOptions", "payload"]);
    expect(result.output.nextFailed).toBe(keys);
    expect(result.output.nextClaims).toEqual(keys ? null : {sub: "next", iat: 100, exp: 2000000000, iss: "registered-issuer", aud: "registered-audience"});
    expect(result.events.map((event: any) => event.event)).toEqual(keys ? ["get", "get"] : ["get"]);
    expect(result.rows).toBe(1);
    if (token) result.output.claims.aud = "<server>";
    observations.push(result);
  }
  return observations;
});
