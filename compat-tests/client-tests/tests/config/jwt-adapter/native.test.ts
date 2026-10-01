import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("JWT native calls resolve dynamic URLs without manufacturing Request or headers", async ctx => {
  const observations = [];
  const cases = [
    {input: {headers: {host: "headers.example", "x-source": "headers"}}, origin: "https://headers.example", request: false, headers: true, suppliedHeader: "headers"},
    {input: {headers: {Host: "headers.example", "X-Source": "mixed-case"}}, origin: "https://headers.example", request: false, headers: true, suppliedHeader: "mixed-case"},
    {input: {request: "https://request.example/input"}, origin: "https://request.example", request: true, headers: false, suppliedHeader: null},
    {input: {request: "https://request.example/input", headers: {host: "headers.example", "x-source": "headers"}}, origin: "https://request.example", request: true, headers: true, suppliedHeader: "headers"},
    {input: {headers: {}, fallback: "https://fallback.example"}, origin: "https://fallback.example", request: false, headers: true, suppliedHeader: null},
    {input: {fallback: "https://fallback.example"}, origin: "https://fallback.example", request: false, headers: false, suppliedHeader: null},
  ];
  for (const entry of cases) {
    const response = await fetch(`${ctx.baseURL}/__test/jwt-adapter`, {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify({operation: "native-context", ...entry.input})});
    expect(response.status).toBe(200);
    const result = await response.json();
    expect(result.output).toEqual({claims: {sub: "user", iat: 100, exp: 1000, iss: entry.origin, aud: entry.origin}});
    expect(result.rows).toBe(1);
    expect(result.events.map((event: any) => event.event)).toEqual(["get", "get", "create"]);
    for (const event of result.events) expect(event.context).toEqual({path: "virtual:", request: entry.request, headers: entry.headers, bodyKeys: ["payload"], session: false, newSession: false, baseURL: `${entry.origin}/api/auth`, requestURL: entry.request ? "https://request.example/input" : null, suppliedHeader: entry.suppliedHeader});
    observations.push(result);
  }
  const response = await fetch(`${ctx.baseURL}/__test/jwt-adapter`, {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify({operation: "native-context"})});
  expect(response.status).toBe(200);
  const result = await response.json();
  expect(result).toEqual({events: [], rows: 0, output: {thrown: true, message: "Dynamic baseURL could not be resolved for this direct auth.api call. Pass `headers: request.headers` (or `request`) to the call, or add `fallback` to your baseURL config."}});
  return [...observations, result];
});
