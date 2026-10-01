import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("JWT native token headers preserve omission and authenticate mixed-case Cookie names", async ctx => {
  const response = await fetch(`${ctx.baseURL}/__test/jwt-adapter`, {
    method: "POST", headers: {"content-type": "application/json"},
    body: JSON.stringify({operation: "native-token"}),
  });
  expect(response.status).toBe(200);
  const result = await response.json();
  expect(result.output.signupStatus).toBe(200);
  expect(result.rows).toBe(1);
  expect(result.events).toEqual([]);
  expect(result.output.results.map(({events, ...value}: any) => value)).toEqual([
    {name: "omitted", status: 400, body: {code: "VALIDATION_ERROR", message: "Headers is required"}},
    {name: "empty", status: 401, body: {code: "UNAUTHORIZED", message: "Unauthorized"}},
    {name: "lowercase", status: 200, body: {token: true, subjectMatches: true}},
    {name: "mixed-case", status: 200, body: {token: true, subjectMatches: true}},
  ]);
  const events = result.output.results.map((entry: any) => entry.events);
  expect(events.map((entries: any[]) => entries.map(event => event.event))).toEqual([
    [], [], ["get", "get", "create"], ["get"],
  ]);
  for (const event of events.flat()) expect(event.context).toEqual({
    path: "/token", request: false, headers: true, bodyKeys: [], session: true, newSession: false,
  });
  return result;
});
