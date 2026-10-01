import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("JWT after hooks use the endpoint session even when the response is null or replaced", async ctx => {
  const observations = [];
  for (const state of ["valid", "expired", "revoked", "replaced"]) for (const transport of ["http", "native"]) {
    const response = await fetch(`${ctx.baseURL}/__test/jwt-session`, {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify({state, transport})});
    expect(response.status).toBe(200);
    const result = await response.json();
    expect(result.status).toBe(200);
    expect(result.body).toBe(state === "replaced" ? "replaced" : ["expired", "revoked"].includes(state) ? "null" : "session");
    expect(result.storedSessions).toBe(["expired", "revoked"].includes(state) ? 0 : 1);
    if (state === "revoked") {
      expect(result.jwt).toBeNull();
      expect(result.events).toEqual([]);
    } else {
      expect(result.jwt).toEqual({name: "Original user", expired: state === "expired"});
      expect(result.events).toEqual([
        {event: "payload", name: "Original user", expired: state === "expired"},
        {event: "get", path: "/get-session", session: true, newSession: false},
        {event: "get", path: "/get-session", session: true, newSession: false},
      ]);
    }
    observations.push({state, transport, result});
  }
  return observations;
});
