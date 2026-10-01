import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

async function invoke(ctx: any, input: object) {
  const response = await fetch(`${ctx.baseURL}/__test/jwt-adapter`, {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify(input)});
  expect(response.status).toBe(200);
  return response.json();
}
const calls = (result: any) => result.events.map((event: any) => event.event);

compatScenario("JWT cookie verification reads the adapter after typ and kid checks, before alg validation", async ctx => {
  const observations = [];
  const type = "better-auth.session-cache+jwt";
  for (const [header, reads] of [
    [{typ: type, kid: "missing", alg: 42}, true],
    [{typ: type, kid: 7}, true],
    [{typ: "other", kid: "missing", alg: "EdDSA"}, false],
    [{typ: type, alg: "EdDSA"}, false],
  ] as const) {
    const result = await invoke(ctx, {operation: "cookie", transport: "http", verifyFailure: true, verifyHeader: header});
    expect(result.output).toEqual({status: 200, cache: true, verifyStatus: 200, verifiedSession: false});
    expect(calls(result)).toEqual(["get", "get", "create", "verify-cookie", ...(reads ? ["get"] : [])]);
    observations.push(result);
  }
  return observations;
});

compatScenario("JWT verification uses upstream truthiness for the subject claim", async ctx => {
  const observations = [];
  for (const [claims, accepted] of [
    [{sub: "user"}, true], [{sub: 7}, true], [{sub: ["user"]}, true],
    [{sub: 0}, false], [{sub: ""}, false], [{}, false],
    [{sub: "user", aud: []}, false], [{sub: "user", aud: 7}, false],
    [{sub: "user", aud: [ctx.baseURL, 7]}, true],
    [{sub: "user", iat: -1, nbf: -1, jti: 7}, true],
    [{sub: "user", exp: -1}, false],
  ] as const) {
    const result = await invoke(ctx, {operation: "verify-claims", claims});
    expect(result.output).toEqual({accepted});
    expect(calls(result)).toEqual(["get"]);
    observations.push({case: observations.length, result});
  }
  return observations;
});

compatScenario("JWT read and create overrides remain independent and preserve endpoint context", async ctx => {
  const observations = [];
  for (const adapter of ["both", "get-only", "create-only"]) {
    for (const transport of ["http", "native"]) {
      const result = await invoke(ctx, {operation: "discovery", adapter, transport});
      expect(result.output).toEqual({status: 200, keys: 1}); expect(result.rows).toBe(1);
      expect(calls(result)).toEqual(adapter === "both" ? ["get", "create", "get"] : adapter === "get-only" ? ["get", "get"] : ["create"]);
      for (const event of result.events) {
        expect(event.context).toEqual({path: "/jwks", request: transport === "http", headers: transport === "http", bodyKeys: [], session: false, newSession: false});
        if (event.event === "create") {
          expect(event.date).toBe(true);
          expect(event.fields).toEqual(["alg", "createdAt", "crv", "privateKey", "publicKey"]);
        }
      }
      observations.push({adapter, transport, result});
    }
    const result = await invoke(ctx, {operation: "sign", adapter});
    expect(result.output).toEqual({signed: true}); expect(result.rows).toBe(1);
    expect(calls(result)).toEqual(adapter === "both" ? ["get", "get", "create"] : adapter === "get-only" ? ["get", "get"] : ["create"]);
    for (const event of result.events) expect(event.context).toEqual({path: "virtual:", request: false, headers: false, bodyKeys: ["payload"], session: false, newSession: false});
    observations.push({adapter, result});
  }
  return observations;
});

compatScenario("JWT discovery rereads custom keysets and rejects absent persisted keys", async ctx => {
  const observations = [];
  for (const transport of ["http", "native"]) for (const mode of ["empty", "noStore"]) {
    const result = await invoke(ctx, {operation: "discovery", transport, [mode]: true});
    expect(calls(result)).toEqual(["get", "create", "get"]);
    expect(result.rows).toBe(mode === "empty" ? 1 : 0);
    expect(result.output).toEqual(transport === "http" ? {status: 500, keys: null} : {thrown: true, message: "No key sets found. Make sure you have a key in your database."});
    observations.push({transport, mode, result});
  }
  return observations;
});

compatScenario("JWT discovery and signing stop at the original adapter failure", async ctx => {
  const observations = [];
  for (const failure of ["read", "create"]) {
    for (const transport of ["http", "native"]) {
      const result = await invoke(ctx, {operation: "discovery", transport, failure});
      expect(calls(result)).toEqual(failure === "read" ? ["get"] : ["get", "create"]); expect(result.rows).toBe(0);
      expect(result.output).toEqual(transport === "http" ? {status: 500, keys: null} : {thrown: true, message: `JWT adapter ${failure} failed`});
      observations.push({transport, failure, result});
    }
    const result = await invoke(ctx, {operation: "sign", failure});
    expect(calls(result)).toEqual(failure === "read" ? ["get"] : ["get", "get", "create"]); expect(result.rows).toBe(0);
    expect(result.output).toEqual({thrown: true, message: `JWT adapter ${failure} failed`});
    observations.push({failure, result});
  }
  return observations;
});

compatScenario("JWT verification checks the header before key reads and catches adapter failures", async ctx => {
  const observations = [];
  const inputs = [
    {malformed: true}, {header: {alg: "EdDSA"}}, {header: {kid: 0}},
    {header: {alg: "EdDSA", kid: "missing"}}, {header: {alg: 42, kid: "missing"}}, {header: {kid: 42}},
  ];
  for (let index = 0; index < inputs.length; index++) {
    const result = await invoke(ctx, {operation: "verify", failure: "read", ...inputs[index]});
    expect(result.output).toEqual({payload: null}); expect(result.rows).toBe(0);
    expect(calls(result)).toEqual(index < 3 ? [] : ["get"]);
    observations.push({input: inputs[index], result});
  }
  return observations;
});

compatScenario("JWT cookie signing uses callbacks and a failed key read cannot authenticate a cache", async ctx => {
  const observations = [];
  for (const adapter of ["both", "get-only", "create-only"]) for (const transport of ["http", "native"]) {
    const result = await invoke(ctx, {operation: "cookie", adapter, transport, verifyFailure: true});
    expect(result.output).toEqual({status: 200, cache: true, verifyStatus: 200, verifiedSession: adapter === "create-only"});
    expect(result.rows).toBe(1);
    const initial = adapter === "both" ? ["get", "get", "create"] : adapter === "get-only" ? ["get", "get"] : ["create"];
    expect(calls(result)).toEqual([...initial, "verify-cookie", ...(adapter === "create-only" ? [] : ["get"])]);
    for (const event of result.events.slice(0, initial.length)) expect(event.context).toEqual({path: "/sign-up/email", request: transport === "http", headers: true, bodyKeys: ["email", "name", "password"], session: false, newSession: false});
    observations.push({adapter, transport, result});
  }
  return observations;
});
