import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("JWT header prechecks preserve Base64 decoding and JSON truthiness before adapter errors", async ctx => {
  const plain = Buffer.from('{"kid":"missing"}').toString("base64url");
  const cases = [
    [plain + "=ignored+/_", true],
    [Buffer.from('{"kid":"missing","extra":"ÿÿ"}').toString("base64"), true],
    [Buffer.from('\ufeff{"kid":"missing"}').toString("base64url"), true],
    [Buffer.concat([Buffer.from('{"kid":"'), Buffer.from([255]), Buffer.from('"}')]).toString("base64url"), true],
    [Buffer.from('{"kid":"\\ud800"}').toString("base64url"), true],
    [Buffer.from('{"kid":{},"typ":7}').toString("base64url"), true],
    [Buffer.from('{"kid":[],"extra":"\\ud800"}').toString("base64url"), true],
    [Buffer.from('{"kid":"missing","\\ud800":7}').toString("base64url"), true],
    [Buffer.from('{"kid":0,"kid":"missing"}').toString("base64url"), true],
    [Buffer.from('{"kid":"missing","kid":0}').toString("base64url"), false],
    [plain + "!", false],
    [Buffer.from('null').toString("base64url"), false],
  ] as const;
  const observations = [];
  for (const [headerEncoded, reads] of cases) {
    const response = await fetch(`${ctx.baseURL}/__test/jwt-adapter`, {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify({operation: "verify", failure: "read", headerEncoded})});
    expect(response.status).toBe(200);
    const result = await response.json();
    expect(result.output).toEqual({payload: null});
    expect(result.rows).toBe(0);
    expect(result.events.map((event: any) => event.event)).toEqual(reads ? ["get"] : []);
    observations.push(result);
  }
  return observations;
});
