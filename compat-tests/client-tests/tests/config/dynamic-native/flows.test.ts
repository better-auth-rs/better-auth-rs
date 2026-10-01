import assert from "node:assert/strict";
import { compatScenario } from "../../../support/scenario";

for (const scenario of ["missing", "fallback", "headers", "transaction-deny", "transaction-allow"]) {
  compatScenario(`typed native runtime: ${scenario}`, async ctx => {
    const response = await fetch(`${ctx.baseURL}/__test/dynamic-native`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ scenario }),
    });
    assert.equal(response.status, 200);
    const result = await response.json();
    if (scenario === "missing") {
      assert.equal(result.calls.length, 6);
      assert.ok(result.calls.every((call: any) => !call.ok));
      assert.deepEqual(result.snapshot, { admin: false, signup: false, otp: false, keys: 0 });
      assert.deepEqual(result.events, []);
    } else if (scenario === "fallback") {
      assert.ok(result.calls.every((call: any) => call.ok));
      assert.deepEqual(result.snapshot, { admin: true, signup: false, otp: true, keys: 1 });
      assert.equal(result.calls.at(-1).value, true);
      assert.equal(result.events.filter((event: any) => event.event === "generate").length, 1);
    } else if (scenario === "headers") {
      assert.equal(result.calls[0].ok, false);
      assert.equal(result.events.filter((event: any) => event.event === "origins").length, 1);
      assert.deepEqual(result.snapshot, { admin: false, signup: false, otp: false, keys: 0 });
    } else {
      const accepted = scenario === "transaction-allow";
      assert.equal(result.calls[0].ok, accepted);
      assert.equal(result.events.filter((event: any) => event.event === "origins").length, 2);
      assert.deepEqual(result.events.find((event: any) => event.event === "admission"), { event: "admission", before: null, created: "123456", after: "123456" });
      assert.deepEqual(result.snapshot, { admin: false, signup: accepted, otp: accepted, keys: 0 });
    }
    return result;
  });
}
