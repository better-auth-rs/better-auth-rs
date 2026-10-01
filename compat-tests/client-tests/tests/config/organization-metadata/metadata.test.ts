import assert from "node:assert/strict";
import { compatScenario } from "../../../support/scenario";

for (const database of ["memory", "sqlite"]) {
  compatScenario(`${database}: raw metadata stays literal and route JSON is encoded once`, async ctx => {
    const response = await fetch(`${ctx.baseURL}/__test/organization-metadata`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ database }),
    });
    assert.equal(response.status, 200);
    const result = await response.json();
    const inputs = [null, "plain", '{"key":"value"}', "null", { key: "value" }];
    assert.deepEqual(result.raw, inputs.map(value => database === "sqlite" && value !== null && typeof value === "object"
      ? { draft: value, rejected: true, persisted: false }
      : { draft: value, saved: value, read: value }));
    assert.deepEqual(result.route, {
      created: { nested: { value: 1 } }, createdRead: '{"nested":{"value":1}}',
      updated: {}, updatedRead: "{}",
    });
    return result;
  });
}
