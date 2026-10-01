import assert from "node:assert/strict";
import { compatScenario } from "../../../support/scenario";

for (const secondary of [false, true]) {
  for (const mode of ["database", "callback-empty", "callback-disabled", "user-missing", "session-missing", "account-missing"]) {
    compatScenario(`ID policy ${mode}, secondary=${secondary}`, async ctx => {
      const response = await fetch(`${ctx.baseURL}/__test/id-policy`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ mode, secondary }),
      });
      assert.equal(response.status, 200);
      const result = await response.json();
      const missingUser = ["database", "callback-empty", "callback-disabled", "user-missing"].includes(mode);
      const missingSession = ["callback-empty", "session-missing"].includes(mode) || (!secondary && ["database", "callback-disabled"].includes(mode));
      assert.deepEqual(result.steps.map((step: any) => step.status), [200, 200, missingUser ? 401 : 200, 200]);
      assert.equal(result.steps[0].userKeys.includes("id"), !missingUser);
      assert.equal(result.steps[1].null, missingUser && !secondary);
      if (!result.steps[1].null) {
        assert.equal(result.steps[1].sessionKeys.includes("id"), !missingSession);
        assert.equal(result.steps[1].sessionKeys.includes("userId"), !missingUser);
      }
      assert.equal(result.steps[3].null, missingUser);
      assert.equal(result.cachedMissingUser, secondary && missingUser);
      return result;
    });
  }
}
