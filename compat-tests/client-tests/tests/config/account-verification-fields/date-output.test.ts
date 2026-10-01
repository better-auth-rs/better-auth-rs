import { compatScenario } from "../../../support/scenario";
import { assertDateOutput, dateCases } from "./date-contracts";

for (const input of dateCases) {
  compatScenario(`Verification ${input.mode} preserves ${input.kind} expiry output`, ctx =>
    assertDateOutput(input, async body => {
      const response = await fetch(`${ctx.baseURL}/__test/verification-date-output`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
      });
      if (!response.ok) throw new Error(`Fixture HTTP ${response.status}: ${await response.text()}`);
      return response.json();
    }));
}
