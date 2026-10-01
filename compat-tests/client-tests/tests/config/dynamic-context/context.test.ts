import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { dynamicContextScenarios } from "./scenarios";

for (const scenario of dynamicContextScenarios) {
  compatScenario(scenario.name, async ctx => scenario.run(async input => {
    const response = await fetch(`${ctx.baseURL}/__test/dynamic-context`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(input),
    });
    expect(response.status).toBe(200);
    return response.json();
  }));
}
