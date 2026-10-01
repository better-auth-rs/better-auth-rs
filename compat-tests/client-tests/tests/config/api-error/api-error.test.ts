import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { registerApiErrorContracts } from "./contracts";

registerApiErrorContracts((name, scenario) => compatScenario(name, async ctx => scenario(async input => {
  const response = await fetch(`${ctx.baseURL}/__test/api-error`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(input) });
  expect(response.status).toBe(200);
  return response.json();
})), process.env.COMPAT_PROFILE === "api-error-production");
