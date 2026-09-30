import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { signUpUser } from "../../phase6/helpers";
import { asRecord, fixture } from "../passkey-options/helpers";
compatScenario("Passkey optional registration without a resolver still accepts existing sessions", async (ctx) => {
  const missing = await ctx.rawRequest({ path: "/api/auth/passkey/generate-register-options" });
  expect(missing.status).toBe(400); expect(asRecord(missing.body).code).toBe("RESOLVE_USER_REQUIRED");
  await signUpUser(ctx, "primary", "passkey-no-resolver", "Owner");
  const f = fixture(ctx); await f.control(); await f.options(); await f.trace();
  return { missing, observations: f.observations };
});
