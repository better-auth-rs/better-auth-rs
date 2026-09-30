import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { signUpUser } from "../../phase6/helpers";
import { asRecord, fixture } from "../passkey-options/helpers";
compatScenario("Passkey required registration rejects stale sessions on both ceremony endpoints", async (ctx) => {
  await signUpUser(ctx, "primary", "passkey-stale", "Owner");
  const f = fixture(ctx); await f.control();
  const generated = await ctx.rawRequest({ path: "/api/auth/passkey/generate-register-options" });
  const verified = await ctx.rawRequest({ path: "/api/auth/passkey/verify-registration", method: "POST", json: { response: {} } });
  for (const result of [generated, verified]) { expect(result.status).toBe(403); expect(asRecord(result.body).code).toBe("SESSION_NOT_FRESH"); }
  expect((await f.trace()).events).toEqual([]);
  await f.authenticationOptions();
  return { generated, verified, observations: f.observations };
});
