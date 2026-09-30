import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { callback, invalid, issuer, verifyLocalEmail } from "../one-tap/helpers";

compatScenario("One Tap applies hosted domain and disabled signup with explicit audience overrides", async (ctx) => {
  const email = ctx.uniqueEmail("one-tap-options");
  const sign = await issuer(ctx, email, "one-tap-alternative");
  const noDomain = await callback(ctx, await sign()); invalid(noDomain);
  const wrongDomain = await callback(ctx, await sign({ hd: "other.example.com" })); invalid(wrongDomain);
  const disabled = await callback(ctx, await sign({ hd: "example.com" }));
  expect(disabled.status).toBe(401);
  expect(disabled.body).toEqual({ message: "signup disabled" });
  const signup = await ctx.actor().client.signUp.email({ email, password: "Password123!", name: "Allowed Existing" });
  expect(signup.error).toBeNull();
  const verified = await verifyLocalEmail(ctx, email);
  const linked = await callback(ctx, await sign({ hd: "example.com" }));
  expect(linked.status).toBe(200);
  expect((linked.body as any).user.id).toBe(signup.data?.user.id);
  const fallbackAudience = await callback(ctx, await sign({ hd: "example.com", aud: "google-client-id" })); invalid(fallbackAudience);
  return { noDomain, wrongDomain, disabled, verified, linked, fallbackAudience };
});
