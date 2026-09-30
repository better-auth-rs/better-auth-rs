import { expect } from "bun:test";
import { asArray, asRecord, type CompatContext } from "../../phase6/helpers";

export async function configure(ctx: CompatContext, options: { fail?: string; limits?: Record<string, number | boolean>; organizationIdOverride?: string; clearLogo?: boolean; metadataOverride?: Record<string, unknown> | null } = {}) {
  const result = await ctx.rawRequest({ path: "/__test/organization-callbacks", method: "POST", json: options });
  expect(result.status).toBe(200);
}

export async function trace(ctx: CompatContext) {
  const result = await ctx.rawRequest({ path: "/__test/organization-callbacks" });
  expect(result.status).toBe(200);
  return asArray(result.body).map(asRecord);
}
