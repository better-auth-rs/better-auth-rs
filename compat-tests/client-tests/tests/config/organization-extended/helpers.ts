import { expect } from "bun:test";
import type { CompatContext } from "../../phase6/helpers";

export function requests(ctx: CompatContext) {
  const observations: unknown[] = [];
  return {
    observations,
    async call(actor: string, route: string, json?: unknown, status = 200) {
      const result = await ctx.rawRequest({ actor, path: `/api/auth/organization/${route}`, method: json === undefined ? "GET" : "POST", json });
      expect(result.status, `${route}: ${JSON.stringify(result.body)}`).toBe(status);
      observations.push(result);
      return result.body;
    },
  };
}
