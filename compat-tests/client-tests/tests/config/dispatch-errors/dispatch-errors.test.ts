import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

async function invoke(ctx: any, input: object) {
  const response = await fetch(`${ctx.baseURL}/__test/dispatch-errors`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(input) });
  expect(response.status).toBe(200);
  return response.json();
}

for (const phase of ["http", "before", "endpoint", "after"]) {
  compatScenario(`${phase} failures retain the upstream HTTP and native hook boundary`, async ctx => {
    const observations = [];
    for (const transport of ["http", "native"]) {
      for (const mode of ["api-error", "api-500", "ordinary-error", "redirect"]) {
        const result = await invoke(ctx, { phase, transport, mode });
        const bypassed = phase === "http" && transport === "native";
        expect(result.persisted).toBe(bypassed || ["endpoint", "after"].includes(phase));
        expect(result.output.thrown).toBe(!bypassed && (transport === "native" || phase === "http"));
        if (!bypassed && mode === "ordinary-error") {
          if (result.output.thrown) expect(result.output.message).toBe("Fixture ordinary failure");
          else {
            expect(result.output.status).toBe(500); expect(result.output.body).toBe("");
            expect(result.output.cookies).toEqual([]); expect(result.output.priority).toBeNull();
          }
          expect(result.events.some((event: any) => event.hook === "after-later")).toBe(false);
        } else if (!bypassed) {
          expect(result.output.status).toBe(mode === "api-500" ? 500 : mode === "redirect" ? 302 : 400);
          const nativeBefore = transport === "native" && phase === "before";
          expect(result.output.priority).toBe(nativeBefore ? "before" : "explicit-error");
          expect(result.output.location).toBe(nativeBefore ? null : "/explicit-error");
          expect(result.output.cookies).toContain(nativeBefore ? "before_cookie" : "explicit_error_cookie");
          expect(result.events.some((event: any) => event.hook === "after-later")).toBe(["endpoint", "after"].includes(phase));
        }
        observations.push({ phase, transport, mode, ...result });
      }
    }
    return observations;
  });
}

compatScenario("returned responses and recovered API errors do not become native exceptions", async ctx => {
  const observations = [];
  for (const transport of ["http", "native"]) {
    for (const phase of ["before", "endpoint", "after"]) {
      const result = await invoke(ctx, { phase, transport, mode: "response", endpointError: phase === "after" });
      expect(result.output.thrown).toBe(false);
      expect(result.output.status).toBe(phase === "before" ? 200 : 400);
      expect(result.persisted).toBe(phase !== "before");
      expect(result.events.some((event: any) => event.hook === "after-later")).toBe(phase !== "before");
      if (phase === "after") {
        expect(result.events.find((event: any) => event.hook === "after-first").apiError).toBe(true);
        expect(result.events.find((event: any) => event.hook === "after-later").apiError).toBe(false);
        expect(JSON.parse(result.output.body)).toEqual({ recovered: true });
      }
      observations.push({ phase, transport, ...result });
    }
  }
  return observations;
});
