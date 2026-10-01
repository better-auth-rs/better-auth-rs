import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

type Input = { mode: string; model: string; scenario: string; fault?: string; transaction?: string };
const kinds = (state: any) => state.events.map((event: any) => event.kind);
const rows = (state: any, model: string) => model === "account" ? state.accounts : state.verifications;
function scenario(input: Input, assert: (output: any) => void) {
  compatScenario(`${input.mode}/${input.model}: ${input.scenario} ${input.fault ?? ""} ${input.transaction ?? ""}`, async ctx => {
    const response = await fetch(`${ctx.baseURL}/__test/account-verification-fields`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(input),
    });
    if (!response.ok) throw new Error(`Field fixture HTTP ${response.status}: ${await response.text()}`);
    const output = await response.json();
    assert(output);
    return ctx.snapshot(output);
  });
}

for (const mode of ["database", "cache", "database-cache"]) {
  for (const model of ["account", "verification"]) {
    const adapter = model === "account" || mode !== "cache";
    const cache = model === "verification" && mode !== "database";
    scenario({ mode, model, scenario: "lifecycle" }, out => {
      expect(out.created.value.label).toBe(adapter ? "default:in:out" : undefined);
      expect(out.created.value.hidden).toBe(adapter ? "secret" : undefined);
      expect(out.created.value.protected).toBe(adapter ? "server" : undefined);
      expect(kinds(out.created.state)).toEqual([`${model}.create.before`, ...(adapter ? [`${model}.default`, `${model}.input`, `${model}.output`] : []), ...(cache ? ["cache.set"] : []), `${model}.create.after`]);
      expect(rows(out.created.state, model)[0]?.label).toBe(adapter ? "default:in" : undefined);
      expect(out.read.value).toEqual(out.created.value);
      expect(kinds(out.read.state)).toEqual(cache ? ["cache.get"] : [`${model}.output`]);
      expect(out.updated.value.label).toBe(adapter ? "updated:in:out" : undefined);
      expect(kinds(out.updated.state)).toEqual([...(cache ? ["cache.get", "cache.set"] : []), ...(adapter ? [`${model}.update.before`, `${model}.onUpdate`, `${model}.input`, `${model}.output`, `${model}.update.after`] : [])]);
      expect(rows(out.updated.state, model)[0]?.label).toBe(adapter ? "updated:in" : undefined);
      if (cache) expect(out.updated.state.cached.label).toBe(out.created.value.label);
      expect(out.explicit.value.label).toBe(adapter ? "explicit:in:out" : "explicit");
      expect(out.readExplicit.value.label).toBe(cache ? "explicit" : "explicit:in:out");
      if (model === "account") expect(out.listed).toEqual({ status: 200, body: [{ label: "explicit:in:out", protected: "server", scopes: ["read", "write"], privateKeys: [] }] });
    });
    scenario({ mode, model, scenario: "explicit-null" }, out => {
      expect(out.created.value.label).toBe(adapter ? "null:in:out" : null);
      expect(out.created.value.protected).toBe("native"); expect(out.created.value.hidden).toBe("native-secret");
      expect(kinds(out.created.state)).not.toContain(`${model}.default`);
      if (adapter) expect(rows(out.created.state, model)[0].label).toBe("null:in");
    });
    scenario({ mode, model, scenario: "hook-fields" }, out => {
      expect(out.created.value.label).toBe(adapter ? "hook:in:out" : "hook");
      expect(out.created.value.hidden).toBe("hook-secret");
      const after = out.created.state.events.find((event: any) => event.kind === `${model}.create.after`).value;
      expect(after.label).toBe(out.created.value.label); expect(after.hidden).toBe("hook-secret"); expect(after.protected).toBe("hook-protected");
      for (const direction of ["input", "output"]) expect(kinds(out.created.state).filter((kind: string) => kind === `${model}.${direction}`).length).toBe(adapter ? 1 : 0);
    });
    for (const fault of ["input", "output"]) {
      for (const transaction of fault === "input" ? ["outside"] : ["outside", "rollback", "caught"]) {
        scenario({ mode, model, scenario: "create-error", fault, transaction }, out => {
          expect(out.result.error).toBe(adapter && transaction !== "caught" ? `fixture ${model}.${fault} rejected` : null);
          const state = out.final.state;
          expect(rows(state, model).length).toBe(adapter && fault === "output" && transaction !== "rollback" ? 1 : 0);
          expect(kinds(state).includes(`${model}.create.after`)).toBe(!adapter);
          if (cache) expect(state.cached !== null).toBe(!adapter);
        });
      }
    }
    scenario({ mode, model, scenario: "after-error" }, out => {
      expect(out.result.error).toBe(`fixture ${model}.create.after rejected`); expect(out.insideAfter).toBe(false);
      expect(rows(out.final.state, model).length).toBe(adapter ? 1 : 0);
      if (cache) expect(out.final.state.cached.label).toBe(adapter ? "value:in:out" : "value");
      expect(kinds(out.final.state).at(-1)).toBe(`${model}.create.after`);
    });
  }
  const adapter = mode !== "cache", cache = mode !== "database", model = "verification";
  scenario({mode, model, scenario: "create-rollback"}, out => {
    expect(out.result.error).toBe("rollback requested"); expect(out.insideAfter).toBe(false);
    expect(out.inside.label).toBe(adapter ? "value:in:out" : "value"); expect(out.final.state.verifications).toEqual([]);
    expect(kinds(out.final.state)).not.toContain("verification.create.after");
    expect(out.final.state.cached?.label).toBe(cache ? adapter ? "value:in:out" : "value" : undefined);
    expect(out.final.state.cached?.hidden).toBe(cache ? "hidden-value" : undefined);
  });
  for (const fault of ["update.before", "input", "output", "update.after"]) {
    scenario({mode, model, scenario: "update-error", fault}, out => {
      expect(out.result.error).toBe(adapter ? `fixture verification.${fault} rejected` : null);
      const state = out.final.state, wrote = adapter && ["output", "update.after"].includes(fault);
      expect(state.verifications[0]?.label).toBe(adapter ? wrote ? "replacement:in" : "initial:in" : undefined);
      expect(state.cached?.label).toBe(cache ? "replacement" : undefined);
      const order = ["verification.update.before", "verification.input", "verification.output", "verification.update.after"];
      expect(kinds(state)).toEqual([...(cache ? ["cache.get", "cache.set"] : []), ...(adapter ? order.slice(0, order.indexOf(`verification.${fault}`) + 1) : [])]);
      if (!adapter) expect(out.result.value.label).toBe("replacement");
    });
  }
  scenario({mode, model, scenario: "update-rollback"}, out => {
    expect(out.result.error).toBe("rollback requested"); expect(out.insideAfter).toBe(false);
    expect(out.inside.label).toBe(adapter ? "replacement:in:out" : "replacement");
    expect(out.final.state.verifications[0]?.label).toBe(adapter ? "initial:in" : undefined);
    expect(out.final.state.cached?.label).toBe(cache ? "replacement" : undefined);
    expect(kinds(out.final.state)).not.toContain("verification.update.after");
  });
  scenario({mode, model, scenario: "consume"}, out => {
    expect(out.consumed.value.label).toBe(adapter ? "value:in:out" : "value"); expect(out.consumed.value.hidden).toBe("consume-secret");
    expect(kinds(out.consumed.state)).toEqual(adapter ? ["verification.output", "verification.delete.before", "verification.output", "verification.delete.after", ...(cache ? ["cache.delete"] : [])] : ["cache.getAndDelete"]);
    expect(out.consumed.state.verifications).toEqual([]); expect(out.consumed.state.cached).toBe(null); expect(out.again.value).toBe(null);
  });
  if (cache) {
    for (const transaction of ["outside", "rollback"]) scenario({mode, model, scenario: "create-cache-error", transaction}, out => {
      expect(out.result.error).toBe("fixture cache.set rejected"); expect(out.final.state.verifications.length).toBe(adapter && transaction === "outside" ? 1 : 0);
      expect(out.final.state.cached).toBe(null); expect(kinds(out.final.state)).not.toContain("verification.create.after"); expect(kinds(out.final.state).at(-1)).toBe("cache.set");
    });
    scenario({mode, model, scenario: "update-cache-error"}, out => {
      expect(out.result.error).toBe("fixture cache.set rejected"); expect(out.final.state.verifications[0]?.label).toBe(adapter ? "initial:in" : undefined);
      expect(out.final.state.cached.label).toBe(adapter ? "initial:in:out" : "initial"); expect(kinds(out.final.state)).toEqual(["cache.get", "cache.set"]);
    });
  }
}
