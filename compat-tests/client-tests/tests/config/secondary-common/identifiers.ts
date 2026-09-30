import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { control } from "./scenarios";
const digest = (value: string) => new Bun.CryptoHasher("sha256").update(value).digest("base64url");

export function identifierScenarios(database: boolean, secondary = true) {
  compatScenario("verification identifier strategies preserve ordered prefixes and transform each operation once", async ctx => {
    const suffix = ctx.uniqueToken("policy");
    const identifiers = [`hash:${suffix}`, `custom:${suffix}`, `custom:specific:${suffix}`, `plain:${suffix}`];
    const stored = [digest(identifiers[0]!), `custom-${identifiers[1]}`, `custom-${identifiers[2]}`, identifiers[3]!];
    for (let index = 0; index < identifiers.length; index++) {
      const identifier = identifiers[index]!;
      const created = await control(ctx, { action: "create-verification", identifier, value: "initial" });
      expect(created.identifier).toBe(stored[index]);
      expect((await control(ctx, { action: "find-verification", identifier })).value).toBe("initial");
      await control(ctx, { action: "update-verification", identifier, value: "updated" });
      expect((await control(ctx, { action: "find-verification", identifier })).value).toBe("updated");
      if (secondary) expect((await control(ctx)).entries.some((entry: any) => entry.key === `verification:${stored[index]}`)).toBe(true);
      await control(ctx, { action: "delete-verification", identifier });
      expect(await control(ctx, { action: "find-verification", identifier })).toBeNull();
    }
    return { transformed: identifiers.length, records: (await control(ctx)).verifications };
  });

  compatScenario("verification identifier migration reads and consumes legacy plaintext without rewriting update or delete", async ctx => {
    const identifier = `hash:${ctx.uniqueToken("legacy")}`;
    await control(ctx, { action: "seed-verification", id: ctx.uniqueToken("legacy-id"), identifier, value: "legacy" });
    expect((await control(ctx, { action: "find-verification", identifier })).value).toBe("legacy");
    await control(ctx, { action: "update-verification", identifier, value: "new" });
    expect((await control(ctx, { action: "find-verification", identifier })).value).toBe("legacy");
    await control(ctx, { action: "delete-verification", identifier });
    expect((await control(ctx, { action: "find-verification", identifier })).value).toBe("legacy");
    expect((await control(ctx, { action: "consume-verification", identifier })).value).toBe("legacy");
    expect(await control(ctx, { action: "consume-verification", identifier })).toBeNull();
    const dual = `hash:${ctx.uniqueToken("dual")}`;
    await control(ctx, { action: "seed-verification", id: ctx.uniqueToken("old-id"), identifier: dual, value: "plain" });
    await control(ctx, { action: "create-verification", identifier: dual, value: "hashed" });
    expect((await control(ctx, { action: "consume-verification", identifier: dual })).value).toBe("hashed");
    const remaining = await control(ctx, { action: "consume-verification", identifier: dual });
    expect(remaining?.value ?? null).toBe(database ? "plain" : null);
    return { legacyConsumed: true, secondRepresentation: remaining?.value ?? null };
  });

  compatScenario("expired hashed verification blocks plaintext fallback and clears both cached representations", async ctx => {
    const identifier = `hash:${ctx.uniqueToken("expired-hash")}`;
    await control(ctx, { action: "seed-verification", id: ctx.uniqueToken("valid-id"), identifier, value: "plain" });
    await control(ctx, { action: "seed-verification", id: ctx.uniqueToken("expired-id"), identifier: digest(identifier), value: "expired", seconds: -1 });
    expect(await control(ctx, { action: "consume-verification", identifier })).toBeNull();
    if (secondary) {
      const state = await control(ctx);
      expect(state.entries.some((entry: any) => entry.key === `verification:${identifier}` || entry.key === `verification:${digest(identifier)}`)).toBe(false);
    }
    const remaining = await control(ctx, { action: "consume-verification", identifier });
    expect(remaining?.value ?? null).toBe(database ? "plain" : null);
    return { remaining: remaining?.value ?? null };
  });
}
