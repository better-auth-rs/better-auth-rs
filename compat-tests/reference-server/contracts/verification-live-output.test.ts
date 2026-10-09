import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { getCurrentAdapter } from "@better-auth/core/context";
import { getWithHooks } from "../node_modules/better-auth/dist/db/with-hooks.mjs";
import { base, date, row, stored } from "./verification-consume-hooks-contract";

type Backend = "memory" | "sqlite";
const original = () => row("target", "subject", "before");
const changed = () => ({ ...original(), value: "after", updatedAt: date(1) });

async function setup(backend: Backend) {
  const memory = { user: [], account: [], session: [], verification: [] };
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const options = base(sqlite ?? memoryAdapter(memory));
  if (sqlite) await (await getMigrations(options)).runMigrations();
  const writer = await betterAuth(options).$context;
  return {
    options, writer,
    storage: () => sqlite ? sqlite.query("SELECT * FROM verification ORDER BY id").all() : memory.verification,
    expectedStorage: (value: Record<string, unknown>) => sqlite ? stored("sqlite", value) : value,
    close: () => sqlite?.close(),
  };
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const path of ["create", "find", "update"] as const) {
    for (const reject of [false, true]) {
      test(`${backend} Verification ${path} output ${reject ? "preserves write then failure" : "reads the adapter record source"}`, async () => {
        const fixture = await setup(backend);
        try {
          const events: unknown[] = [];
          const failure = new TypeError("verification-output-rejected");
          const hooks = { verification: {
            create: { after(value: unknown) { events.push(["after-create", value]); } },
            update: { after(value: unknown) { events.push(["after-update", value]); } },
          } };
          const options: BetterAuthOptions = {
            ...fixture.options,
            verification: { additionalFields: {
              identifier: { type: "string", transform: { async output(value) {
                events.push(["identifier", value]);
                const written = await fixture.writer.adapter.update({ model: "verification", where: [{ field: "identifier", value: "subject" }], update: { value: "after", updatedAt: date(1) } });
                events.push(["write", written]);
                if (reject) throw failure;
                return value;
              } } },
              value: { type: "string", transform: { output(value) {
                events.push(["value", value]);
                return `${value}:out`;
              } } },
            } },
          };
          const reader = await betterAuth(options).$context;
          const withHooks = getWithHooks(reader.adapter, { options, hooks: [{ source: "user", hooks }] });
          if (path !== "create") await fixture.writer.adapter.create({ model: "verification", data: original(), forceAllowId: true });
          const operation = () => path === "create"
            ? withHooks.createWithHooks(original(), "verification")
            : path === "find"
              ? reader.adapter.findOne({ model: "verification", where: [{ field: "identifier", value: "subject" }] })
              : withHooks.updateWithHooks({ value: "before", updatedAt: date(0) }, [{ field: "identifier", value: "subject" }], "verification");
          const trace: unknown[] = [["identifier", "subject"], ["write", changed()]];
          if (reject) {
            let caught: unknown;
            try { await operation(); } catch (error) { caught = error; }
            expect(caught).toBe(failure);
          } else {
            const value = backend === "memory" ? "after" : "before";
            const projected = { ...(backend === "memory" ? changed() : original()), value: `${value}:out` };
            expect(await operation()).toStrictEqual(projected);
            trace.push(["value", value]);
            if (path !== "find") trace.push([`after-${path}`, projected]);
          }
          expect(events).toStrictEqual(trace);
          expect(fixture.storage()).toStrictEqual([fixture.expectedStorage(changed())]);
        } finally { fixture.close(); }
      });
    }
  }

  test(`${backend} Verification consumed output retains the detached record when its ID is reused`, async () => {
    const fixture = await setup(backend);
    try {
      const events: unknown[] = [];
      const replacement = row("target", "replacement", "other");
      let calls = 0;
      const reader = await betterAuth({
        ...fixture.options,
        verification: { additionalFields: {
          identifier: { type: "string", transform: { async output(value) {
            if (value === "replacement") return value;
            events.push(["identifier", value]);
            if (++calls === 2) {
              const tx = await getCurrentAdapter(fixture.writer.adapter);
              expect(await tx.findOne({ model: "verification", where: [{ field: "identifier", value: "subject" }] })).toBeNull();
              const written = await tx.create({ model: "verification", data: replacement, forceAllowId: true });
              events.push(["replacement", written]);
            }
            return value;
          } } },
          value: { type: "string", transform: { output(value) {
            if (value === "other") return value;
            events.push(["value", value]);
            return `${value}:out`;
          } } },
        } },
      }).$context;
      await fixture.writer.adapter.create({ model: "verification", data: original(), forceAllowId: true });
      expect(await reader.internalAdapter.consumeVerificationValue("subject")).toStrictEqual({ ...original(), value: "before:out" });
      expect(events).toStrictEqual([
        ["identifier", "subject"], ["value", "before"],
        ["identifier", "subject"], ["replacement", replacement], ["value", "before"],
      ]);
      expect(fixture.storage()).toStrictEqual([fixture.expectedStorage(replacement)]);
    } finally { fixture.close(); }
  });
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const mode of ["keep", "delete", "replace", "reread-failure"] as const) {
    test(`${backend} Verification reservation output failure rereads the original primary key after ${mode}`, async () => {
      const fixture = await setup(backend);
      try {
        const events: unknown[] = [];
        const failure = new TypeError("verification-reservation-output-rejected");
        const rereadFailure = new TypeError("verification-reservation-reread-rejected");
        const id = createHash("sha256").update("reserve:subject").digest("base64url");
        const retained = row(id, "subject", "before");
        const replacement = row(id, "replacement", "other");
        let calls = 0;
        const reader = await betterAuth({
          ...fixture.options,
          verification: { additionalFields: {
            identifier: { type: "string", transform: { async output(value) {
              events.push(["identifier", value]);
              if (++calls === 1) {
                if (mode === "delete" || mode === "replace") {
                  await fixture.writer.adapter.delete({ model: "verification", where: [{ field: "id", value: id }] });
                  events.push(["deleted"]);
                }
                if (mode === "replace") {
                  const written = await fixture.writer.adapter.create({ model: "verification", data: replacement, forceAllowId: true });
                  events.push(["replacement", written]);
                }
                throw failure;
              }
              if (mode === "reread-failure") throw rereadFailure;
              return value;
            } } },
            value: { type: "string", transform: { output(value) { events.push(["value", value]); return value; } } },
            createdAt: { type: "date", transform: { input() { return date(0); } } },
            updatedAt: { type: "date", transform: { input() { return date(0); } } },
          } },
        }).$context;
        let caught: unknown;
        let result: unknown;
        try {
          result = await reader.internalAdapter.reserveVerificationValue({ identifier: "subject", value: "before", expiresAt: date(100) });
        } catch (error) { caught = error; }
        expect(result).toBe(mode === "keep" || mode === "replace" ? false : undefined);
        expect(caught).toBe(mode === "delete" ? failure : mode === "reread-failure" ? rereadFailure : undefined);
        const trace: unknown[] = [["identifier", "subject"]];
        if (mode === "delete" || mode === "replace") trace.push(["deleted"]);
        if (mode === "replace") trace.push(["replacement", replacement]);
        if (mode !== "delete") trace.push(["identifier", mode === "replace" ? "replacement" : "subject"]);
        if (mode === "keep" || mode === "replace") trace.push(["value", mode === "replace" ? "other" : "before"]);
        expect(events).toStrictEqual(trace);
        expect(fixture.storage()).toStrictEqual(mode === "delete" ? [] : [fixture.expectedStorage(mode === "replace" ? replacement : retained)]);
      } finally { fixture.close(); }
    });
  }
}
