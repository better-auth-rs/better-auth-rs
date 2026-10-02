import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { siwe } from "better-auth/plugins";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

export const base = {
  baseURL: "http://wallet-fields.test",
  secret: "ordinary-wallet-extra-fields-secret-at-least-32-characters",
  logger: { disabled: true },
  telemetry: { enabled: false },
};
export const walletPlugin = () => siwe({
  domain: "wallet-fields.test",
  async getNonce() { throw new Error("The display-field contract must not request a nonce"); },
  async verifyMessage() { throw new Error("The display-field contract must not verify a message"); },
});
export const policies = () => ({
  label: { type: "string" as const, fieldName: "stored_label", required: false },
  note: { type: "string" as const, required: false, defaultValue: "default-note" },
  settings: { type: "json" as const, fieldName: "stored_settings", required: false },
});
export const plugin = (fields: ReturnType<typeof policies>) => ({
  id: "ordinary-wallet-additional-fields",
  schema: { walletAddress: { fields } },
});
export const address = "0x0000000000000000000000000000000000000001";
export const input = (userId: string) => ({
  userId, address, chainId: 1, isPrimary: false, createdAt: new Date("2030-01-01T00:00:00Z"),
  label: " Display ", settings: { compact: true, theme: "dark" },
});
export const display = (row: any) => ({ label: row.label, note: row.note, settings: row.settings });

export async function captureWalletAdditionalFields() {
  const cases = [];
  for (const backend of ["memory", "sqlite"] as const) {
    for (const scenario of ["success", "input-error", "output-error"] as const) {
      const memory = { user: [], session: [], account: [], verification: [], walletAddress: [] };
      const db = backend === "sqlite" ? new Database(":memory:") : undefined;
      try {
        const database = db ?? memoryAdapter(memory);
        const readerOptions = { ...base, database, plugins: [walletPlugin(), plugin(policies())] };
        if (db) await (await getMigrations(readerOptions)).runMigrations();
        const reader = (await betterAuth(readerOptions).$context).adapter;
        const user = await reader.create<any>({ model: "user", data: {
          name: "Display fixture", email: "display@wallet-fields.test", emailVerified: false,
          createdAt: new Date("2030-01-01T00:00:00Z"), updatedAt: new Date("2030-01-01T00:00:00Z"),
        } });
        const events: unknown[] = [];
        const callbackError = new Error(`ordinary Wallet ${scenario}`);
        const fields = {
          label: { ...policies().label, transform: {
            input(value: unknown) {
              events.push(["input", "label", value]);
              if (scenario === "input-error") throw callbackError;
              return typeof value === "string" ? value.trim() : value;
            },
            output(value: unknown) {
              events.push(["output", "label", value]);
              if (scenario === "output-error") throw callbackError;
              return `${value}:out`;
            },
          } },
          note: { ...policies().note, transform: {
            input(value: unknown) { events.push(["input", "note", value]); return value; },
            output(value: unknown) { events.push(["output", "note", value]); return value; },
          } },
          settings: { ...policies().settings, transform: {
            input(value: unknown) { events.push(["input", "settings", value]); return value; },
            output(value: unknown) { events.push(["output", "settings", value]); return value; },
          } },
        };
        const projecting = (await betterAuth({ ...base, database, plugins: [walletPlugin(), plugin(fields)] }).$context).adapter;
        const exact = [{ field: "address", value: address }, { field: "chainId", value: 1 }];
        let result: unknown;
        events.push(["operation", "create"]);
        if (scenario === "success") {
          const created = await projecting.create<any>({ model: "walletAddress", data: input(user.id) });
          events.push(["operation", "read-exact"]);
          const read = await projecting.findOne<any>({ model: "walletAddress", where: exact });
          events.push(["operation", "read-address"]);
          const byAddress = await projecting.findOne<any>({ model: "walletAddress", where: [{ field: "address", value: address }] });
          result = { created: display(created), readExact: display(read), readAddress: display(byAddress) };
        } else {
          let sameError = false;
          try { await projecting.create({ model: "walletAddress", data: input(user.id) }); }
          catch (error) {
            if (error !== callbackError) throw error;
            sameError = true;
          }
          result = { sameError, message: callbackError.message };
        }
        const stored = await reader.findOne<any>({ model: "walletAddress", where: exact });
        cases.push({ backend, scenario, events, result, stored: stored === null ? null : display(stored) });
      } finally {
        db?.close();
      }
    }
  }
  return {
    version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    cases,
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureWalletAdditionalFields(), null, 2));
