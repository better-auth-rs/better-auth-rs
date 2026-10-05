import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { siwe } from "better-auth/plugins";
import { captureFreshServerCatalog, observeServerIndexes } from "./server-catalog-shared.mjs";
import { observeSqliteCatalog } from "./sqlite-catalog.ts";

const input = {
  address: "0x1111111111111111111111111111111111111111",
  wallets: [
    { chainId: 1, isPrimary: true, createdAt: "2030-01-02T03:04:05.123Z" },
    { chainId: 137, isPrimary: false, createdAt: "2030-01-02T03:04:06.456Z" },
  ],
};
const fields = ["id", "userId", "address", "chainId", "isPrimary", "createdAt"];
const json = value => JSON.parse(JSON.stringify(value));

async function observeWallets({ options, query, backend }, configuration, callbackCount) {
  const context = await betterAuth(options).$context;
  const adapter = context.adapter;
  const owner = await adapter.create({
    model: "user",
    data: {
      name: "Wallet catalog owner", email: "owner@wallet-catalog.test", emailVerified: false,
      createdAt: new Date(input.wallets[0].createdAt), updatedAt: new Date(input.wallets[0].createdAt),
    },
  });
  assert.equal(typeof owner.id, "string");
  assert.ok(owner.id.length > 0);
  const created = [];
  let byAddress;
  for (const wallet of input.wallets) {
    const value = json(await adapter.create({
      model: "walletAddress",
      data: { userId: owner.id, address: input.address, ...wallet, createdAt: new Date(wallet.createdAt) },
    }));
    assert.equal(typeof value.id, "string");
    assert.ok(value.id.length > 0);
    assert.deepEqual(value, { id: value.id, userId: owner.id, address: input.address, ...wallet });
    created.push(value);
    if (created.length === 1) {
      byAddress = json(await adapter.findOne({ model: "walletAddress", where: [{ field: "address", value: input.address }] }));
      assert.deepEqual(byAddress, value);
    }
  }
  assert.notEqual(created[0].id, created[1].id);
  const byAddressAndChain = [];
  for (const wallet of input.wallets) {
    byAddressAndChain.push(json(await adapter.findOne({
      model: "walletAddress",
      where: [{ field: "address", value: input.address }, { field: "chainId", value: wallet.chainId }],
    })));
  }
  assert.deepEqual(byAddressAndChain, created);
  const byOwner = json(await adapter.findMany({
    model: "walletAddress", where: [{ field: "userId", value: owner.id }],
    sortBy: { field: "chainId", direction: "asc" },
  }));
  assert.deepEqual(byOwner, created);

  const quote = name => backend === "mysql" ? `\`${name.replaceAll("`", "``")}\`` : `"${name.replaceAll('"', '""')}"`;
  const schema = configuration.walletAddress;
  const fieldName = field => schema?.fields?.[field] || field;
  const columns = fields.map(field => `${quote(fieldName(field))} AS ${quote(field)}`).join(", ");
  const raw = await query(`SELECT ${columns} FROM ${quote(schema?.modelName || "walletAddress")} ORDER BY ${quote(fieldName("chainId"))}`, []);
  const rawTypes = raw.map(row => Object.fromEntries(Object.entries(row).map(([field, value]) => [field, Object.prototype.toString.call(value)])));
  const rawVisible = json(raw);
  assert.deepEqual(rawVisible, created.map(row => ({ ...row, isPrimary: backend === "postgres" ? row.isPrimary : Number(row.isPrimary) })));
  for (const row of raw) {
    assert.equal(typeof row.chainId, "number");
    assert.ok(Number.isSafeInteger(row.chainId));
    // SQLite's adapter writes ISO strings; server driver types remain visible in rawTypes.
    if (backend === "sqlite") assert.equal(typeof row.createdAt, "string");
  }
  const retainedOwner = await adapter.findOne({ model: "user", where: [{ field: "id", value: owner.id }] });
  assert.equal(retainedOwner.id, owner.id);
  assert.equal(callbackCount(), 0);

  function visible(row) {
    const wallet = created.find(value => value.id === row.id);
    assert.ok(wallet);
    assert.equal(row.userId, owner.id);
    return { ...row, id: `<wallet-${wallet.chainId}-id>`, userId: "<owner-id>" };
  }
  return {
    created: created.map(visible), byAddress: visible(byAddress),
    byAddressAndChain: byAddressAndChain.map(visible), byOwner: byOwner.map(visible),
    raw: rawVisible.map(visible), rawTypes, ownerRetained: true, siweCallbacks: callbackCount(),
  };
}

async function captureSqlite(tableName, configuration, observeRows) {
  const database = new Database(":memory:");
  try {
    const options = {
      database, baseURL: "http://catalog.example.test",
      secret: "ordinary-server-catalog-secret-at-least-32-characters",
      logger: { disabled: true }, telemetry: { enabled: false }, ...configuration,
    };
    const initial = await getMigrations(options);
    const initialSql = await initial.compileMigrations();
    await initial.runMigrations();
    const catalog = observeSqliteCatalog(database, tableName, "The generated WalletAddress table exists in the SQLite catalog");
    const repeated = await getMigrations(options);
    assert.equal(repeated.toBeCreated.length, 0);
    assert.equal(repeated.toBeAdded.length, 0);
    assert.equal(repeated.toBeAddedIndexes.length, 0);
    assert.equal(repeated.schemaProblems.length, 0);
    const storage = await observeRows({ options, backend: "sqlite", query: async (sql, values) => database.query(sql).all(...values) });
    return { ...catalog, migration: { initialSql, repeatedSql: await repeated.compileMigrations() }, observation: { storage } };
  } finally {
    database.close();
  }
}

export async function captureWalletAddressCatalog(backend) {
  assert.ok(["sqlite", "postgres", "mysql"].includes(backend), "Select sqlite, postgres or mysql");
  const version = JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")).version;
  assert.equal(version, "1.7.6");
  const configurations = JSON.parse(readFileSync(new URL("../../schema-consumer/wallet-address-catalog-config.json", import.meta.url), "utf8"));
  const cases = [];
  for (const name of backend === "sqlite" ? ["default", "legacy", "custom"] : ["default", "custom"]) {
    const configuration = configurations[name];
    const tableName = configuration.walletAddress?.modelName || "walletAddress";
    let callbacks = 0;
    const unusedCallback = async () => { callbacks += 1; throw new Error("Storage observation must not invoke SIWE callbacks"); };
    const options = { plugins: [siwe({
      domain: "wallet-catalog.test", getNonce: unusedCallback, verifyMessage: unusedCallback,
      ...(configuration.walletAddress === undefined ? {} : { schema: configuration }),
    })] };
    const observeRows = context => observeWallets(context, configuration, () => callbacks);
    const observation = backend === "sqlite"
      ? await captureSqlite(tableName, options, observeRows)
      : await captureFreshServerCatalog(backend, [tableName], options, async context => ({
        ...await observeServerIndexes(context, tableName), storage: await observeRows(context),
      }));
    cases.push({ name, configuration, ...observation });
  }
  // Compare the complete JSON-visible result; rawTypes preserves driver types before JSON serialization.
  return json({ version, database: backend, input, cases });
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the second argument");
  writeFileSync(output, `${JSON.stringify(await captureWalletAddressCatalog(backend), null, 2)}\n`);
}
