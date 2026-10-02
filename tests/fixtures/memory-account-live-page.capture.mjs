const modules = `${import.meta.dir}/../../compat-tests/reference-server/node_modules`;
const { betterAuth } = await import(`${modules}/better-auth/dist/index.mjs`);

export async function capture(joins) {
  const events = [];
  let adapter;
  let enabled = false;
  let nested = false;
  let changed = false;
  const auth = betterAuth({
    baseURL: "http://ordinary-account-page.test",
    secret: "ordinary-account-page-secret-with-more-than-thirty-two-characters",
    telemetry: { enabled: false }, logger: { disabled: true },
    rateLimit: { enabled: false },
    advanced: { database: { joins, defaultFindManyLimit: 2 } },
    account: { additionalFields: {
      displayLabel: { type: "string", required: false, transform: { async output(value) {
        if (!enabled || nested) return value;
        events.push(["displayLabel", value]);
        if (!changed) {
          changed = true;
          nested = true;
          try {
            await adapter.update({
              model: "account",
              where: [{ field: "id", value: "ordinary-account-b" }],
              update: { displayLabel: "label-b-after" },
            });
            events.push(["display-write", "label-b-after"]);
          } finally { nested = false; }
        }
        return `${value}-visible`;
      } } },
    } },
  });
  const context = await auth.$context;
  adapter = context.adapter;
  const createdAt = new Date("2025-01-01T00:00:00.000Z");
  const create = (model, data) => adapter.create({ model, forceAllowId: true, data: { createdAt, updatedAt: createdAt, ...data } });
  await create("user", { id: "ordinary-user", name: "ordinary-name", email: "ordinary@account-page.test", emailVerified: true });
  for (const suffix of ["a", "b"]) {
    await create("account", { id: `ordinary-account-${suffix}`, providerId: "ordinary-provider", accountId: `ordinary-account-${suffix}`, userId: "ordinary-user", displayLabel: `label-${suffix}-before` });
  }
  enabled = true;
  const joined = await context.internalAdapter.findUserByEmail("ordinary@account-page.test", { includeAccounts: true });
  enabled = false;
  const stored = await adapter.findMany({ model: "account", where: [{ field: "userId", value: "ordinary-user" }] });
  return { joins, events, result: joined.accounts.map((account) => account.displayLabel), stored: stored.map((account) => account.displayLabel) };
}

if (import.meta.main) {
  const cases = [];
  for (const joins of [false, true]) cases.push(await capture(joins));
  console.log(JSON.stringify({ version: "1.7.6", cases }, null, 2));
}
