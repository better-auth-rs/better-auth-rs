const modules = `${import.meta.dir}/../../compat-tests/reference-server/node_modules`;
const { betterAuth } = await import(`${modules}/better-auth/dist/index.mjs`);

export async function capture(path) {
  const events = [];
  let adapter;
  let enabled = false;
  let nested = false;
  let changed = false;
  const auth = betterAuth({
    baseURL: "http://ordinary-memory-join.test",
    secret: "ordinary-memory-join-secret-with-more-than-thirty-two-characters",
    telemetry: { enabled: false }, logger: { disabled: true },
    rateLimit: { enabled: false },
    advanced: { database: { joins: true } },
    user: { additionalFields: {
      name: { type: "string", required: false, transform: { async output(value) {
        if (!enabled || nested) return value;
        events.push(["name", value]);
        if (!changed) {
          changed = true;
          nested = true;
          try {
            await adapter.update({ model: "user", where: [{ field: "id", value: "ordinary-user" }], update: { image: "image-after" } });
            events.push(["display-write", "image-after"]);
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
  await create("user", { id: "ordinary-user", name: "ordinary-name", image: "image-before", email: "ordinary@memory-join.test", emailVerified: true });
  await create("session", { id: "ordinary-session", token: "ordinary-session-token", userId: "ordinary-user", expiresAt: new Date("2099-01-01T00:00:00.000Z") });
  await create("account", { id: "ordinary-account", providerId: "ordinary-provider", accountId: "ordinary-account", userId: "ordinary-user" });
  enabled = true;
  const joined = path === "session"
    ? await context.internalAdapter.findSession("ordinary-session-token")
    : await context.internalAdapter.findAccountOwnerByKey({ providerId: "ordinary-provider", accountId: "ordinary-account" });
  enabled = false;
  const stored = await adapter.findOne({ model: "user", where: [{ field: "id", value: "ordinary-user" }] });
  return { path, events, result: { name: joined.user.name, image: joined.user.image }, stored: { name: stored.name, image: stored.image } };
}

if (import.meta.main) {
  const cases = [];
  for (const path of ["session", "owner"]) cases.push(await capture(path));
  console.log(JSON.stringify({ version: "1.7.6", cases }, null, 2));
}
