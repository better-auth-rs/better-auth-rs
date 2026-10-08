const modules = `${import.meta.dir}/../../compat-tests/reference-server/node_modules`;
const { betterAuth } = await import(`${modules}/better-auth/dist/index.mjs`);

export async function capture(path, joins, database) {
  const events = [];
  let adapter;
  let enabled = false;
  let nested = false;
  const auth = betterAuth({
    database,
    baseURL: "http://ordinary-user-read.test",
    secret: "ordinary-user-read-secret-with-more-than-thirty-two-characters",
    telemetry: { enabled: false }, logger: { disabled: true },
    rateLimit: { enabled: false },
    advanced: { database: { joins, defaultFindManyLimit: 1 } },
    user: { additionalFields: {
      name: { type: "string", required: false, transform: { async output(value) {
        if (!enabled || nested) return value;
        events.push(["name", value]);
        nested = true;
        try {
          await adapter.update({ model: "user", where: [{ field: "id", value: "ordinary-user" }], update: { image: "image-after" } });
          events.push(["display-write", "image-after"]);
        } finally { nested = false; }
        return `${value}-visible`;
      } } },
    } },
  });
  const context = await auth.$context;
  adapter = context.adapter;
  const createdAt = new Date("2025-01-01T00:00:00.000Z");
  const create = (model, data) => adapter.create({ model, forceAllowId: true, data: { createdAt, updatedAt: createdAt, ...data } });
  const createUser = () => create("user", { id: "ordinary-user", name: "ordinary-name", image: "image-before", email: "ordinary@user-read.test", emailVerified: true });
  if (path !== "create") await createUser();
  if (path !== "create" && path !== "update") {
    await create("session", { id: "ordinary-session", token: "ordinary-session-token", userId: "ordinary-user", expiresAt: new Date("2099-01-01T00:00:00.000Z") });
    await create("account", { id: "ordinary-account", providerId: "ordinary-provider", accountId: "ordinary-account", userId: "ordinary-user" });
  }
  enabled = true;
  let users;
  switch (path) {
    case "create": users = [await createUser()]; break;
    case "update": users = [await context.internalAdapter.updateUser("ordinary-user", { image: "image-before" })]; break;
    case "point": users = [await context.internalAdapter.findUserById("ordinary-user")]; break;
    case "email": users = [(await context.internalAdapter.findUserByEmail("ordinary@user-read.test")).user]; break;
    case "user-accounts": users = [(await context.internalAdapter.findUserByEmail("ordinary@user-read.test", { includeAccounts: true })).user]; break;
    case "list": users = await adapter.findMany({ model: "user", limit: 1, sortBy: { field: "name", direction: "asc" } }); break;
    case "ids": users = await adapter.findMany({ model: "user", where: [{ field: "id", value: ["ordinary-user"], operator: "in" }], limit: 1 }); break;
    case "owner": users = [(await context.internalAdapter.findAccountOwnerByKey({ providerId: "ordinary-provider", accountId: "ordinary-account" })).user]; break;
    case "sessions": users = (await context.internalAdapter.findSessions(["ordinary-session-token"])).map((row) => row.user); break;
    default: throw new Error(`Unknown capture path: ${path}`);
  }
  enabled = false;
  const stored = await adapter.findOne({ model: "user", where: [{ field: "id", value: "ordinary-user" }] });
  const display = (user) => ({ name: user.name, image: user.image });
  return { path, joins, events, result: users.map(display), stored: display(stored) };
}

if (import.meta.main) {
  const cases = [];
  for (const path of ["point", "email", "list", "ids"]) cases.push(await capture(path, false));
  for (const path of ["owner", "sessions"]) for (const joins of [false, true]) cases.push(await capture(path, joins));
  for (const joins of [false, true]) cases.push(await capture("user-accounts", joins));
  console.log(JSON.stringify({ version: "1.7.6", cases }, null, 2));
}
