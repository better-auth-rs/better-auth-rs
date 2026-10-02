import { Database } from "bun:sqlite";

const modules = `${import.meta.dir}/../../compat-tests/reference-server/node_modules`;
const { betterAuth } = await import(`${modules}/better-auth/dist/index.mjs`);
const { getMigrations } = await import(`${modules}/better-auth/dist/db/get-migration.mjs`);
const { APIError } = await import(`${modules}/better-auth/dist/api/index.mjs`);

const cases = [
  ...["session", "sessions", "owner", "accounts"].map(path => ({ path, mode: "sync", limit: 2 })),
  ...[undefined, 0, 1, 8].map(limit => ({ path: "accounts", mode: "sync", limit })),
  { path: "page", mode: "sync", limit: 2 },
  ...["session", "owner", "accounts"].map(path => ({ path, mode: "parent-read", limit: 2 })),
  { path: "sessions", mode: "parent-wait", limit: 2 },
  { path: "sessions", mode: "parent-error", limit: 2 },
  { path: "accounts", mode: "child-error", limit: 2 },
];

export async function capture(backend, joins, { path, mode, limit }) {
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const events = [];
  const firstStarted = Promise.withResolvers();
  const releaseFirst = Promise.withResolvers();
  const secondFinished = Promise.withResolvers();
  let adapter;
  let enabled = false;
  let nestedWrite = false;
  let changed = false;
  const failure = new APIError("BAD_REQUEST", {
    code: "ORDINARY_DISPLAY_FAILURE",
    message: "Ordinary display callback failed",
  });
  const parentField = path === "accounts" || path === "page"
    ? "user.name"
    : path === "owner" ? "account.displayLabel" : "session.userAgent";

  async function updateChildDisplay() {
    changed = true;
    nestedWrite = true;
    try {
      if (path === "accounts") {
        await adapter.update({
          model: "account", where: [{ field: "id", value: "account-a-0" }],
          update: { displayLabel: "A-label-0-after" },
        });
        events.push(["display-write", "A-label-0-after"]);
      } else {
        await adapter.update({
          model: "user", where: [{ field: "id", value: "user-a" }],
          update: { name: "A-after" },
        });
        events.push(["display-write", "A-after"]);
      }
    } finally {
      nestedWrite = false;
    }
  }

  function field(model, key) {
    const fieldName = `${model}.${key}`;
    return {
      type: "string", required: false,
      transform: { output(value) {
        if (!enabled || nestedWrite) return value;
        events.push([fieldName, value]);
        if (mode === "parent-error" && fieldName === parentField && value === "A-agent") throw failure;
        if (mode === "child-error" && fieldName === "account.displayLabel" && value === "A-label-0") throw failure;
        if (fieldName === "user.image" && value === "B-image") secondFinished.resolve();
        if (mode === "parent-wait" && fieldName === parentField && value === "A-agent") {
          firstStarted.resolve();
          return releaseFirst.promise.then(() => `${value}-visible`);
        }
        if (mode === "parent-read" && fieldName === parentField && !changed) {
          return updateChildDisplay().then(() => `${value}-visible`);
        }
        return `${value}-visible`;
      } },
    };
  }

  const options = {
    database,
    secret: "ordinary-native-join-secret-with-more-than-thirty-two-characters",
    baseURL: "http://ordinary-native-join.test",
    telemetry: { enabled: false }, logger: { disabled: true },
    rateLimit: { enabled: false },
    advanced: { database: { joins, defaultFindManyLimit: limit } },
    user: { additionalFields: { name: field("user", "name"), image: field("user", "image") } },
    session: { additionalFields: { userAgent: field("session", "userAgent") } },
    account: { additionalFields: { displayLabel: field("account", "displayLabel") } },
  };

  try {
    if (database) await (await getMigrations(options)).runMigrations();
    const context = await betterAuth(options).$context;
    adapter = context.adapter;
    const createdAt = new Date("2025-01-01T00:00:00.000Z");
    const create = (model, data) => adapter.create({
      model, forceAllowId: true, data: { createdAt, updatedAt: createdAt, ...data },
    });
    for (const label of ["A", "B", "C"]) {
      const suffix = label.toLowerCase();
      await create("user", {
        id: `user-${suffix}`, name: label, image: `${label}-image`,
        email: `${suffix}@ordinary-native-join.test`, emailVerified: true,
      });
      await create("session", {
        id: `session-${suffix}`, userId: `user-${suffix}`, token: `ordinary-session-${suffix}`,
        userAgent: `${label}-agent`, expiresAt: new Date("2099-01-01T00:00:00.000Z"),
      });
      for (let index = 0; index < 3; index++) {
        await create("account", {
          id: `account-${suffix}-${index}`, userId: `user-${suffix}`,
          providerId: "ordinary-provider", accountId: `ordinary-${suffix}-${index}`,
          displayLabel: `${label}-label-${index}`,
        });
      }
    }

    function displayUser(user) {
      return user && { name: user.name, image: user.image };
    }
    function displaySession(result) {
      return result && { userAgent: result.session.userAgent, user: displayUser(result.user) };
    }
    async function query() {
      if (path === "session") return displaySession(await context.internalAdapter.findSession("ordinary-session-a"));
      if (path === "sessions") return (await context.internalAdapter.findSessions([
        "ordinary-session-c", "ordinary-session-b", "ordinary-session-a",
      ])).map(displaySession);
      if (path === "owner") {
        const result = await context.internalAdapter.findAccountOwnerByKey({
          providerId: "ordinary-provider", accountId: "ordinary-a-0",
        });
        return result && { kind: result.kind, displayLabel: result.account.displayLabel, user: displayUser(result.user) };
      }
      if (path === "accounts") {
        const result = await context.internalAdapter.findUserByEmail("A@ordinary-native-join.test", { includeAccounts: true });
        return result && { user: displayUser(result.user), accounts: result.accounts.map(row => row.displayLabel) };
      }
      const rows = await adapter.findMany({
        model: "user", sortBy: { field: "name", direction: "asc" }, offset: 1, limit: 1,
        join: { account: { limit: 2 } },
      });
      return rows.map(row => ({ user: displayUser(row), accounts: row.account.map(account => account.displayLabel) }));
    }

    enabled = true;
    let originalError = false;
    const pending = query().then(result => ({ result })).catch(error => {
      if (error !== failure) throw error;
      originalError = true;
      return { error: { status: error.status, code: error.body?.code, message: error.body?.message } };
    });
    if (mode === "parent-wait") {
      await Promise.all([firstStarted.promise, secondFinished.promise]);
      events.push(["controller", "second-child-finished"]);
      releaseFirst.resolve();
    }
    const outcome = await pending;
    if (mode === "parent-error") await secondFinished.promise;
    enabled = false;
    const users = await adapter.findMany({ model: "user", sortBy: { field: "email", direction: "asc" }, limit: 10 });
    const accounts = await adapter.findMany({ model: "account", sortBy: { field: "accountId", direction: "asc" }, limit: 10 });
    return {
      backend, joins, path, mode, limit: limit ?? null, events, ...outcome, originalError,
      stored: { users: users.map(displayUser), accounts: accounts.map(row => row.displayLabel) },
    };
  } finally {
    database?.close();
  }
}

if (import.meta.main) {
  const observations = [];
  for (const backend of ["memory", "sqlite"]) {
    for (const joins of [false, true]) {
      for (const config of cases) observations.push(await capture(backend, joins, config));
    }
  }
  console.log(JSON.stringify({ version: "1.7.6", cases: observations }, null, 2));
}
