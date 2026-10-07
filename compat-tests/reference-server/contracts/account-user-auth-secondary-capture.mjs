import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { writeFileSync } from "node:fs";
import { captureAccountUserAuthCases } from "./account-user-auth-boundary-capture.mjs";

const scenarios = [{
  name: "social-owner-many-pure-secondary", route: "social",
  relation: "reverse-user-reference-many", many: true,
}];

function configure(_scenario, options, record) {
  const cache = new Map();
  options.session.storeSessionInDatabase = false;
  options.verification = { storeInDatabase: true };
  options.logger = { level: "error", log(level, message, ...args) { record({ kind: "logger", level, message, args }); } };
  options.secondaryStorage = {
    async get(key) {
      const value = cache.get(key)?.value ?? null;
      record({ kind: "secondary.get", key, value });
      return value;
    },
    async set(key, value, ttl) {
      record({ kind: "secondary.set", key, value, ttl });
      cache.set(key, { value, ttl });
    },
    async delete(key) {
      record({ kind: "secondary.delete", key });
      cache.delete(key);
    },
  };
  return {
    observeAdapter(adapter) {
      const findOne = adapter.findOne;
      adapter.findOne = async function(input) {
        record({ kind: "adapter.findOne.call", input });
        try {
          const value = await findOne.call(this, input);
          record({ kind: "adapter.findOne.return", value });
          return value;
        } catch (error) {
          record({ kind: "adapter.findOne.throw", error });
          throw error;
        }
      };
    },
    snapshot(tables) {
      return {
        tablePresence: Object.fromEntries(Object.entries(tables).map(([name, rows]) => [name, rows !== null])),
        cache: [...cache].map(([key, entry]) => ({ key, ...entry })),
      };
    },
  };
}

function verify({ backend, joins, before, after, response, body, events, requestWindow,
  idToken, nonce, milliseconds, observationBefore, observationAfter, secret, expiresIn }) {
  assert.deepEqual(observationBefore, {
    tablePresence: { user: true, session: backend !== "sqlite", account: true, verification: true },
    cache: [],
  });
  assert.deepEqual(observationAfter.tablePresence, observationBefore.tablePresence);
  assert.deepEqual(after.user, before.user);
  assert.deepEqual(after.verification, before.verification);
  assert.deepEqual(before.verification, []);
  assert.deepEqual(before.session, backend === "sqlite" ? null : []);
  assert.deepEqual(after.session, before.session);
  assert.deepEqual(events.filter(event => event.kind.startsWith("password.")), []);
  assert.deepEqual(events.filter(event => event.kind.startsWith("provider.")), [
    { kind: "provider.verify", token: idToken, nonce },
    { kind: "provider.userInfo", tokens: { idToken, accessToken: undefined, refreshToken: undefined, user: undefined } },
  ]);
  const admissions = events.filter(event => event.kind === "admission");
  assert.equal(admissions.length, 1);
  assert.equal(Object.hasOwn(admissions[0].data.user, "id"), true);
  assert.equal(admissions[0].data.user.id, undefined);
  assert.equal(admissions[0].data.source.action, "sign-in");
  const hooks = events.filter(event => event.kind === "hook");
  const accountAfter = hooks.find(event => event.model === "account" && event.phase === "after");
  const updatedAccount = after.account.find(row => row.id === "account-a");
  assert.ok(accountAfter && updatedAccount);
  assert.equal(updatedAccount.userId, "user-a");
  assert.deepEqual(after.account, before.account.map(row => row.id === "account-a"
    ? { ...row, idToken, updatedAt: updatedAccount.updatedAt } : row));
  const accountUpdatedAt = milliseconds(updatedAccount.updatedAt);
  assert.ok(accountUpdatedAt >= requestWindow.start && accountUpdatedAt <= requestWindow.end);
  assert.equal(milliseconds(accountAfter.data.updatedAt), accountUpdatedAt);

  const sessionBefore = hooks.find(event => event.model === "session" && event.phase === "before");
  assert.ok(sessionBefore);
  const issued = sessionBefore.data;
  assert.equal(Object.hasOwn(issued, "userId"), true);
  assert.equal(issued.userId, undefined);
  assert.equal(typeof issued.id, "string");
  assert.ok(issued.id.length > 0);
  assert.equal(typeof issued.token, "string");
  assert.equal(issued.token.length, 32);
  const session = Object.fromEntries(["createdAt", "updatedAt", "expiresAt"].map(key => [key, milliseconds(issued[key])]));
  assert.ok(session.createdAt >= accountUpdatedAt && session.createdAt <= requestWindow.end);
  assert.ok(session.updatedAt >= session.createdAt && session.updatedAt <= requestWindow.end);
  const expiryOrigin = session.expiresAt - expiresIn * 1000;
  assert.ok(expiryOrigin >= requestWindow.start && expiryOrigin <= session.createdAt);

  const queryCalls = events.filter(event => event.kind === "adapter.findOne.call");
  const queryResults = events.filter(event => event.kind === "adapter.findOne.return" || event.kind === "adapter.findOne.throw");
  assert.deepEqual(queryCalls.map(event => event.input), [{ model: "user", where: [{ field: "id", value: undefined }] }]);
  assert.equal(Object.hasOwn(queryCalls[0].input.where[0], "value"), true);
  assert.equal(queryResults.length, 1);
  assert.deepEqual(events.filter(event => event.kind === "query").map(({ operation, model }) => [operation, model]), [
    ["findMany", "account"], ...(!joins ? [["findMany", "user"]] : []), ["update", "account"], ["findOne", "user"],
  ]);

  const secondary = events.filter(event => event.kind.startsWith("secondary."));
  assert.deepEqual(secondary[0], { kind: "secondary.get", key: "active-sessions-undefined", value: null });
  const index = secondary[1];
  assert.equal(index.kind, "secondary.set");
  assert.equal(index.key, "active-sessions-undefined");
  assert.equal(typeof index.value, "string");
  assert.deepEqual(JSON.parse(index.value), [{ token: issued.token, expiresAt: session.expiresAt }]);
  assert.ok(Number.isInteger(index.ttl));
  assert.ok(index.ttl > 0 && index.ttl <= expiresIn);
  assert.ok(index.ttl >= Math.floor((session.expiresAt - requestWindow.end) / 1000));
  assert.ok(events.indexOf(accountAfter) < events.indexOf(sessionBefore));
  assert.ok(events.indexOf(sessionBefore) < events.indexOf(secondary[0]));
  assert.ok(events.indexOf(index) < events.indexOf(queryCalls[0]));
  assert.ok(events.indexOf(queryCalls[0]) < events.indexOf(queryResults[0]));

  const failed = queryResults[0].kind === "adapter.findOne.throw";
  const errors = events.filter(event => event.kind === "api-error");
  let cookie = null;
  if (failed) {
    assert.equal(response.status, 500);
    assert.equal(body, "");
    assert.equal(errors.length, 1);
    assert.deepEqual(errors[0].error, queryResults[0].error);
    assert.equal(secondary.length, 2);
    assert.deepEqual(response.headers.getSetCookie(), []);
  } else {
    assert.equal(response.status, 200);
    assert.deepEqual(errors, []);
    assert.deepEqual(events.filter(event => event.kind === "console.error"), []);
    assert.equal(secondary.length, 3);
    const cached = secondary[2];
    assert.equal(cached.kind, "secondary.set");
    assert.equal(cached.key, issued.token);
    assert.equal(cached.ttl, index.ttl);
    const envelope = JSON.parse(cached.value);
    assert.deepEqual(Object.keys(envelope), ["session", "user"]);
    assert.deepEqual(envelope.session, JSON.parse(JSON.stringify(issued)));
    assert.equal(Object.hasOwn(envelope.session, "userId"), false);
    assert.deepEqual(envelope.user, JSON.parse(JSON.stringify(queryResults[0].value)));
    const completed = hooks.find(event => event.model === "session" && event.phase === "after");
    assert.ok(completed);
    assert.deepEqual(completed.data, issued);
    assert.ok(events.indexOf(queryResults[0]) < events.indexOf(cached));
    assert.ok(events.indexOf(cached) < events.indexOf(completed));
    const json = JSON.parse(body);
    assert.deepEqual(Object.keys(json), ["redirect", "token", "user"]);
    assert.equal(json.redirect, false);
    assert.equal(json.token, issued.token);
    assert.deepEqual(Object.keys(json.user), ["0", "1"]);
    assert.deepEqual(Object.values(json.user).map(user => user.id), ["user-b", "user-c"]);
    const cookies = response.headers.getSetCookie();
    assert.equal(cookies.length, 1);
    const separator = cookies[0].indexOf(";");
    const signature = createHmac("sha256", secret).update(issued.token).digest("base64");
    assert.equal(cookies[0].slice(0, separator), `better-auth.session_token=${encodeURIComponent(`${issued.token}.${signature}`)}`);
    assert.equal(cookies[0].slice(separator), `; Max-Age=${expiresIn}; Path=/; HttpOnly; SameSite=Lax`);
    cookie = { raw: cookies[0], normalized: `better-auth.session_token=<verified-signed-session-token>${cookies[0].slice(separator)}` };
  }
  assert.deepEqual(hooks.map(({ model, operation, phase }) => [model, operation, phase]), [
    ["account", "update", "before"], ["account", "update", "after"], ["session", "create", "before"],
    ...(!failed ? [["session", "create", "after"]] : []),
  ]);
  assert.deepEqual(observationAfter.cache, secondary.filter(event => event.kind === "secondary.set")
    .map(({ key, value, ttl }) => ({ key, value, ttl })));
  const replacements = new Map([[issued.token, "<session-token>"], [issued.id, "<session-id>"]]);
  for (const [key, value] of Object.entries(session)) {
    replacements.set(`${JSON.stringify(key)}:${JSON.stringify(new Date(value).toISOString())}`, `${JSON.stringify(key)}:${JSON.stringify(`<session.${key}>`)}`);
  }
  replacements.set(`"expiresAt":${session.expiresAt}`, `"expiresAt":"<session.expiresAt.milliseconds>"`);
  return {
    dynamic: { accountUpdatedAt, session }, replacements, cookie, embeddedStrings: true,
    normalizeEvent(event) { return event.kind === "secondary.set" ? { ...event, ttl: "<session-ttl>" } : event; },
    observations: {
      before: observationBefore,
      after: { ...observationAfter, cache: observationAfter.cache.map(entry => ({ ...entry, ttl: "<session-ttl>" })) },
    },
    checked: {
      noNetwork: true, completeStorage: true, pureSecondarySession: true, completeSecondaryCalls: true,
      admissionIdIsUndefined: true, sessionOwnerIsOwnUndefined: true, adapterLookupValueIsOwnUndefined: true,
      sqliteUndefinedLookupObserved: backend === "sqlite", lookupOutcome: failed ? "throw" : "return",
      preservedCanonicalAccountOwner: true, sessionDatesWithinRequest: true, exactSharedTtl: !failed,
      sessionCookieMatchesToken: cookie !== null,
    },
  };
}

export async function captureAccountUserAuthSecondary() {
  const result = await captureAccountUserAuthCases(scenarios, { configure, verify });
  assert.equal(result.cases.length, 4);
  return result;
}

if (import.meta.main) {
  const serialized = `${JSON.stringify(await captureAccountUserAuthSecondary(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], serialized);
  else process.stdout.write(serialized);
}
