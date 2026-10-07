import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { captureAccountUserAuthCases } from "./account-user-auth-boundary-capture.mjs";

const scenarios = [true, false].map(emailSender => ({
  name: `social-owner-many-email-${emailSender ? "sender" : "no-sender"}`,
  route: "social", relation: "reverse-user-reference-many", many: true,
  requireEmailVerification: true, sendOnSignIn: true, emailSender,
}));

function configure(scenario, options, record) {
  options.socialProviders.google.requireEmailVerification = scenario.requireEmailVerification;
  options.logger = { level: "error", log(level, message, ...args) { record({ kind: "logger", level, message, args }); } };
  options.emailVerification = {
    sendOnSignIn: scenario.sendOnSignIn,
    ...(scenario.emailSender ? { sendVerificationEmail(data, request) {
      record({ kind: "email.sender", data, request: request ? {
        url: request.url, method: request.method, headers: [...request.headers],
      } : undefined });
      return Promise.resolve();
    } } : {}),
  };
}

function verify({ scenario, joins, before, after, response, body, events, requestWindow, idToken, nonce, milliseconds }) {
  assert.equal(response.status, 403);
  assert.deepEqual(JSON.parse(body), { code: "EMAIL_NOT_VERIFIED", message: "Email not verified" });
  assert.deepEqual(response.headers.getSetCookie(), []);
  assert.deepEqual(events.filter(event => event.kind === "api-error"), []);
  assert.deepEqual(events.filter(event => event.kind === "console.error"), []);
  assert.deepEqual(events.filter(event => event.kind === "email.sender"), []);
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
  assert.equal(admissions[0].data.source.method, "oauth");
  assert.equal(admissions[0].data.source.oauth.providerId, "google");
  assert.deepEqual(events.filter(event => event.kind === "query").map(({ operation, model }) => [operation, model]), [
    ["findMany", "account"], ...(!joins ? [["findMany", "user"]] : []), ["update", "account"],
  ]);

  const hooks = events.filter(event => event.kind === "hook");
  assert.deepEqual(hooks.map(({ model, operation, phase }) => [model, operation, phase]), [
    ["account", "update", "before"], ["account", "update", "after"],
  ]);
  assert.deepEqual(after.user, before.user);
  assert.deepEqual(after.session, before.session);
  assert.deepEqual(after.verification, before.verification);
  assert.deepEqual(after.session, []);
  const updatedAccount = after.account.find(row => row.id === "account-a");
  assert.ok(updatedAccount);
  assert.equal(updatedAccount.userId, "user-a");
  assert.deepEqual(after.account, before.account.map(row => row.id === "account-a"
    ? { ...row, idToken, updatedAt: updatedAccount.updatedAt } : row));
  const accountUpdatedAt = milliseconds(updatedAccount.updatedAt);
  assert.ok(accountUpdatedAt >= requestWindow.start && accountUpdatedAt <= requestWindow.end);
  assert.equal(milliseconds(hooks[1].data.updatedAt), accountUpdatedAt);

  const logs = events.filter(event => event.kind === "logger");
  assert.equal(logs.length, scenario.emailSender ? 1 : 0);
  if (scenario.emailSender) {
    const log = logs[0];
    assert.equal(log.level, "error");
    assert.equal(log.message, "Failed to send OAuth verification email");
    assert.equal(log.args.length, 1);
    assert.equal(log.args[0].name, "TypeError");
    assert.match(log.args[0].message, /toLowerCase/);
    const accountAfterIndex = events.indexOf(hooks[1]);
    assert.ok(events.indexOf(log) > accountAfterIndex, "The email failure must follow the completed Account update");
    assert.equal(events.at(-1), log, "Email rejection must not reach session creation or sender execution");
  }

  return {
    dynamic: { accountUpdatedAt }, replacements: new Map(), cookie: null,
    checked: {
      noNetwork: true, completeStorage: true, admissionIdIsUndefined: true,
      preservedCanonicalAccountOwner: true, accountDatesWithinRequest: true,
      verificationRejectedBeforeSession: true, emailSenderCalls: 0,
      missingEmailFailureLogged: scenario.emailSender,
    },
  };
}

export async function captureAccountUserAuthEmail() {
  const result = await captureAccountUserAuthCases(scenarios, { configure, verify });
  assert.equal(result.cases.length, 8);
  return result;
}

if (import.meta.main) {
  const serialized = `${JSON.stringify(await captureAccountUserAuthEmail(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], serialized);
  else process.stdout.write(serialized);
}
