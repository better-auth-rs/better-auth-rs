import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { createEmailVerificationToken } from "../node_modules/better-auth/dist/api/routes/email-verification.mjs";
import { withClock } from "./email-verification-duration-capture.mjs";
import {
  assertSecondaryNativeVersions, createSecondaryNativeObserver,
  secondaryNativeNow as now, secondaryNativeVersion as version,
} from "./secondary-native-shared.mjs";
import {
  inspectToken, nativeEndpoint, nativeLower, nativeUser, ownerEmail,
  secret, selectedEmail, withEmailConsumer,
} from "./native-email-consumer-source.mjs";
import { writeObservation } from "./write-observation.mjs";

export const nativeEmailConsumerCases = [
  ...["utf16", "native-json", "undefined", "null", "json-error"].map(mode => ({ group: "token", mode })),
  ...["reread", "second-getter-error", "verified-short-circuit"].map(mode => ({ group: "verification", mode })),
  ...[
    ["get", "same-object"], ["get", "distinct-objects"], ["accept", "left-getter-error"], ["reject", "right-call-error"],
  ].map(([route, mode]) => ({ group: "invitation", route, mode })),
  ...["memory", "sqlite"].flatMap(backend => ["zero", "string"].map(mode => ({ group: "selector", backend, mode }))),
];

function throwingValue(label) { return { message: `${label}-failure`, nullable: null, optional: undefined }; }

function jsonResult(native, failure, rejects) {
  const result = { marker: "original-result", calls: 0 };
  result.toJSON = function (...args) {
    native.call("result.toJSON:call", this, result, args);
    result.calls++;
    if (rejects) throw failure;
    return { transformed: 17, nullable: null, optional: undefined };
  };
  return result;
}

async function tokenCase(scenario) {
  const native = createSecondaryNativeObserver();
  const failure = throwingValue("token-json");
  const result = scenario.mode === "undefined" ? undefined : scenario.mode === "null" ? null
    : jsonResult(native, failure, scenario.mode === "json-error");
  const email = scenario.mode === "utf16" ? "MIXED\ud800@EXAMPLE.TEST"
    : nativeLower(native, "email", result, failure);
  const input = native.snapshot({ email, result, failure });
  let token;
  const outcome = await native.outcome(async () => {
    token = await createEmailVerificationToken(secret, email, undefined, 3600);
    return token;
  }, failure);
  const jwt = token === undefined ? undefined : await inspectToken(token);
  if (scenario.mode === "json-error") {
    assert.equal(outcome.returned, false);
    assert.equal(outcome.sameOriginal, true);
  } else {
    assert.equal(outcome.returned, true);
    const payload = JSON.parse(jwt.payload);
    assert.equal(payload.iat, now / 1000);
    assert.equal(payload.exp, now / 1000 + 3600);
    if (scenario.mode === "undefined") assert.equal(Object.hasOwn(payload, "email"), false);
    if (scenario.mode === "null") assert.equal(payload.email, null);
  }
  return { name: `token/${scenario.mode}`, scenario, input, outcome, jwt,
    events: native.events, after: native.snapshot({ email, result, failure }), functions: native.functions };
}

async function verificationCase(scenario) {
  const native = createSecondaryNativeObserver();
  const failure = throwingValue("email-second-getter");
  const first = nativeLower(native, "first", ownerEmail, failure);
  const second = nativeLower(native, "second", "SECOND@native-email-consumers.test", failure);
  const selected = nativeUser(native, read => {
    if (read === 2 && scenario.mode === "second-getter-error") throw failure;
    return read === 1 ? first : second;
  }, scenario.mode === "verified-short-circuit" ? [] : false);
  const messages = [];
  const input = native.snapshot({ user: selected.user, first, second, failure });
  const observed = await withEmailConsumer(native, {
    backend: "memory", user: selected.user,
    sender(data, request) {
      native.record("sender:call", { sameUser: data.user === selected.user, hasRequest: request !== undefined,
        data: native.snapshot(data) });
      messages.push(data);
      return Promise.resolve();
    },
  }, async ({ auth }) => nativeEndpoint(native, () => auth.api.sendVerificationEmail({
    headers: new Headers(), body: { email: ownerEmail, callbackURL: "/verified" }, returnHeaders: true, asResponse: false,
  }), failure));
  const jwt = messages.length === 0 ? undefined : await inspectToken(messages[0].token);
  if (scenario.mode === "reread") {
    assert.equal(observed.outcome.returned, true);
    assert.equal(selected.reads(), 2);
    assert.equal(first.calls, 1);
    assert.equal(second.calls, 1);
    assert.equal(messages.length, 1);
    assert.equal(JSON.parse(jwt.payload).email, "SECOND@native-email-consumers.test");
  } else {
    assert.equal(observed.outcome.returned, false);
    assert.equal(messages.length, 0);
    assert.equal(second.calls, 0);
    assert.equal(selected.reads(), scenario.mode === "second-getter-error" ? 2 : 1);
    if (scenario.mode === "second-getter-error") assert.equal(observed.outcome.sameOriginal, true);
  }
  const { response, ...serialized } = observed;
  return { name: `verification/${scenario.mode}`, scenario, input, ...serialized, jwt,
    reads: selected.reads(), events: native.events,
    afterValues: native.snapshot({ user: selected.user, first, second, failure, messages, response }),
    functions: native.functions };
}

async function invitationCase(scenario) {
  const native = createSecondaryNativeObserver();
  const failure = throwingValue("invitation-lower");
  const leftResult = { marker: "comparison-result" };
  const rightResult = scenario.mode === "distinct-objects" ? { marker: "comparison-result" } : leftResult;
  const left = nativeLower(native, "invitation.email", leftResult, failure,
    scenario.mode === "left-getter-error" ? "get" : undefined);
  const right = nativeLower(native, "user.email", rightResult, failure,
    scenario.mode === "right-call-error" ? "call" : undefined);
  const selected = nativeUser(native, () => right);
  const input = native.snapshot({ left, right, leftResult, rightResult, user: selected.user, failure });
  const observed = await withEmailConsumer(native, { backend: "memory", user: selected.user, invitationEmail: left },
    async ({ auth }) => nativeEndpoint(native, () => {
      const input = { headers: new Headers(), returnHeaders: true, asResponse: false };
      if (scenario.route === "get") return auth.api.getInvitation({ ...input, query: { id: "invitation" } });
      if (scenario.route === "accept") return auth.api.acceptInvitation({ ...input, body: { invitationId: "invitation" } });
      return auth.api.rejectInvitation({ ...input, body: { invitationId: "invitation" } });
    }, failure));
  if (scenario.mode === "same-object") {
    assert.equal(observed.outcome.returned, true);
    assert.equal(observed.response.email, left);
  } else {
    assert.equal(observed.outcome.returned, false);
    if (scenario.mode.endsWith("error")) assert.equal(observed.outcome.sameOriginal, true);
  }
  assert.equal(selected.reads(), scenario.mode === "left-getter-error" ? 0 : 1);
  assert.equal(native.events.some(event => event.phase.startsWith("organization:")), false);
  const { response, ...serialized } = observed;
  return { name: `invitation/${scenario.route}/${scenario.mode}`, scenario, input, ...serialized,
    reads: selected.reads(), events: native.events,
    afterValues: native.snapshot({ left, right, leftResult, rightResult, user: selected.user, failure, response }),
    functions: native.functions };
}

async function selectorCase(scenario) {
  const native = createSecondaryNativeObserver();
  const failure = throwingValue("selector-lower");
  const selector = scenario.mode === "zero" ? 0 : selectedEmail;
  const email = nativeLower(native, "user.email", selector, failure);
  const selected = nativeUser(native, () => email);
  const input = native.snapshot({ email, selector, user: selected.user, failure });
  const observed = await withEmailConsumer(native, { backend: scenario.backend, user: selected.user },
    async ({ auth }) => nativeEndpoint(native, () => auth.api.listUserInvitations({
      headers: new Headers(), query: { email: "fallback@native-email-consumers.test" }, returnHeaders: true, asResponse: false,
    }), failure));
  assert.equal(selected.reads(), 1);
  assert.equal(email.calls, 1);
  assert.equal(native.events.some(event => event.phase === "invitation.email:input"), false);
  const queries = native.events.filter(event => event.phase === "adapter:findMany");
  assert.ok(queries.length >= 1, "The truthy native email must reach the real adapter after returning its selector");
  const { response, ...serialized } = observed;
  return { name: `selector/${scenario.backend}/${scenario.mode}`, scenario, input, ...serialized,
    reads: selected.reads(), events: native.events,
    afterValues: native.snapshot({ email, selector, user: selected.user, failure, response }), functions: native.functions };
}

export async function captureNativeEmailConsumers() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
  const paths = [
    "better-auth/dist/api/routes/email-verification.mjs", "better-auth/dist/crypto/jwt.mjs",
    "better-auth/dist/api/routes/session.mjs", "better-auth/dist/plugins/organization/adapter.mjs",
    "better-auth/dist/plugins/organization/routes/crud-invites.mjs", "better-auth/dist/db/schema.mjs",
  ];
  const provenance = paths.map(path => ({ path,
    sha256: createHash("sha256").update(readFileSync(new URL(`../node_modules/${path}`, import.meta.url))).digest("hex") }));
  return withClock(async setClock => {
    setClock(now);
    const cases = [];
    for (const scenario of nativeEmailConsumerCases) {
      if (scenario.group === "token") cases.push(await tokenCase(scenario));
      else if (scenario.group === "verification") cases.push(await verificationCase(scenario));
      else if (scenario.group === "invitation") cases.push(await invitationCase(scenario));
      else cases.push(await selectorCase(scenario));
    }
    return { contract: "native-email-consumers", version, runtime: { name: "bun", version: Bun.version }, provenance,
      boundary: "Invoke the published email token helper and real Better Auth endpoints. Observe native method receivers, getter order, strict comparison identity, complete return values, signed payload bytes, callbacks, adapter selectors, and full Memory or SQLite storage. Preserve both backend observations without normalization. Email transport, OTP state machines, signup/signin gates, arbitrary prototype/Symbol behavior, and new sampling of existing fixtures are outside this additive batch.",
      cases };
  });
}

if (import.meta.main) {
  const output = `${JSON.stringify(await captureNativeEmailConsumers(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], output);
  await writeObservation(output);
}
