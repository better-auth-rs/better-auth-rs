import assert from "node:assert/strict";
import { APIError } from "@better-auth/core/error";

export const transportCases = [
  "array", "object", "number", "null", "undefined", "unread-result",
  "getter-error", "call-error", "api-error", "noncallable",
];
export const transportFails = name => ["getter-error", "call-error", "api-error", "noncallable"].includes(name);

export function createTransport(name) {
  assert.ok(transportCases.includes(name));
  const original = name === "api-error"
    ? new APIError("CONFLICT", { message: "Original transport error" })
    : { marker: name, ownUndefined: undefined };
  const events = [];
  const result = name === "array" ? ["internal", "hybrid"] : name === "number" ? 17
    : name === "null" ? null : name === "undefined" ? undefined
    : { marker: "retained result", ownUndefined: undefined };
  if (name === "unread-result") Object.defineProperty(result, "toJSON", {
    configurable: true, get() {
      assert.equal(arguments.length, 0);
      events.push("result:read");
      throw original;
    },
  });
  const receiver = Object.defineProperty({}, "split", {
    enumerable: true, configurable: true, get() {
      assert.equal(this, receiver);
      assert.equal(arguments.length, 0);
      events.push("split:get");
      if (name === "getter-error") throw original;
      if (name === "noncallable") return 17;
      return function (...args) {
        assert.equal(this, receiver);
        assert.deepEqual(args, [","]);
        events.push("split:call");
        if (["call-error", "api-error"].includes(name)) throw original;
        return result;
      };
    },
  });
  return { receiver, result, original, events, assertCalls() {
    assert.deepEqual(events, ["getter-error", "noncallable"].includes(name)
      ? ["split:get"] : ["split:get", "split:call"]);
  } };
}

export function reviveTransportInput(value) {
  if (Array.isArray(value)) return value.map(reviveTransportInput);
  if (value !== null && typeof value === "object") {
    if (value.type === "undefined" && Object.keys(value).length === 1) return undefined;
    if (value.type === "date" && Object.keys(value).length === 2) return new Date(value.value);
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, reviveTransportInput(child)]));
  }
  return value;
}
