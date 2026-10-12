import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { assertSecondaryNativeVersions, createSecondaryNativeObserver } from "./secondary-native-shared.mjs";

function transition(name, operation) {
  const observer = createSecondaryNativeObserver();
  const events = [];
  const states = [];
  const record = (phase, root, result) => states.push({ phase, result, graph: observer.snapshot(root) });
  operation({ events, record });
  return { name, events, states, functions: observer.functions };
}

export function captureNativePropertyTransitions() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
  const cases = [];
  cases.push(transition("new-property-defaults-and-redefinition", ({ record }) => {
    const object = {};
    assert.equal(Reflect.defineProperty(object, "value", {}), true);
    record("default", object, true);
    assert.equal(Reflect.set(object, "value", 1), false);
    assert.equal(Reflect.deleteProperty(object, "value"), false);
    assert.equal(Reflect.defineProperty(object, "value", { configurable: true }), false);
    record("rejected-mutations", object, false);
    assert.equal(Reflect.defineProperty(object, "value", { value: undefined }), true);
    record("same-undefined", object, true);
  }));
  for (const [name, value, replacement, permitted] of [["nan", NaN, NaN, true], ["positive-zero", 0, -0, false], ["negative-zero", -0, 0, false]]) {
    cases.push(transition(`same-value-${name}`, ({ record }) => {
      const object = Object.defineProperty({}, "value", { value });
      const result = Reflect.defineProperty(object, "value", { value: replacement });
      assert.equal(result, permitted);
      assert.equal(Object.is(object.value, value), true);
      record("redefine", object, result);
      record("zero-sign", { negative: Object.is(object.value, -0) }, true);
    }));
  }
  cases.push(transition("data-accessor-data-replacement", ({ events, record }) => {
    const object = { value: 1 };
    const get = function getValue() { events.push("get"); return this.marker; };
    assert.equal(Reflect.defineProperty(object, "value", { get }), true);
    record("accessor", { object, get }, true);
    assert.equal(Reflect.get(object, "value", { marker: 9 }), 9);
    assert.equal(Reflect.set(object, "value", 2), false);
    record("getter-only", object, false);
    assert.deepEqual(events, ["get"]);
    assert.equal(Reflect.defineProperty(object, "value", { value: 3 }), true);
    record("data", object, true);
    assert.equal(Reflect.set(object, "value", 4), false);
  }));
  cases.push(transition("accessor-receiver-errors-and-delete", ({ events, record }) => {
    const failure = { original: true };
    const receiver = { marker: "receiver" };
    const object = {};
    const get = function getValue() { events.push(["get", this === receiver]); return this.marker; };
    const set = function setValue(value) {
      events.push(["set", this === receiver, value]);
      this.changed = value;
      if (value === "failure") throw failure;
    };
    assert.equal(Reflect.defineProperty(object, "value", { get, set, enumerable: true, configurable: true }), true);
    record("defined", { object, get, set }, true);
    assert.equal(Reflect.get(object, "value", receiver), "receiver");
    assert.equal(Reflect.set(object, "value", "changed", receiver), true);
    let caught;
    try { Reflect.set(object, "value", "failure", receiver); } catch (error) { caught = error; }
    assert.equal(caught, failure);
    assert.deepEqual(events, [["get", true], ["set", true, "changed"], ["set", true, "failure"]]);
    record("setter-failure", { object, receiver, failure, caught }, false);
    assert.equal(Reflect.deleteProperty(object, "value"), true);
    record("delete-without-get", object, true);
    assert.equal(events.length, 3);
  }));
  cases.push(transition("nonconfigurable-accessor-redefinition", ({ events, record }) => {
    const get = function getValue() { events.push("unexpected-get"); return 7; };
    const object = Object.defineProperty({}, "value", { get });
    assert.equal(Reflect.defineProperty(object, "value", { get }), true);
    record("same-getter", { object, get }, true);
    assert.equal(Reflect.defineProperty(object, "value", { get: undefined }), false);
    assert.equal(Reflect.defineProperty(object, "value", { value: 7 }), false);
    assert.equal(Reflect.deleteProperty(object, "value"), false);
    record("rejected", object, false);
    assert.deepEqual(events, []);
  }));
  for (const writable of [true, false]) {
    cases.push(transition(`array-length-partial-failure-${writable}`, ({ record }) => {
      const array = [0, 1, 2, 3];
      Object.defineProperty(array, "2", { configurable: false });
      record("before", array, true);
      const result = Reflect.defineProperty(array, "length", { value: 0, writable });
      assert.equal(result, false);
      assert.equal(array.length, 3);
      assert.equal(Object.hasOwn(array, "3"), false);
      assert.equal(Object.hasOwn(array, "2"), true);
      assert.equal(Object.getOwnPropertyDescriptor(array, "length").writable, writable);
      record("partial-deletion", array, result);
      const inserted = Reflect.defineProperty(array, "4", { value: 4, enumerable: true, configurable: true, writable: true });
      assert.equal(inserted, writable);
      record("extend", array, inserted);
    }));
  }
  cases.push(transition("array-accessor-shrink-does-not-read-getters", ({ events, record }) => {
    const array = [0, 1, 2];
    Object.defineProperty(array, "2", { get() { events.push("unexpected-get"); return 2; }, configurable: true });
    record("before", array, true);
    assert.equal(Reflect.defineProperty(array, "length", { value: 1 }), true);
    assert.deepEqual(events, []);
    record("after", array, true);
  }));
  return {
    version: "1.7.6", runtime: { bun: Bun.version },
    boundary: "Complete own-property transition graphs and callback events. SameValue records the zero sign explicitly. Prototype lookup and Symbols require separate contracts.",
    cases,
  };
}

if (import.meta.main) {
  assert.ok(process.argv[2], "Pass the native property transition output path");
  writeFileSync(process.argv[2], `${JSON.stringify(captureNativePropertyTransitions(), null, 2)}\n`);
}
