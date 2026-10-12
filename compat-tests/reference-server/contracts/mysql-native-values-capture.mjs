import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname } from "node:path";

const require = createRequire(import.meta.url);
const mysql2 = require("mysql2");
const escaperEntry = require.resolve("sql-escaper", { paths: [dirname(require.resolve("mysql2"))] });
const escaperRoot = dirname(dirname(escaperEntry));
const source = "ac9bfa502b26eea8f8503036a4944046701c37f755bd4da8710482980fe61eed";
for (const path of [escaperEntry, new URL("../../../vendor/sql-escaper-source/lib/index.js", import.meta.url)]) {
  if (createHash("sha256").update(readFileSync(path)).digest("hex") !== source) {
    throw new Error(`Unexpected sql-escaper source: ${path}`);
  }
}
const versions = {
  mysql2: require("mysql2/package.json").version,
  sqlEscaper: JSON.parse(readFileSync(`${escaperRoot}/package.json`)).version,
};
if (versions.mysql2 !== "3.24.5" || versions.sqlEscaper !== "1.5.2" || process.env.TZ !== "UTC") {
  throw new Error("Use pinned mysql2 3.24.5, sql-escaper 1.5.2, and TZ=UTC");
}

const units = (text) => Array.from({ length: text.length }, (_, index) => text.charCodeAt(index));
function observe(name, sql, value, events = [], thrown) {
  try {
    return { name, units: units(mysql2.format(sql, [value])), events };
  } catch (error) {
    return error === thrown
      ? { name, sameError: true, events }
      : { name, error: { name: error.name, message: error.message }, events };
  }
}

const getters = ["getTime", "getFullYear", "getMonth", "getDate", "getHours", "getMinutes", "getSeconds", "getMilliseconds"];
function dateNative(name, timestamp, configure = () => {}) {
  const date = new Date(timestamp);
  const events = [];
  const thrown = { marker: name };
  const overrides = new Map();
  const faults = {};
  configure({ date, events, thrown, overrides, faults });
  for (const method of getters) {
    Object.defineProperty(date, method, {
      get() {
        events.push(`get:${method}`);
        if (faults.get === method) throw thrown;
        if (faults.nonCallable === method) return false;
        return function () {
          events.push(`call:${method}:${this === date}:${arguments.length}`);
          if (faults.call === method) throw thrown;
          return overrides.has(method) ? overrides.get(method) : Date.prototype[method].call(this);
        };
      },
    });
  }
  return observe(name, "select ?", date, events, thrown);
}

const dates = [
  ...[0, -1, 1_893_553_445_006, NaN, -8_640_000_000_000_000, 8_640_000_000_000_000].map((timestamp, index) =>
    observe(`date-${index}`, "select ?", new Date(timestamp))),
  dateNative("date-read-order", 0),
  dateNative("date-nan-short-circuit", 0, ({ overrides }) => overrides.set("getTime", NaN)),
  dateNative("date-get-time-keeps-string", 0, ({ overrides }) => overrides.set("getTime", "NaN")),
  dateNative("date-invalid-overridden-time", NaN, ({ overrides }) => overrides.set("getTime", 0)),
  dateNative("date-cross-type-components", 0, ({ overrides }) => {
    for (const [name, value] of [["getFullYear", "2"], ["getMonth", "8"], ["getDate", null], ["getHours", true], ["getMinutes", NaN], ["getSeconds", undefined], ["getMilliseconds", 5]]) {
      overrides.set(name, value);
    }
  }),
  dateNative("date-padding-coercion-order", 0, ({ overrides, events }) => {
    let yearReads = 0;
    overrides.set("getFullYear", { valueOf() { events.push(`year:valueOf:${++yearReads}`); return yearReads === 1 ? 20 : 50; } });
    overrides.set("getMonth", { valueOf() { events.push("month:valueOf"); return 2; } });
  }),
  dateNative("date-getter-throws", 0, ({ faults }) => { faults.get = "getMonth"; }),
  dateNative("date-method-throws", 0, ({ faults }) => { faults.call = "getMonth"; }),
  dateNative("date-non-callable", 0, ({ faults }) => { faults.nonCallable = "getMonth"; }),
];

const arrays = [];
for (const depth of [64, 512, 2048]) {
  let value = 7;
  for (let index = 0; index < depth; index++) value = [value];
  arrays.push(observe(`array-depth-${depth}`, "select ?", value));
  arrays.push(observe(`identifier-depth-${depth}`, "select ??", value));
}
for (const sql of ["select ?", "select ??"]) {
  const self = [];
  self.push(self);
  arrays.push(observe(`self-cycle-${sql}`, sql, self));
  const left = [];
  const right = [left];
  left.push(right);
  arrays.push(observe(`mutual-cycle-${sql}`, sql, left));
}
{
  const value = [];
  const events = [];
  let calls = 0;
  value.push({ toSqlString() {
    events.push(`call:${++calls}`);
    if (calls === 2) value[1] = 9;
    return "NOW()";
  } }, value);
  arrays.push(observe("cycle-broken-on-second-callback", "select ?", value, events));
}
{
  const value = [null, 2];
  const events = [];
  value[0] = { toSqlString() { events.push("mutate"); delete value[1]; value.push(3); return "NOW()"; } };
  arrays.push(observe("array-captured-length-live-indices", "select ?", value, events));
}
{
  const value = Array(3);
  value[1] = "present";
  arrays.push(observe("array-holes", "select ?", value));
}

if (!process.argv[2]) throw new Error("Specify the source observation output path");
writeFileSync(process.argv[2], `${JSON.stringify({ versions, dates, arrays }, null, 2)}\n`);
