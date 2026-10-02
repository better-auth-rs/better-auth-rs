import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/cookie-expires-1.7.6.json";
import { captureCookieExpires } from "../../../tests/fixtures/cookie-expires.capture.mjs";

type Capture = {
  metadata: { serializerNow: number };
  [key: string]: unknown;
};

function normalize(value: unknown, serializerNow: number, key?: string): unknown {
  if (key === "body" || key === "error" || key === "events") return value;
  if (typeof value === "string") {
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
      return Date.parse(value) - serializerNow;
    }
    if (key === "attributes" && value.startsWith("Expires=")) {
      return `Expires=${Date.parse(value.slice("Expires=".length)) - serializerNow}ms`;
    }
    return value;
  }
  if (Array.isArray(value)) {
    const normalized = value.map(item => normalize(item, serializerNow, key));
    return key === "attributes" ? normalized.sort() : normalized;
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([childKey, child]) => [
      childKey, normalize(child, serializerNow, childKey),
    ]));
  }
  return value;
}

function comparable(capture: Capture): unknown {
  const { metadata, ...sections } = capture;
  return normalize(sections, metadata.serializerNow);
}

test("ordinary explicit Cookie expires preserves writer, cleanup, hook, and telemetry behavior", async () => {
  const actual = await captureCookieExpires();
  expect(comparable(actual)).toStrictEqual(comparable(expected));
});
