import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { captureGenericProfilePresets } from "./generic-profile-presets.mjs";

test("Generic profile helpers retain pinned configuration, requests, profiles, and mapper inputs", async () => {
  const expected = JSON.parse(readFileSync(new URL("../../../tests/fixtures/generic-profile-presets-1.7.6.json", import.meta.url), "utf8"));
  const actual = await captureGenericProfilePresets();
  expect(actual).toEqual(expected);
  const yandex = actual.cases.find(value => value.provider === "yandex" && value.name === "avatar")!;
  expect(Object.keys(yandex.expected.mapperInputs[0])).toEqual(["id", "name", "email", "emailVerified", "image"]);
});
