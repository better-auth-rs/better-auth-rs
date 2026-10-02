import { expect, test } from "bun:test";
import { captureWeChat } from "./wechat";

const fixture = await Bun.file(new URL("../../../tests/fixtures/wechat-1.7.6.json", import.meta.url)).json();
const captured = await captureWeChat();

test("WeChat capture uses pinned Better Auth 1.7.6", () => {
  expect(captured.metadata).toEqual(fixture.metadata);
  expect(captured.metadata.version).toBe("1.7.6");
});

for (const section of ["scopeCases", "grants", "grantFailures", "profileCases", "specialCases"] as const) {
  test(`WeChat ${section} match the captured ordinary contract`, () => {
    expect(captured[section]).toEqual(fixture[section]);
  });
}
