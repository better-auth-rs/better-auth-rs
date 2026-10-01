import { expect, test } from "bun:test";
import { captureEmailVerified } from "./email-verified-presence.mjs";
import fixture from "../../../tests/fixtures/email-verified-presence-1.7.6.json";

test("ordinary email verification fields and mapper metadata match the shared Rust fixture", async () => {
  expect(await captureEmailVerified()).toEqual(fixture);
});
