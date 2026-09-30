import { expect, test } from "bun:test";
import { normalizeDeviceCookieName } from "./normalize";

test("device cookie aliases preserve session identity and unrelated cookie names", () => {
  const aliases = new Map<string, string>();
  const first = normalizeDeviceCookieName("better-auth.session_token_multi-first123", aliases);
  const second = normalizeDeviceCookieName("better-auth.session_token_multi-second456", aliases);
  expect(first).not.toBe(second);
  expect(normalizeDeviceCookieName("better-auth.session_token_multi-first123", aliases)).toBe(first);
  expect(normalizeDeviceCookieName("__Secure-better-auth.session_token_multi-first123", aliases)).toBe(`__Secure-${first}`);
  expect(normalizeDeviceCookieName("other_multi-first123", aliases)).toBe("other_multi-first123");
  expect(normalizeDeviceCookieName("better-auth.session_token_multi-", aliases)).toBe("better-auth.session_token_multi-");
});
