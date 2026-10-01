import { expect, test } from "bun:test";
import { clientDiffs, normalizeClientValue } from "./normalize";

test("business identifiers, token types, expiry fields and redirect origins remain observable", () => {
  for (const [left, right] of [
    [{ providerId: "google" }, { providerId: "github" }],
    [{ configId: "machine" }, { configId: "organization" }],
    [{ accountId: "provider-user-one" }, { accountId: "provider-user-two" }],
    [{ providerId: "credential", accountId: "alice", userId: "alice" }, { providerId: "credential", accountId: "mallory", userId: "bob" }],
    [{ tokenType: "Bearer" }, { tokenType: "invalid" }],
    [{ accessToken: "expected-provider-token" }, { accessToken: "wrong-provider-token" }],
    [{ expiresAt: "2026-01-01T00:00:00Z" }, { expiresAt: "2099-01-01T00:00:00Z" }],
    [{ refreshTokenExpiresAt: null }, {}],
    [{ metadata: { id: "expected" } }, { metadata: { id: "wrong" } }],
    [{ metadata: { expiresAt: "2026-01-01T00:00:00Z" } }, { metadata: { expiresAt: "2026-01-01T00:00:05Z" } }],
    [{ rp: { id: "example.com" } }, { rp: { id: "attacker.com" } }],
    [{ user: { id: "alice" }, session: { userId: "alice" } }, { user: { id: "bob" }, session: { userId: "mallory" } }],
    [{ team: { id: "team-a" }, session: { activeTeamId: "team-a" } }, { team: { id: "team-b" }, session: { activeTeamId: "wrong-team" } }],
    [{ role: { id: "role-a" }, roleId: "role-a" }, { role: { id: "role-b" }, roleId: "wrong-role" }],
    [{ token: "" }, { token: "valid-secret" }],
    [{ location: "https://trusted.example/callback" }, { location: "https://wrong.example/callback" }],
  ]) {
    expect(clientDiffs(left, right).length).toBeGreaterThan(0);
  }
});

test("only generated fields and bounded clock skew are normalized", () => {
  expect(clientDiffs(
    { id: "random-left", token: "secret-left", createdAt: new Date("2026-01-01T00:00:00Z") },
    { id: "random-right", token: "secret-right", createdAt: "2026-01-01T00:00:02Z" },
  )).toEqual([]);
  expect(clientDiffs({ expiresAt: "invalid" }, { expiresAt: "2026-01-01T00:00:00Z" }).length).toBeGreaterThan(0);
  expect(clientDiffs({ userId: null }, { userId: "random" }).length).toBeGreaterThan(0);
  expect(normalizeClientValue({ callbackURL: "https://example.com/callback" })).toEqual({ callbackURL: "https://example.com/callback" });
  expect(clientDiffs(
    { user: { id: "alice" }, session: { userId: "alice" } },
    { user: { id: "bob" }, session: { userId: "bob" } },
  )).toEqual([]);
  expect(clientDiffs(
    { providerId: "credential", accountId: "alice", userId: "alice" },
    { providerId: "credential", accountId: "bob", userId: "bob" },
  )).toEqual([]);
});

test("OIDC nonce entropy is normalized while absent or empty nonce remains observable", () => {
  const location = "https://issuer.example/authorize?nonce=";
  expect(clientDiffs({ location: `${location}random-left` }, { location: `${location}random-right` })).toEqual([]);
  expect(clientDiffs({ location: `${location}random-left` }, { location }).length).toBeGreaterThan(0);
  expect(clientDiffs({ location: `${location}random-left` }, { location: "https://issuer.example/authorize" }).length).toBeGreaterThan(0);
});

test("device verification URLs normalize server ports while preserving code bindings", () => {
  const normalize = (base: string, code: string) => normalizeClientValue({ verification_uri: `${base}/device`, verification_uri_complete: `${base}/device?user_code=${code}` }, "", base);
  expect(clientDiffs(normalize("http://localhost:3100", "CODE"), normalize("http://localhost:3200", "CODE"))).toEqual([]);
  expect(clientDiffs(normalize("http://localhost:3100", "CODE"), normalize("http://localhost:3200", "OTHER")).length).toBeGreaterThan(0);
});

test("team ID arrays retain membership, order and raw replacement values", () => {
  const left = { teams: [{ id: "one" }, { id: "two" }], hook: { teamIds: ["one", "two"] } };
  expect(clientDiffs(left, { teams: [{ id: "a" }, { id: "b" }], hook: { teamIds: ["a", "b"] } })).toEqual([]);
  for (const teamIds of [["b", "a"], ["a"], ["a", "unknown"], 0, null]) {
    expect(clientDiffs(left, { teams: [{ id: "a" }, { id: "b" }], hook: { teamIds } }).length).toBeGreaterThan(0);
  }
  expect(clientDiffs({ teamIds: [7] }, { teamIds: [8] }).length).toBeGreaterThan(0);
  expect(clientDiffs({ teamIds: [""] }, { teamIds: ["a"] }).length).toBeGreaterThan(0);
});
