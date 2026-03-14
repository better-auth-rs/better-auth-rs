import { before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { BASE_URL, createTestClient } from "../auth-client.mjs";

async function fetchResetToken(email) {
  const response = await fetch(
    `${BASE_URL}/__test/reset-password-token?email=${encodeURIComponent(email)}`,
  );
  assert.equal(response.status, 200, "reset token helper should return 200");
  const body = await response.json();
  assert.equal(typeof body.token, "string");
  return body.token;
}

describe("phase1", () => {
  before(async () => {
    const res = await fetch(`${BASE_URL}/__health`).catch(() => null);
    if (!res?.ok) {
      throw new Error(`Server not reachable at ${BASE_URL}`);
    }
  });

  it("request password reset then reset password updates credentials", async () => {
    const { client } = createTestClient();
    const email = `phase1-reset-${Date.now()}@test.com`;

    const signup = await client.signUp.email({
      email,
      password: "password123",
      name: "Reset User",
    });
    assert.equal(signup.error, null);

    const requestReset = await client.requestPasswordReset({
      email,
      redirectTo: "/reset",
    });
    assert.equal(requestReset.error, null);
    assert.equal(requestReset.data?.status, true);

    const token = await fetchResetToken(email);
    const reset = await client.resetPassword({
      newPassword: "newPassword123!",
      token,
    });
    assert.equal(reset.error, null);
    assert.equal(reset.data?.status, true);

    const { client: freshClient } = createTestClient();
    const signIn = await freshClient.signIn.email({
      email,
      password: "newPassword123!",
    });
    assert.equal(signIn.error, null);
    assert.ok(signIn.data?.user);
  });

  it("list sessions and revoke a session through the SDK", async () => {
    const email = `phase1-sessions-${Date.now()}@test.com`;
    const password = "password123";

    const first = createTestClient();
    const second = createTestClient();

    const signup = await first.client.signUp.email({
      email,
      password,
      name: "Sessions User",
    });
    assert.equal(signup.error, null);

    const secondSignIn = await second.client.signIn.email({ email, password });
    assert.equal(secondSignIn.error, null);

    const sessions = await first.client.listSessions();
    assert.equal(sessions.error, null);
    assert.ok(Array.isArray(sessions.data));
    assert.ok(sessions.data.length >= 2);

    const currentSession = await first.client.getSession();
    assert.equal(currentSession.error, null);
    const currentToken = currentSession.data?.session?.token;
    assert.equal(typeof currentToken, "string");

    const revoke = await first.client.revokeSession({ token: currentToken });
    assert.equal(revoke.error, null);
    assert.equal(revoke.data?.status, true);

    const firstAfter = await first.client.getSession();
    assert.equal(firstAfter.data, null);

    const secondAfter = await second.client.getSession();
    assert.ok(secondAfter.data);
  });

  it("change password with revokeOtherSessions invalidates the other client", async () => {
    const email = `phase1-change-${Date.now()}@test.com`;
    const password = "password123";

    const primary = createTestClient();
    const secondary = createTestClient();

    const signup = await primary.client.signUp.email({
      email,
      password,
      name: "Change Password User",
    });
    assert.equal(signup.error, null);

    const secondarySignIn = await secondary.client.signIn.email({ email, password });
    assert.equal(secondarySignIn.error, null);

    const change = await primary.client.changePassword({
      currentPassword: password,
      newPassword: "newPassword123!",
      revokeOtherSessions: true,
    });
    assert.equal(change.error, null);
    assert.ok(change.data?.user);

    const primarySession = await primary.client.getSession();
    assert.ok(primarySession.data);

    const secondarySession = await secondary.client.getSession();
    assert.equal(secondarySession.data, null);
  });
});
