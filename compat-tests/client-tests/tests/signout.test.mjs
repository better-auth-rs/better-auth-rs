import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { createTestClient, BASE_URL } from "../auth-client.mjs";

describe("sign-out", () => {
  before(async () => {
    const res = await fetch(`${BASE_URL}/api/auth/ok`).catch(() => null);
    if (!res?.ok) {
      throw new Error(`Server not reachable at ${BASE_URL}`);
    }
  });

  it("sign out after sign-in invalidates session", async () => {
    const { client } = createTestClient();
    const email = `signout-${Date.now()}@test.com`;

    // Sign up (also signs in)
    const signup = await client.signUp.email({
      email,
      password: "password123",
      name: "Signout User",
    });
    assert.equal(signup.error, null);

    // Verify session exists
    const sessionBefore = await client.getSession();
    assert.ok(sessionBefore.data);

    // Sign out
    const signout = await client.signOut();
    assert.equal(signout.error, null);
    assert.ok(signout.data);
    assert.equal(signout.data.success, true);

    // Session should be gone
    const sessionAfter = await client.getSession();
    assert.equal(sessionAfter.data, null);
  });

  it("sign out without auth still succeeds", async () => {
    const { client } = createTestClient();

    const result = await client.signOut();

    // Should not error — sign-out is always 200
    assert.equal(result.error, null);
  });
});
