import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { createTestClient, BASE_URL } from "../auth-client.mjs";

describe("session", () => {
  before(async () => {
    const res = await fetch(`${BASE_URL}/api/auth/ok`).catch(() => null);
    if (!res?.ok) {
      throw new Error(`Server not reachable at ${BASE_URL}`);
    }
  });

  it("get session after sign-in returns session and user", async () => {
    const { client } = createTestClient();
    const email = `session-${Date.now()}@test.com`;

    // Sign up (also signs in)
    const signup = await client.signUp.email({
      email,
      password: "password123",
      name: "Session User",
    });
    assert.equal(signup.error, null);

    // Get session — cookie should carry over
    const session = await client.getSession();

    assert.equal(session.error, null);
    assert.ok(session.data);
    assert.ok(session.data.user);
    assert.equal(session.data.user.email, email);
    assert.ok(session.data.session);
    assert.equal(typeof session.data.session.id, "string");
  });

  it("get session without auth returns null", async () => {
    const { client } = createTestClient();

    const session = await client.getSession();

    // Client returns null data when unauthenticated
    assert.equal(session.data, null);
  });
});
