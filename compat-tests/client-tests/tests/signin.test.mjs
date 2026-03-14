import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { createTestClient, BASE_URL } from "../auth-client.mjs";

describe("sign-in", () => {
  const TEST_EMAIL = `signin-${Date.now()}@test.com`;
  const TEST_PASSWORD = "password123";

  before(async () => {
    const res = await fetch(`${BASE_URL}/api/auth/ok`).catch(() => null);
    if (!res?.ok) {
      throw new Error(`Server not reachable at ${BASE_URL}`);
    }

    // Create a test user
    const { client } = createTestClient();
    const result = await client.signUp.email({
      email: TEST_EMAIL,
      password: TEST_PASSWORD,
      name: "Signin User",
    });
    if (result.error) {
      throw new Error(`Failed to create test user: ${JSON.stringify(result.error)}`);
    }
  });

  it("sign in with valid credentials returns user and token", async () => {
    const { client } = createTestClient();

    const result = await client.signIn.email({
      email: TEST_EMAIL,
      password: TEST_PASSWORD,
    });

    assert.equal(result.error, null);
    assert.ok(result.data);
    assert.ok(result.data.user);
    assert.equal(result.data.user.email, TEST_EMAIL);
    assert.equal(typeof result.data.token, "string");
  });

  it("sign in with wrong password returns error", async () => {
    const { client } = createTestClient();

    const result = await client.signIn.email({
      email: TEST_EMAIL,
      password: "wrong-password",
    });

    assert.ok(result.error);
    assert.equal(result.data, null);
  });

  it("sign in with nonexistent email returns error", async () => {
    const { client } = createTestClient();

    const result = await client.signIn.email({
      email: "nonexistent@test.com",
      password: TEST_PASSWORD,
    });

    assert.ok(result.error);
    assert.equal(result.data, null);
  });
});
