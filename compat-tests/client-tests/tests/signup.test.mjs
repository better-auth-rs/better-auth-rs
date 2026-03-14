import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { createTestClient, BASE_URL } from "../auth-client.mjs";

describe("sign-up", () => {
  before(async () => {
    const res = await fetch(`${BASE_URL}/api/auth/ok`).catch(() => null);
    if (!res?.ok) {
      throw new Error(`Server not reachable at ${BASE_URL}`);
    }
  });

  it("sign up with valid credentials returns user and token", async () => {
    const { client } = createTestClient();

    const result = await client.signUp.email({
      email: `signup-valid-${Date.now()}@test.com`,
      password: "password123",
      name: "Test User",
    });

    assert.equal(result.error, null);
    assert.ok(result.data);
    assert.ok(result.data.user);
    assert.ok(result.data.user.email.includes("signup-valid-"));
    assert.equal(result.data.user.name, "Test User");
    assert.equal(typeof result.data.user.id, "string");
    assert.equal(typeof result.data.token, "string");
  });

  it("sign up with duplicate email returns error", async () => {
    const email = `signup-dup-${Date.now()}@test.com`;
    const { client } = createTestClient();

    // First signup
    const first = await client.signUp.email({
      email,
      password: "password123",
      name: "First User",
    });
    assert.equal(first.error, null);

    // Second signup with same email
    const second = await client.signUp.email({
      email,
      password: "password456",
      name: "Second User",
    });

    assert.ok(second.error);
    assert.equal(second.data, null);
  });

  it("sign up with short password returns error", async () => {
    const { client } = createTestClient();

    const result = await client.signUp.email({
      email: `signup-short-${Date.now()}@test.com`,
      password: "123",
      name: "Weak User",
    });

    assert.ok(result.error);
    assert.equal(result.data, null);
  });
});
