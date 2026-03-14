import { describe, test, expect, beforeAll } from "bun:test";
import { createTestClient, BASE_URL } from "../auth-client.mjs";

describe("sign-up", () => {
  beforeAll(async () => {
    const res = await fetch(`${BASE_URL}/api/auth/ok`).catch(() => null);
    if (!res?.ok) {
      throw new Error(`Server not reachable at ${BASE_URL}`);
    }
  });

  test("sign up with valid credentials returns user and token", async () => {
    const { client } = createTestClient();

    const result = await client.signUp.email({
      email: `signup-valid-${Date.now()}@test.com`,
      password: "password123",
      name: "Test User",
    });

    expect(result.error).toBeNull();
    expect(result.data).toBeDefined();
    expect(result.data.user).toBeDefined();
    expect(result.data.user.email).toContain("signup-valid-");
    expect(result.data.user.name).toBe("Test User");
    expect(typeof result.data.user.id).toBe("string");
    expect(typeof result.data.token).toBe("string");
  });

  test("sign up with duplicate email returns error", async () => {
    const email = `signup-dup-${Date.now()}@test.com`;
    const { client } = createTestClient();

    // First signup
    const first = await client.signUp.email({
      email,
      password: "password123",
      name: "First User",
    });
    expect(first.error).toBeNull();

    // Second signup with same email
    const second = await client.signUp.email({
      email,
      password: "password456",
      name: "Second User",
    });

    expect(second.error).toBeDefined();
    expect(second.error).not.toBeNull();
    expect(second.data).toBeNull();
  });

  test("sign up with short password returns error", async () => {
    const { client } = createTestClient();

    const result = await client.signUp.email({
      email: `signup-short-${Date.now()}@test.com`,
      password: "123",
      name: "Weak User",
    });

    expect(result.error).toBeDefined();
    expect(result.error).not.toBeNull();
    expect(result.data).toBeNull();
  });
});
