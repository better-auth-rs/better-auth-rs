import { describe, test, expect, beforeAll } from "bun:test";
import { createTestClient, BASE_URL } from "../auth-client.mjs";

describe("sign-in", () => {
  const TEST_EMAIL = `signin-${Date.now()}@test.com`;
  const TEST_PASSWORD = "password123";

  beforeAll(async () => {
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

  test("sign in with valid credentials returns user and token", async () => {
    const { client } = createTestClient();

    const result = await client.signIn.email({
      email: TEST_EMAIL,
      password: TEST_PASSWORD,
    });

    expect(result.error).toBeNull();
    expect(result.data).toBeDefined();
    expect(result.data.user).toBeDefined();
    expect(result.data.user.email).toBe(TEST_EMAIL);
    expect(typeof result.data.token).toBe("string");
  });

  test("sign in with wrong password returns error", async () => {
    const { client } = createTestClient();

    const result = await client.signIn.email({
      email: TEST_EMAIL,
      password: "wrong-password",
    });

    expect(result.error).toBeDefined();
    expect(result.error).not.toBeNull();
    expect(result.data).toBeNull();
  });

  test("sign in with nonexistent email returns error", async () => {
    const { client } = createTestClient();

    const result = await client.signIn.email({
      email: "nonexistent@test.com",
      password: TEST_PASSWORD,
    });

    expect(result.error).toBeDefined();
    expect(result.error).not.toBeNull();
    expect(result.data).toBeNull();
  });
});
