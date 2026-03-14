import { describe, test, expect, beforeAll } from "bun:test";
import { createTestClient, BASE_URL } from "../auth-client.mjs";

describe("sign-out", () => {
  beforeAll(async () => {
    const res = await fetch(`${BASE_URL}/api/auth/ok`).catch(() => null);
    if (!res?.ok) {
      throw new Error(`Server not reachable at ${BASE_URL}`);
    }
  });

  test("sign out after sign-in invalidates session", async () => {
    const { client } = createTestClient();
    const email = `signout-${Date.now()}@test.com`;

    // Sign up (also signs in)
    const signup = await client.signUp.email({
      email,
      password: "password123",
      name: "Signout User",
    });
    expect(signup.error).toBeNull();

    // Verify session exists
    const sessionBefore = await client.getSession();
    expect(sessionBefore.data).toBeDefined();
    expect(sessionBefore.data).not.toBeNull();

    // Sign out
    const signout = await client.signOut();
    expect(signout.error).toBeNull();
    expect(signout.data).toBeDefined();
    expect(signout.data.success).toBe(true);

    // Session should be gone
    const sessionAfter = await client.getSession();
    expect(sessionAfter.data).toBeNull();
  });

  test("sign out without auth still succeeds", async () => {
    const { client } = createTestClient();

    const result = await client.signOut();

    // Should not error — sign-out is always 200
    expect(result.error).toBeNull();
  });
});
