import { describe, test, expect, beforeAll } from "bun:test";
import { createTestClient, BASE_URL } from "../auth-client.mjs";

describe("session", () => {
  beforeAll(async () => {
    const res = await fetch(`${BASE_URL}/api/auth/ok`).catch(() => null);
    if (!res?.ok) {
      throw new Error(`Server not reachable at ${BASE_URL}`);
    }
  });

  test("get session after sign-in returns session and user", async () => {
    const { client } = createTestClient();
    const email = `session-${Date.now()}@test.com`;

    // Sign up (also signs in)
    const signup = await client.signUp.email({
      email,
      password: "password123",
      name: "Session User",
    });
    expect(signup.error).toBeNull();

    // Get session — cookie should carry over
    const session = await client.getSession();

    expect(session.error).toBeNull();
    expect(session.data).toBeDefined();
    expect(session.data.user).toBeDefined();
    expect(session.data.user.email).toBe(email);
    expect(session.data.session).toBeDefined();
    expect(typeof session.data.session.id).toBe("string");
  });

  test("get session without auth returns null", async () => {
    const { client } = createTestClient();

    const session = await client.getSession();

    // Client returns null data when unauthenticated
    expect(session.data).toBeNull();
  });
});
