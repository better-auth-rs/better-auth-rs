import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";

const baseProfile = {
  id: 42,
  login: "octocat",
  name: "Octo Cat",
  avatar_url: "https://images.example.test/octocat.png",
};
const primary = [
  { email: "secondary@example.test", primary: false, verified: false },
  { email: "primary@example.test", primary: true, verified: true },
];
const cases: {
  name: string;
  rawEmail: string | null | undefined;
  status: number;
  emails: unknown;
  email: string | null | undefined;
  ownEmail: boolean;
  verified: boolean;
}[] = [
  { name: "omitted email with an empty list", rawEmail: undefined, status: 200, emails: [], email: undefined, ownEmail: true, verified: false },
  { name: "null email with an empty list", rawEmail: null, status: 200, emails: [], email: undefined, ownEmail: true, verified: false },
  { name: "empty email with an empty list", rawEmail: "", status: 200, emails: [], email: undefined, ownEmail: true, verified: false },
  { name: "omitted email with an unavailable list", rawEmail: undefined, status: 503, emails: {}, email: undefined, ownEmail: false, verified: false },
  { name: "null email with an unavailable list", rawEmail: null, status: 503, emails: {}, email: null, ownEmail: true, verified: false },
  { name: "empty email with an unavailable list", rawEmail: "", status: 503, emails: {}, email: "", ownEmail: true, verified: false },
  { name: "null email selects the primary record", rawEmail: null, status: 200, emails: primary, email: "primary@example.test", ownEmail: true, verified: true },
  { name: "empty email selects the primary record", rawEmail: "", status: 200, emails: primary, email: "primary@example.test", ownEmail: true, verified: true },
  { name: "nonempty email keeps its value with an empty list", rawEmail: "public@example.test", status: 200, emails: [], email: "public@example.test", ownEmail: true, verified: false },
  { name: "no primary selects the first record", rawEmail: null, status: 200, emails: [{ email: "first@example.test", primary: false, verified: true }, { email: "second@example.test", primary: false, verified: false }], email: "first@example.test", ownEmail: true, verified: true },
  { name: "the selected empty email is retained", rawEmail: null, status: 200, emails: [{ email: "secondary@example.test", primary: false, verified: false }, { email: "", primary: true, verified: true }], email: "", ownEmail: true, verified: true },
];

const normalized = (value: unknown) => JSON.parse(JSON.stringify(value));
const presence = (value: Record<string, unknown>) => ({
  ownEmail: Object.hasOwn(value, "email"),
  emailIsUndefined: value.email === undefined,
});

test("uses pinned Better Auth core 1.7.6", async () => {
  const core = await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json();
  expect(core.version).toBe("1.7.6");
});

for (const sample of cases) {
  test(`github ${sample.name}`, async () => {
    const profile = { ...baseProfile, ...(sample.rawEmail === undefined ? {} : { email: sample.rawEmail }) };
    const expectedData = { ...baseProfile, ...(sample.email === undefined ? {} : { email: sample.email }) };
    const expectedPresence = { ownEmail: sample.ownEmail, emailIsUndefined: sample.email === undefined };
    const events: string[] = [];
    let mapperPresence: ReturnType<typeof presence> | undefined;
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(request) {
        expect(request.method).toBe("GET");
        expect(request.headers.get("authorization")).toBe("Bearer ordinary-github-token");
        expect(request.headers.get("user-agent")).toBe("better-auth");
        const path = new URL(request.url).pathname;
        expect(["/user", "/user/emails"]).toContain(path);
        events.push(path === "/user" ? "profile" : "emails");
        return path === "/user" ? Response.json(profile) : Response.json(sample.emails, { status: sample.status });
      },
    });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = Object.assign((input: Parameters<typeof fetch>[0], init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url !== "https://api.github.com/user" && url !== "https://api.github.com/user/emails") {
        throw new Error(`Unexpected GitHub fixture URL: ${url}`);
      }
      return originalFetch(new URL(new URL(url).pathname, server.url), init);
    }, originalFetch);
    try {
      const auth = betterAuth({
        secret: "github-email-presence-contract-secret-at-least-32-characters",
        baseURL: "http://github-email-presence.example.test",
        logger: { disabled: true },
        telemetry: { enabled: false },
        socialProviders: {
          github: {
            clientId: "ordinary-client",
            clientSecret: "ordinary-client-secret",
            mapProfileToUser: async (raw) => {
              events.push("mapper");
              mapperPresence = presence(raw);
              expect(mapperPresence).toEqual(expectedPresence);
              expect(normalized(raw)).toEqual(expectedData);
              return {};
            },
          },
        },
      });
      const provider = (await auth.$context).socialProviders.find((value) => value.id === "github")!;
      const result = await provider.getUserInfo({ accessToken: "ordinary-github-token" });
      expect(result).not.toBeNull();
      expect(normalized(result)).toEqual({
        user: {
          name: baseProfile.name,
          ...(sample.email === undefined ? {} : { email: sample.email }),
          image: baseProfile.avatar_url,
          emailVerified: sample.verified,
        },
        data: expectedData,
      });
      expect(presence(result!.data)).toEqual(expectedPresence);
      expect(presence(result!.user)).toEqual({ ownEmail: true, emailIsUndefined: sample.email === undefined });
      expect(events).toEqual(["profile", "emails", "mapper"]);
      console.log(JSON.stringify({ case: sample.name, mapper: mapperPresence, data: presence(result!.data), user: presence(result!.user) }));
    } finally {
      globalThis.fetch = originalFetch;
      await server.stop(true);
    }
  });
}
