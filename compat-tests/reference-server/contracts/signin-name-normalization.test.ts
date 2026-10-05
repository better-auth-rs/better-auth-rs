import { beforeAll, expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { genericOAuth } from "better-auth/plugins/generic-oauth";

beforeAll(async () => {
  const metadata = await Bun.file(new URL("../node_modules/better-auth/package.json", import.meta.url)).json();
  expect(metadata.version).toBe("1.7.6");
});

const baseURL = "http://signin-name.example.test";
const cookie = (headers: Headers) => headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ");
const cases = [
  { label: "omitted", patch: {}, expected: "" },
  { label: "null", patch: { name: null }, expected: "" },
  { label: "empty", patch: { name: "" }, expected: "" },
  { label: "ordinary", patch: { name: "Profile Reader" }, expected: "Profile Reader" },
];

for (const overrideUserInfo of [false, true]) {
  for (const sample of cases) {
    test(`${sample.label} callback name is normalized with overrideUserInfo=${overrideUserInfo}`, async () => {
      const profile = { id: "ordinary-name-subject", email: "name@example.test", emailVerified: true, ...sample.patch };
      const original = structuredClone(profile);
      const records: unknown[] = [];
      const database: Record<string, Record<string, unknown>[]> = { user: [], account: [], session: [], verification: [] };
      const auth = betterAuth({
        secret: "signin-name-contract-secret-at-least-32-characters",
        baseURL,
        database: memoryAdapter(database),
        logger: { disabled: true },
        telemetry: { enabled: false },
        user: { validateUserInfo: async ({ user, source }) => {
          records.push({ name: user.name, source: structuredClone(source) });
        } },
        plugins: [genericOAuth({ config: [{
          providerId: "generic",
          clientId: "client",
          authorizationUrl: "https://provider.example/authorize",
          getToken: async () => ({}),
          getUserInfo: async () => profile,
          overrideUserInfo,
        }] })],
      });
      const signin = async () => {
        const start = await auth.api.signInSocial({
          body: { provider: "generic", callbackURL: `${baseURL}/welcome`, disableRedirect: true },
          returnHeaders: true,
        });
        const state = new URL(start.response.url!).searchParams.get("state");
        expect(state).toBeTruthy();
        const response = await auth.handler(new Request(
          `${baseURL}/api/auth/callback/generic?${new URLSearchParams({ code: "ordinary-code", state: state! })}`,
          { headers: { cookie: cookie(start.headers) } },
        ));
        expect(response.status).toBe(302);
        expect(response.headers.get("location")).toBe(`${baseURL}/welcome`);
      };
      const context = await auth.$context;
      const provider = context.socialProviders.find(value => value.id === "generic");
      if (!provider) throw new Error("Missing Generic provider");
      const before = await provider.getUserInfo({});
      expect(before?.data).toStrictEqual(original);
      expect(JSON.parse(JSON.stringify(before?.user)).name).toBe(original.name);

      await signin();
      expect(database.user).toHaveLength(1);
      const registered = database.user[0]!;
      expect(registered.name).toBe(sample.expected);
      const id = String(registered.id);
      await context.internalAdapter.updateUser(id, { name: "Previously stored" });
      await signin();
      expect(database.user).toHaveLength(1);
      expect(database.user[0]!.id).toBe(id);
      expect(database.user[0]!.name).toBe(overrideUserInfo ? sample.expected : "Previously stored");
      expect(records).toStrictEqual(["create-user", "sign-in"].map(action => ({
        name: sample.expected,
        source: { action, method: "oauth", oauth: { providerId: "generic", profile: original } },
      })));
      const after = await provider.getUserInfo({});
      expect(after?.data).toStrictEqual(original);
      expect(JSON.parse(JSON.stringify(after?.user)).name).toBe(original.name);
      expect(profile).toStrictEqual(original);
    });
  }
}
