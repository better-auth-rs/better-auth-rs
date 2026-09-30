import { APIError } from "better-auth/api";

export function signupEnumerationOptions(profile: string) {
  if (!profile.startsWith("signup-")) return undefined;
  return {
    userFields: {
      alias: { type: "string" as const, required: false, defaultValue: "guest", transform: { input: (value: unknown) => `${value}:in`, output: (value: unknown) => `${value}:out` } },
      optionalAlias: { type: "string" as const, required: false },
      secretNote: { type: "string" as const, required: false, returned: false, defaultValue: "hidden" },
    },
    emailAndPassword: {
      autoSignIn: profile === "signup-verification",
      requireEmailVerification: profile === "signup-verification",
      async onExistingUserSignUp({ user }: { user: { name: string } }, request?: Request) {
        if (!request) throw new Error("Missing signup request");
        const expected = request.headers.get("x-expected-user-name");
        if (expected && user.name !== expected) throw new Error("Duplicate callback received the submitted user");
        if (request.headers.has("x-duplicate-error")) throw new APIError("BAD_REQUEST", { code: "DUPLICATE_CALLBACK_BLOCKED", message: "Duplicate callback blocked" });
      },
      ...(profile === "signup-synthetic" ? { customSyntheticUser({ coreFields, additionalFields, id }: { coreFields: Record<string, unknown>; additionalFields: Record<string, unknown>; id: string }) {
        return { ...coreFields, id, name: `synthetic:${coreFields.name}`, alias: `custom:${additionalFields.alias}`, secretNote: "not-public", unknown: "not-in-schema" };
      } } : {}),
    },
  };
}
