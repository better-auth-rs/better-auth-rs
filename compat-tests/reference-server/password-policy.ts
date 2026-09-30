export function passwordPolicyOptions(profile: string) {
  if (profile !== "password-policy") return {};
  return {
    minPasswordLength: 12,
    maxPasswordLength: 24,
    password: {
      hash: async (password: string) => `fixture:${password}`,
      verify: async ({ hash, password }: { hash: string; password: string }) => hash === `fixture:${password}`,
    },
  };
}
