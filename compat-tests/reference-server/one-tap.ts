import { oneTap } from "better-auth/plugins";

export function createOneTapFixture(profile: string) {
  let jwks = { keys: [] as unknown[] };
  return {
    plugin: oneTap(profile === "one-tap-options" ? { clientId: ["one-tap-client", "one-tap-alternative"], disableSignup: true } : undefined),
    reset() { jwks = { keys: [] }; },
    async handle(request: Request): Promise<Response | null> {
      const url = new URL(request.url);
      if (url.href === "https://www.googleapis.com/oauth2/v3/certs") return Response.json(jwks);
      if (url.pathname !== "/__test/one-tap-jwks") return null;
      if (request.method === "POST") { jwks = await request.json(); return Response.json({ success: true }); }
      return Response.json(jwks);
    },
  };
}
