import { haveIBeenPwned, isPasswordCompromised } from "better-auth/plugins/haveibeenpwned";
import { hashPassword, verifyPassword } from "better-auth/crypto";

export function createPasswordSecurityFixture() {
  let body = "";
  let status = 200;
  let drop = false;
  let requests: unknown[] = [];
  let hashes: string[] = [];
  let stopped = false;
  const serve = () => Bun.serve({
    hostname: "127.0.0.1", port: 0,
    fetch(request, server) {
      requests.push({ prefix: new URL(request.url).pathname.slice("/range/".length), padding: request.headers.get("add-padding"), agent: request.headers.get("user-agent") });
      if (drop) {
        stopped = true;
        server.stop(true);
      }
      return new Response(body, { status, headers: { "content-type": "text/plain" } });
    },
  });
  let range = serve();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url.startsWith("https://api.pwnedpasswords.com/range/")) {
      const original = new Request(input, init);
      return originalFetch(new Request(`${range.url.origin}/range/${url.split("/").at(-1)}`, original));
    }
    return originalFetch(input, init);
  }) as typeof fetch;

  const reset = () => {
    body = ""; status = 200; drop = false; requests = []; hashes = [];
    if (stopped) { range = serve(); stopped = false; }
  };
  return {
    reset,
    plugin(profile: string) {
      return haveIBeenPwned({
        enabled: profile !== "password-security-disabled",
        ...(profile === "password-security-empty" ? { paths: [] } : {}),
        ...(profile === "password-security-custom" ? { paths: ["/change-password", "/sign-in/email"], customPasswordCompromisedMessage: "Choose another password" } : {}),
      });
    },
    emailAndPassword(profile: string) {
      if (!profile.startsWith("password-security")) return {};
      return { password: {
        hash: async (password: string) => { hashes.push(password); return hashPassword(password); },
        verify: verifyPassword,
      } };
    },
    async handle(request: Request, auth: any): Promise<Response | null> {
      if (new URL(request.url).pathname !== "/__test/password-security") return null;
      const input = await request.json() as Record<string, any>;
      try {
        switch (input.action ?? "state") {
          case "configure":
            reset(); body = input.body ?? ""; status = input.status ?? 200; drop = input.drop ?? false;
            return Response.json({ ok: true });
          case "state": return Response.json({ requests, hashes });
          case "check": return Response.json({ compromised: await isPasswordCompromised(input.password) });
          case "hash": return Response.json({ hash: await hashPassword(input.password) });
          case "verify": return Response.json({ valid: await verifyPassword({ hash: input.hash, password: input.password }) });
        }
        const context = await auth.$context;
        const user = await context.internalAdapter.findUserByEmail(input.email);
        if (!user) return Response.json({ user: false, hash: null });
        const account = await context.internalAdapter.findCredentialAccount(user.user.id);
        if (input.action === "write") {
          if (!account) return Response.json({ message: "Credential missing" }, { status: 404 });
          await context.internalAdapter.updateAccount(account.id, { password: input.hash });
          return Response.json({ ok: true });
        }
        return Response.json({ user: true, hash: account?.password ?? null });
      } catch (error: any) {
        return Response.json(error.body ?? { message: error.message }, { status: error.statusCode ?? 500 });
      }
    },
  };
}
