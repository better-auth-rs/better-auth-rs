export function createCookieVersionFixture(profile: string) {
  let version = "1";
  let fail = false;
  let events: unknown[] = [];
  const enabled = profile.startsWith("cookie-version-");
  return {
    options: enabled ? {
      session: {
        cookieCache: {
          enabled: true,
          strategy: profile.endsWith("jwe") ? "jwe" as const : profile.endsWith("jwt") ? "jwt" as const : "compact" as const,
          async version(session: any, user: any) {
            events.push({ sessionId: session.id, userId: user.id, name: user.name, hiddenSession: session.internalNote ?? null, hiddenUser: user.secretNote ?? null });
            if (fail) throw new Error("Cookie version failed");
            return version;
          },
        },
        additionalFields: { internalNote: { type: "string" as const, required: false, returned: false, defaultValue: "session-secret" } },
      },
    } : {},
    userFields: enabled ? { secretNote: { type: "string" as const, required: false, returned: false, defaultValue: "user-secret" } } : undefined,
    reset() { version = "1"; fail = false; events = []; },
    async route(request: Request) {
      if (new URL(request.url).pathname !== "/__test/cookie-version") return;
      if (request.method === "POST") {
        const body = await request.json();
        if (body.version !== undefined) version = body.version;
        if (body.fail !== undefined) fail = body.fail;
        if (body.clear) events = [];
      }
      return Response.json({ events });
    },
  };
}
