import { APIError } from "better-auth/api";
import { customSession, multiSession } from "better-auth/plugins";

export function createCustomSessionFixture(profile: string) {
  const enabled = profile.startsWith("custom-session");
  let events: unknown[] = [];
  let failRead = false;
  let arrivals: (() => void)[] = [];
  return {
    options: enabled ? { session: {
      deferSessionRefresh: profile === "custom-session-deferred",
      cookieCache: { enabled: true, async version() { if (failRead) throw new Error("Session read failed"); return "1"; } },
    } } : {},
    plugins: enabled ? [multiSession(), customSession(async (data: any, ctx: any) => {
      const mode = ctx.headers.get("x-custom-mode");
      const exists = Boolean(await ctx.context.internalAdapter.findUserById(data.user.id));
      ctx.setHeader("x-customized", "true");
      events.push({ path: ctx.path, name: data.user.name, exists, tag: ctx.headers.get("x-app-tag"), needsRefresh: data.needsRefresh ?? null });
      if (mode === "partial-reject") {
        if (data.user.name === "First") throw APIError.from("FORBIDDEN", { code: "CUSTOM_SESSION_REJECTED", message: "Custom session rejected" });
        await new Promise(resolve => setTimeout(resolve, 20));
        events.push({ completed: data.user.name });
      }
      if (mode === "reject") throw APIError.from("FORBIDDEN", { code: "CUSTOM_SESSION_REJECTED", message: "Custom session rejected" });
      if (mode === "null") return null;
      if (mode === "barrier") await new Promise<void>(resolve => {
        arrivals.push(resolve);
        if (arrivals.length === 2) { const ready = arrivals; arrivals = []; for (const release of ready) release(); }
      });
      return { ...data, marker: "custom-session" };
    }, undefined, { shouldMutateListDeviceSessionsEndpoint: profile === "custom-session-list" })] : [],
    reset() { events = []; failRead = false; arrivals = []; },
    async route(request: Request) {
      if (new URL(request.url).pathname !== "/__test/custom-session") return;
      if (request.method === "POST") {
        const body = await request.json();
        if (body.failRead !== undefined) failRead = body.failRead;
        if (body.clear) events = [];
      }
      return Response.json({ events });
    },
  };
}
