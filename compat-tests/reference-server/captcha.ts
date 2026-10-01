import { captcha } from "better-auth/plugins";
import { createAuthMiddleware } from "better-auth/api";

export function createCaptchaFixture(profile: string, baseURL: string) {
  const enabled = profile.startsWith("captcha-");
  let mode: any = {};
  const events: any[] = [];
  const checked = async () => {
    events.push({ phase: "check" });
    if (mode.delay) await Bun.sleep(mode.delay);
    if (mode.throw) throw new Error("fixture BotID failure");
    events.push({ phase: "checked" });
    return mode.verification ?? { isBot: false };
  };
  const provider = profile === "captcha-recaptcha" ? "google-recaptcha" :
    profile === "captcha-hcaptcha" ? "hcaptcha" : profile === "captcha-captchafox" ? "captchafox" :
    profile.startsWith("captcha-botid") ? "vercel-botid" : "cloudflare-turnstile";
  const options: any = {
    provider, secretKey: profile === "captcha-empty-secret" ? "" : "fixture-secret",
    siteVerifyURLOverride: `${baseURL}/__test/captcha/siteverify`,
    ...(provider === "cloudflare-turnstile" || provider === "google-recaptcha" ? { expectedAction: "login", allowedHostnames: ["auth.example.test"] } : {}),
    ...(provider === "hcaptcha" || provider === "captchafox" ? { siteKey: "fixture-site" } : {}),
    ...(profile === "captcha-paths" ? { endpoints: ["/sign-in/*", "/protected/**", "/literal?", "/sign-up/email"] } : {}),
    ...(provider === "vercel-botid" ? { checkBotId: checked } : {}),
    ...(profile === "captcha-botid" ? { validateRequest: async ({ request, verification }: any) => {
      events.push({ phase: "validate", path: new URL(request.url).pathname, header: request.headers.get("x-bot-allow"), verification });
      if (mode.validatorThrow) throw new Error("fixture validator failure");
      if (mode.validatorDelay) await Bun.sleep(mode.validatorDelay);
      return !verification.isBot || (verification.isVerifiedBot && request.headers.get("x-bot-allow") === "yes");
    } } : {}),
  };
  const ipAddress = profile === "captcha-turnstile" ? { ipAddressHeaders: ["x-client-ip", "x-forwarded-for"], trustedProxies: ["10.0.0.0/8"], ipv6Subnet: 60.9 } :
    profile === "captcha-hcaptcha" ? { disableIpTracking: true } : profile === "captcha-captchafox" ? { ipv6Subnet: 128 } : {};
  return {
    enabled,
    options: enabled ? {
      advanced: { ipAddress },
      ...(["captcha-rate-limit", "captcha-hcaptcha"].includes(profile) ? { rateLimit: { enabled: true, window: 60, max: 1, customRules: { "/sign-in/email": { window: 60, max: 1 } } } } : {}),
    } : {},
    plugins: enabled ? [captcha(options), {
      id: "captcha-observer",
      hooks: {
        before: [{ matcher: (ctx: any) => !!ctx.request && ["/sign-up/email", "/sign-in/email", "/request-password-reset"].includes(ctx.path), handler: createAuthMiddleware(async () => { events.push({ phase: "before" }); }) }],
        after: [{ matcher: (ctx: any) => !!ctx.request && ["/sign-up/email", "/sign-in/email", "/request-password-reset"].includes(ctx.path), handler: createAuthMiddleware(async () => { events.push({ phase: "after" }); }) }],
      },
    }] : [],
    reset() { mode = {}; events.length = 0; },
    async handle(request: Request, auth: any): Promise<Response | null> {
      const path = new URL(request.url).pathname;
      if (!enabled || !path.startsWith("/__test/captcha/")) return null;
      if (path === "/__test/captcha/control") {
        const body = await request.json();
        if (body.clear) events.length = 0;
        if (body.mode) mode = body.mode;
        return Response.json(events);
      }
      if (path === "/__test/captcha/native") {
        const response = await auth.api.signUpEmail({ body: await request.json(), asResponse: true });
        return Response.json({ status: response.status, body: await response.json() });
      }
      if (path === "/__test/captcha/siteverify") {
        const type = request.headers.get("content-type") ?? "";
        const body = type.includes("application/json") ? await request.json() : Object.fromEntries(new URLSearchParams(await request.text()));
        events.push({ phase: "provider", type, body });
        const current = { ...mode };
        if (current.delay) await Bun.sleep(current.delay);
        if (current.text !== undefined) return new Response(current.text, { status: current.status ?? 200, headers: { "content-type": "text/plain" } });
        return Response.json(Object.hasOwn(current, "data") ? current.data : { success: true, action: "login", hostname: "auth.example.test", score: 0.8 }, { status: current.status ?? 200 });
      }
      return null;
    },
  };
}
