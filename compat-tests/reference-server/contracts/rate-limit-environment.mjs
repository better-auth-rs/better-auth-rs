import { betterAuth } from "better-auth";

const configured = process.argv[2];
const auth = betterAuth({
  secret: "rate-environment-reference-secret-more-than-32-characters",
  baseURL: "http://rate-environment.test",
  logger: { disabled: true },
  rateLimit: { window: 0, max: NaN, ...(configured === "omitted" ? {} : { enabled: configured === "true" }) },
});
const { rateLimit } = await auth.$context;
console.log(JSON.stringify({ enabled: rateLimit.enabled, window: rateLimit.window, max: rateLimit.max }));
