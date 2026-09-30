import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

export type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];
export async function control(ctx: Context, data: unknown) {
  const response = await fetch(`${ctx.baseURL}/__test/email-otp`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(data) });
  expect(response.status).toBe(200);
  return response.json();
}
export function post(ctx: Context, path: string, json: unknown, actor = "primary") {
  return ctx.rawRequest({ path: `/api/auth${path}`, method: "POST", json, actor });
}
export async function send(ctx: Context, email: string, type: string) {
  const response = await post(ctx, "/email-otp/send-verification-otp", { email, type });
  expect(response.status).toBe(200);
  expect(response.body).toEqual({ success: true });
  const messages = await control(ctx, { email: email.toLowerCase() });
  const message = messages.at(-1);
  expect(message).toMatchObject({ email: email.toLowerCase(), type });
  expect(message.otp).toMatch(/^\d{6}$/);
  return message.otp as string;
}
export async function signup(ctx: Context, email: string, actor = "primary") {
  const result = await ctx.actor(actor).client.signUp.email({ email, password: "Password123!", name: "OTP Owner" });
  expect(result.error).toBeNull();
  return result.data!;
}
export function error(response: Awaited<ReturnType<typeof post>>, status: number, code: string) {
  expect(response.status).toBe(status);
  expect(response.body).toMatchObject({ code });
}
