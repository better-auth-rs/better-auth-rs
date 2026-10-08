import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import cases from "../../../tests/fixtures/user-runtime-output-cases.json";

export { cases };
export const owner = "runtime-owner";
export const email = "owner@runtime.test";
export const date = "2030-01-02T03:04:05.000Z";
export const secret = "user-runtime-output-secret-at-least-thirty-two-characters";

export function revive(value: any): any {
  if (value?.type === "undefined") return undefined;
  if (value?.type === "date") return new Date(value.value);
  if (value?.type === "number") return Number(value.value);
  if (Array.isArray(value)) return value.map(revive);
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([name, field]) => [name, revive(field)]));
  return value;
}

export function observe(value: any): any {
  if (value === undefined) return { type: "undefined" };
  if (value instanceof Date) return { type: "date", value: Number.isNaN(value.getTime()) ? "Invalid Date" : value.toISOString() };
  if (typeof value === "number" && !Number.isFinite(value)) return { type: "number", value: String(value) };
  if (Array.isArray(value)) return value.map(observe);
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([name, field]) => [name, observe(field)]));
  return value;
}

export function user() {
  return {
    id: owner, name: "Owner", email, emailVerified: false, image: "image",
    createdAt: new Date(date), updatedAt: new Date(date), isAnonymous: false,
    phoneNumber: "+12025550123", phoneNumberVerified: false, username: "owner",
    displayUsername: "Owner", twoFactorEnabled: false, role: "user", banned: false,
    banReason: "reason", banExpires: new Date(date), metadata: { seed: true },
  };
}

export function options(memory: Record<string, any[]>, fields: Record<string, Record<string, unknown>> = {}) {
  return {
    baseURL: "http://localhost:3000", secret,
    database: memoryAdapter(memory), logger: { disabled: true }, telemetry: { enabled: false },
    user: { additionalFields: Object.fromEntries(cases.fields.map(field => [field.name, {
      type: field.type, required: false, ...fields[field.name],
    }])) },
  };
}

export function build(memory: Record<string, any[]>, fields: Record<string, Record<string, unknown>> = {}) {
  return betterAuth(options(memory, fields));
}
