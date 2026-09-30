import { z } from "zod";

const suffix = (value: unknown, suffix: string) => value == null ? value : `${value}${suffix}`;
export function sessionFieldOptions(profile: string, session: object | undefined) {
  if (!profile.startsWith("session-fields")) return {};
  return { session: { ...session, additionalFields: {
    deviceLabel: { type: "string" as const, required: false, defaultValue: () => "factory", onUpdate: () => "tick", transform: {
      input: (value: unknown) => suffix(value, ":input"), output: (value: unknown) => suffix(value, ":output"),
    } },
    validatedLabel: { type: "string" as const, required: false, validator: { input: z.string().min(2, "label too short").transform(value => `${value}:validated`) }, transform: {
      input: (value: unknown) => suffix(value, ":input"), output: (value: unknown) => suffix(value, ":output"),
    } },
    internalNote: { type: "string" as const, required: false, input: false, returned: false, defaultValue: "hidden" },
    settings: { type: "json" as const, required: false, defaultValue: { stage: "created" }, transform: {
      output: (value: unknown) => {
        if (value == null) return value;
        if (typeof value !== "string") throw new Error("SQLite JSON output must receive text");
        const parsed = JSON.parse(value);
        return JSON.stringify({ ...parsed, output: true });
      },
    } },
  } } };
}
