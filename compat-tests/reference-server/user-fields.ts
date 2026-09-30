export const userFields = {
  department: { type: "string", required: true },
  cohort: { type: "string", required: false, defaultValue: () => "factory" },
  changedMarker: { type: "string", required: false, defaultValue: "created", onUpdate: () => "updated" },
  enabled: { type: "boolean", required: false, defaultValue: true },
  tags: { type: "string[]", required: false, defaultValue: ["starter"] },
  ratings: { type: "number[]", required: false, defaultValue: [1, 2] },
  preferences: { type: "json", required: false, defaultValue: { theme: "system" } },
  joinedAt: { type: "date", required: false, defaultValue: () => new Date("2020-01-02T03:04:05.000Z") },
  level: { type: ["basic", "pro"], required: false, defaultValue: "basic" },
  label: { type: "string", required: false, fieldName: "storedLabel", defaultValue: "public-label" },
  alias: {
    type: "string", required: false, defaultValue: "guest",
    transform: { input: (value: unknown) => `${value}:in`, output: (value: unknown) => `${value}:out` },
  },
  optionalAlias: {
    type: "string", required: false,
    transform: { input: (value: unknown) => `${value}:in`, output: (value: unknown) => `${value}:out` },
  },
  internalCode: { type: "string", required: false, input: false, defaultValue: "server" },
  secretNote: { type: "string", required: false, returned: false, defaultValue: "hidden" },
  score: {
    type: "number", required: false, defaultValue: 1,
    validator: { input: { "~standard": { version: 1, vendor: "compat", validate: (value: unknown) =>
      typeof value === "number" && value >= 0 ? { value } : { issues: [{ message: "score must be nonnegative" }] },
    } } },
  },
} as const;
