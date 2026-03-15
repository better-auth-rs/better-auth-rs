function normalizeScalar(value: string, key: string) {
  if (
    key === "id" ||
    key.endsWith("Id") ||
    key.toLowerCase().includes("token") ||
    key.endsWith("At") ||
    key.endsWith("URL") ||
    key.endsWith("Url")
  ) {
    return `<${key}>`;
  }

  if (!Number.isNaN(Date.parse(value)) && key.endsWith("At")) {
    return "<date>";
  }

  return value;
}

export function normalizeClientValue(value: unknown, key = ""): unknown {
  if (value === null || value === undefined) {
    return value;
  }

  if (value instanceof Date) {
    return "<date>";
  }

  if (typeof value === "string") {
    return normalizeScalar(value, key);
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => normalizeClientValue(item));
  }

  if (typeof value === "object") {
    const object = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(object)
        .sort()
        .filter(
          (childKey) =>
            childKey !== "cause" && childKey !== "refreshTokenExpiresAt",
        )
        .map((childKey) => [childKey, normalizeClientValue(object[childKey], childKey)]),
    );
  }

  return String(value);
}

export function jsonShape(value: unknown): unknown {
  if (value === null || value === undefined) {
    return null;
  }

  if (Array.isArray(value)) {
    return value.length === 0 ? [] : [jsonShape(value[0])];
  }

  if (value instanceof Date) {
    return "string";
  }

  switch (typeof value) {
    case "string":
      return "string";
    case "number":
      return "number";
    case "boolean":
      return "boolean";
    case "object":
      return Object.fromEntries(
        Object.entries(value as Record<string, unknown>)
          .sort(([left], [right]) => left.localeCompare(right))
          .map(([key, child]) => [key, jsonShape(child)]),
      );
    default:
      return typeof value;
  }
}
