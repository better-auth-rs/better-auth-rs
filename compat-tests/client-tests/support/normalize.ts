import diff from "microdiff";

// Only server-generated identities and session secrets vary by implementation.
const GENERATED_FIELDS = new Set([
  "id", "userId", "sessionId", "organizationId", "activeOrganizationId",
  "teamId", "activeTeamId", "roleId", "memberId", "invitationId", "inviterId", "keyId", "referenceId", "impersonatedBy", "token",
]);
const CLOCK_FIELDS = new Set([
  "createdAt", "updatedAt", "expiresAt", "accessTokenExpiresAt", "refreshTokenExpiresAt",
  "lastUsedAt", "lastRequest", "lastRefillAt", "banExpires",
]);
// The two servers run each scenario sequentially against real clocks.
const CLOCK_TOLERANCE_MS = 10_000;

export function clientDiffs(left: unknown, right: unknown) {
  return diff(
    { value: normalizeClientValue(left) },
    { value: normalizeClientValue(right) },
    { cyclesFix: false },
  ).filter((entry) => {
    if (entry.path.some((part) => part === "metadata" || part === "permissions")) return true;
    const field = entry.path.at(-1);
    if (entry.type !== "CHANGE" || typeof field !== "string" || !CLOCK_FIELDS.has(field)) return true;
    if (typeof entry.value !== "string" || typeof entry.oldValue !== "string") return true;
    const delta = Math.abs(Date.parse(entry.value) - Date.parse(entry.oldValue));
    return !Number.isFinite(delta) || delta > CLOCK_TOLERANCE_MS;
  });
}

export function normalizeUrl(value: string, baseURL?: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return value;
  }
  for (const key of ["token", "state", "code_challenge"]) {
    if (url.searchParams.has(key)) url.searchParams.set(key, `<${key}>`);
  }
  if (url.searchParams.get("nonce")) url.searchParams.set("nonce", "<nonce>");
  for (const key of ["redirect_uri", "post_logout_redirect_uri", "callbackURL", "errorCallbackURL", "newUserCallbackURL"]) {
    const nested = url.searchParams.get(key);
    if (nested) url.searchParams.set(key, normalizeUrl(nested, baseURL));
  }
  return url.origin === baseURL
    ? `<server>${url.pathname}${url.search}${url.hash}`
    : url.toString();
}

function normalizeScalar(value: string, key: string, baseURL: string | undefined, generated: Map<string, string>) {
  if (value.length > 0 && GENERATED_FIELDS.has(key)) {
    const namespace = key === "token" ? "token" : "identity";
    const source = `${namespace}:${value}`;
    let alias = generated.get(source);
    if (alias === undefined) {
      alias = `<${namespace}:${generated.size + 1}>`;
      generated.set(source, alias);
    }
    return alias;
  }
  if (key === "location" || key === "url" || key === "verification_uri" || key === "verification_uri_complete" || key.endsWith("URL") || key.endsWith("Url")) {
    return normalizeUrl(value, baseURL);
  }
  if (CLOCK_FIELDS.has(key) && Number.isFinite(Date.parse(value))) return new Date(value).toISOString();
  return value;
}

export function normalizeClientValue(value: unknown, key = "", baseURL?: string, generated = new Map<string, string>()): unknown {
  if (key === "metadata" || key === "permissions" || key === "rp") return value;
  if (value === null || value === undefined) {
    return value;
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (typeof value === "string") {
    return normalizeScalar(value, key, baseURL, generated);
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return value;
  }

  if (Array.isArray(value)) {
    const itemKey = key === "teamIds" ? "teamId" : "";
    return value.map((item) => normalizeClientValue(item, itemKey, baseURL, generated));
  }

  if (typeof value === "object") {
    const object = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(object)
        .sort()
        .map((childKey) => {
          // Credential accounts use the generated user ID; OAuth accounts use a provider ID.
          const field = childKey === "accountId" && object.providerId === "credential" ? "userId" : childKey;
          return [childKey, normalizeClientValue(object[childKey], field, baseURL, generated)];
        }),
    );
  }

  return String(value);
}

export function normalizeDeviceCookieName(name: string, generated: Map<string, string>): string {
  const match = /^((?:__Secure-)?better-auth\.session_token_multi-)([a-z0-9_-]+)$/.exec(name);
  return match ? `${match[1]}${normalizeScalar(match[2]!, "token", undefined, generated)}` : name;
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
