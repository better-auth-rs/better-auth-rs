import { parseSetCookie } from "set-cookie-parser";
import { jsonShape } from "./normalize";

export type TraceEntry = {
  actor: string;
  method: string;
  path: string;
  requestBodyShape: unknown;
  responseStatus: number;
  responseHeaders: Record<string, string>;
  responseCookies: Record<string, unknown>;
  responseBodyShape: unknown;
};

function normalizeTracePath(url: URL) {
  const normalized = new URL(url.toString());
  for (const [key] of normalized.searchParams.entries()) {
    if (
      key === "token" ||
      key === "state" ||
      key === "user_code" ||
      key === "id" ||
      key.endsWith("Id")
    ) {
      normalized.searchParams.set(key, `<${key}>`);
    }
  }

  const query = normalized.searchParams.toString();
  return `${normalized.pathname}${query ? `?${query}` : ""}`;
}

type CookieJar = Map<string, string>;

function normalizeRequestBody(body: BodyInit | null | undefined) {
  if (!body) {
    return null;
  }

  if (typeof body === "string") {
    try {
      return jsonShape(JSON.parse(body));
    } catch {
      return "string";
    }
  }

  if (body instanceof URLSearchParams) {
    return jsonShape(Object.fromEntries(body.entries()));
  }

  return typeof body;
}

async function normalizeResponseBody(response: Response) {
  const clone = response.clone();
  const contentType = clone.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    try {
      return jsonShape(await clone.json());
    } catch {
      return "non-json";
    }
  }

  const text = await clone.text();
  if (!text) {
    return null;
  }

  try {
    return jsonShape(JSON.parse(text));
  } catch {
    return "string";
  }
}

function pickHeaders(headers: Headers) {
  const selected = ["content-type", "location"];
  return Object.fromEntries(
    selected.flatMap((header) => {
      const value = headers.get(header);
      if (!value) {
        return [];
      }

      const normalized = header === "location"
        ? (() => {
            try {
              const url = new URL(value, "http://compat.local");
              for (const key of ["token", "state", "code_challenge"]) {
                if (url.searchParams.has(key)) {
                  url.searchParams.set(key, `<${key}>`);
                }
              }
              for (const key of ["redirect_uri", "callbackURL", "errorCallbackURL", "newUserCallbackURL"]) {
                const nested = url.searchParams.get(key);
                if (!nested) {
                  continue;
                }
                try {
                  const nestedUrl = new URL(nested);
                  url.searchParams.set(key, `${nestedUrl.pathname}${nestedUrl.search}${nestedUrl.hash}`);
                } catch {
                  // leave relative or invalid values as-is
                }
              }
              return `${url.pathname}${url.search}${url.hash}`;
            } catch {
              return value;
            }
          })()
        : value.split(";")[0]!.trim();

      return [[header, normalized]];
    }),
  );
}

function normalizeCookies(response: Response) {
  const cookies = parseSetCookie(response, { map: true, silent: true }) as Record<
    string,
    Record<string, unknown>
  >;

  return Object.fromEntries(
    Object.entries(cookies).map(([name, cookie]) => [
      name,
      {
        path: cookie.path ?? null,
        httpOnly: cookie.httpOnly === true,
        secure: cookie.secure === true,
        sameSite: cookie.sameSite ?? null,
        maxAge: cookie.maxAge ?? null,
      },
    ]),
  );
}

function getSetCookieValues(response: Response) {
  if (typeof response.headers.getSetCookie === "function") {
    return response.headers.getSetCookie();
  }

  const single = response.headers.get("set-cookie");
  return single ? [single] : [];
}

function applyCookiesToJar(jar: CookieJar, response: Response) {
  for (const cookie of parseSetCookie(response, {
    silent: true,
  }) as Array<Record<string, unknown>>) {
    if (typeof cookie.name === "string" && typeof cookie.value === "string") {
      jar.set(cookie.name, `${cookie.name}=${cookie.value}`);
    }
  }
}

function buildCookieHeader(jar: CookieJar) {
  return [...jar.values()].join("; ");
}

export function createTracingFetch(
  baseURL: string,
  actor: string,
  traces: TraceEntry[],
) {
  const jar: CookieJar = new Map();

  return async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url, baseURL);
    const headers = new Headers(init?.headers || (input instanceof Request ? input.headers : undefined));

    if (jar.size > 0 && !headers.has("cookie")) {
      headers.set("cookie", buildCookieHeader(jar));
    }
    if (!headers.has("origin")) {
      headers.set("origin", baseURL);
    }

    const method = init?.method || (input instanceof Request ? input.method : "GET");
    const response = await fetch(url, {
      ...init,
      method,
      headers,
    });

    applyCookiesToJar(jar, response);

    traces.push({
      actor,
      method,
      path: normalizeTracePath(url),
      requestBodyShape: normalizeRequestBody(init?.body),
      responseStatus: response.status,
      responseHeaders: pickHeaders(response.headers),
      responseCookies: normalizeCookies(response),
      responseBodyShape: await normalizeResponseBody(response),
    });

    return response;
  };
}
