#!/usr/bin/env bun

// Both auth servers use this issuer so the tests exercise the same signed tokens and JWKS.
const encoder = new TextEncoder();
const server = Bun.serve({
  hostname: "127.0.0.1",
  port: Number(process.env.PORT),
  fetch: () => new Response("Initializing", { status: 503 }),
});
const baseURL = `http://127.0.0.1:${server.port}`;
console.log(`COMPAT_SERVER_PORT=${server.port}`);
const keys = await Promise.all(
  ["primary", "rotated", "forged"].map(async (kid) => {
    const pair = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    );
    return {
      kid,
      pair,
      jwk: {
        ...(await crypto.subtle.exportKey("jwk", pair.publicKey)),
        kid,
        alg: "RS256",
        use: "sig",
      },
    };
  }),
);

type Settings = {
  mode: string;
  sub: string;
  email: string;
  signingKey: "primary" | "rotated";
  publishedKeys: string[];
};
const defaults = (): Settings => ({
  mode: "valid",
  sub: "oidc-subject",
  email: "oidc@example.com",
  signingKey: "primary",
  publishedKeys: ["primary"],
});
let settings = defaults();
let issuedIdToken: string | undefined;
let grant:
  | { nonce: string | null; redirectURI: string; challenge: string | null }
  | undefined;
let requests = { discovery: 0, jwks: 0, token: 0, userinfo: 0 };

function base64url(value: string | ArrayBuffer) {
  return Buffer.from(
    typeof value === "string" ? encoder.encode(value) : value,
  ).toString("base64url");
}

async function idToken(nonce: string | null) {
  const mode = settings.mode;
  const now = Math.floor(Date.now() / 1000);
  const claims: Record<string, unknown> = {
    iss: mode === "wrong-issuer" ? `${baseURL}/other` : baseURL,
    aud: mode === "wrong-audience" ? "another-client" : "oidc-client",
    sub: settings.sub,
    external_subject: `external-${settings.sub}`,
    id: "untrusted-profile-id",
    email: settings.email,
    name: "OIDC User",
    email_verified: true,
    iat: now,
    exp: mode === "expired" ? now - 60 : now + 3600,
    nonce: mode === "wrong-nonce" ? "wrong-nonce" : nonce,
  };
  if (mode === "missing-nonce") delete claims.nonce;
  if (mode === "mapped-image")
    claims.picture = "https://issuer.example/avatar.png";
  if (mode === "userinfo" || mode === "missing-subject") delete claims.email;
  if (mode === "future-not-before") claims.nbf = now + 3600;
  const signingKey = keys.find(
    (key) =>
      key.kid === (mode === "wrong-signature" ? "forged" : settings.signingKey),
  )!;
  const header = { alg: "RS256", kid: settings.signingKey, typ: "JWT" };
  const input = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}`;
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    signingKey.pair.privateKey,
    encoder.encode(input),
  );
  return `${input}.${base64url(signature)}`;
}

function validClient(
  request: Request,
  body: URLSearchParams,
  provider: string,
) {
  if (provider === "oidc-basic") {
    return (
      request.headers.get("authorization") ===
        `Basic ${Buffer.from("oidc-client:oidc-secret").toString("base64")}` &&
      !body.has("client_id") &&
      !body.has("client_secret")
    );
  }
  return (
    !request.headers.has("authorization") &&
    body.get("client_id") === "oidc-client" &&
    (provider === "oidc-public"
      ? !body.has("client_secret")
      : body.get("client_secret") === "oidc-secret")
  );
}

server.reload({
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/__health") return Response.json({ ok: true });
    if (url.pathname === "/__test/configure" && request.method === "POST") {
      settings = { ...defaults(), ...(await request.json()) };
      issuedIdToken = undefined;
      grant = undefined;
      requests = { discovery: 0, jwks: 0, token: 0, userinfo: 0 };
      return Response.json({ ok: true });
    }
    if (url.pathname === "/__test/rotate" && request.method === "POST") {
      settings.signingKey = "rotated";
      settings.publishedKeys = ["rotated"];
      return Response.json({ ok: true });
    }
    if (url.pathname === "/__test/requests") return Response.json(requests);
    if (url.pathname === "/__test/issued-token")
      return Response.json({ idToken: issuedIdToken });
    if (url.pathname === "/__test/id-token" && request.method === "POST") {
      const body = await request.json();
      return Response.json({ token: await idToken(body.nonce ?? null) });
    }
    if (url.pathname.startsWith("/discovery/")) {
      requests.discovery++;
      const kind = url.pathname.split("/").at(-1);
      if (
        kind === "headers" &&
        request.headers.get("x-compat-discovery") !== "allowed"
      ) {
        return Response.json(
          { error: "missing discovery header" },
          { status: 401 },
        );
      }
      if (kind === "unavailable")
        return Response.json({ error: "unavailable" }, { status: 503 });
      const document: Record<string, unknown> = {
        issuer: baseURL,
        authorization_endpoint: `${baseURL}/authorize`,
        token_endpoint: `${baseURL}/token`,
        userinfo_endpoint: `${baseURL}/userinfo`,
        jwks_uri: "/jwks",
        id_token_signing_alg_values_supported: ["RS256"],
      };
      if (kind === "missing-jwks") delete document.jwks_uri;
      if (kind === "invalid-issuer") document.issuer = "invalid issuer";
      return Response.json(document);
    }
    if (url.pathname === "/jwks") {
      requests.jwks++;
      return Response.json({
        keys: keys
          .filter((key) => settings.publishedKeys.includes(key.kid))
          .map((key) => key.jwk),
      });
    }
    if (url.pathname === "/authorize") {
      const redirectURI = url.searchParams.get("redirect_uri");
      const state = url.searchParams.get("state");
      if (
        !redirectURI ||
        !state ||
        url.searchParams.get("client_id") !== "oidc-client"
      ) {
        return Response.json({ error: "invalid_request" }, { status: 400 });
      }
      grant = {
        nonce: url.searchParams.get("nonce"),
        redirectURI,
        challenge: url.searchParams.get("code_challenge"),
      };
      const callback = new URL(redirectURI);
      callback.searchParams.set("code", "oidc-code");
      callback.searchParams.set("state", state);
      callback.searchParams.set(
        "iss",
        settings.mode === "callback-issuer" ? `${baseURL}/other` : baseURL,
      );
      return Response.redirect(callback, 302);
    }
    if (url.pathname === "/token" && request.method === "POST") {
      requests.token++;
      const body = new URLSearchParams(await request.text());
      if (body.get("grant_type") === "refresh_token") {
        const refreshToken = body.get("refresh_token") ?? "";
        const provider = refreshToken.replace("oidc-refresh-token:", "");
        if (
          !refreshToken.startsWith("oidc-refresh-token:") ||
          !validClient(request, body, provider)
        ) {
          return Response.json({ error: "invalid_client" }, { status: 401 });
        }
        return Response.json({
          access_token: "oidc-refreshed-access-token",
          refresh_token: refreshToken,
          expires_in: 3600,
          token_type: "Bearer",
          scope: "openid profile",
        });
      }
      const provider = grant?.redirectURI.split("/").at(-1) ?? "";
      const challenge = base64url(
        await crypto.subtle.digest(
          "SHA-256",
          encoder.encode(body.get("code_verifier") ?? ""),
        ),
      );
      if (
        !grant ||
        body.get("code") !== "oidc-code" ||
        body.get("redirect_uri") !== grant.redirectURI ||
        (grant.challenge === null
          ? body.has("code_verifier")
          : challenge !== grant.challenge) ||
        body.get("grant_type") !== "authorization_code" ||
        !validClient(request, body, provider) ||
        (grant.redirectURI.endsWith("/oidc-parameters") &&
          body.get("audience") !== "fleet-api")
      ) {
        return Response.json({ error: "invalid_grant" }, { status: 400 });
      }
      const token = await idToken(grant.nonce);
      issuedIdToken = token;
      grant = undefined;
      return Response.json({
        access_token: "oidc-access-token",
        refresh_token: `oidc-refresh-token:${provider}`,
        token_type: "Bearer",
        expires_in: 3600,
        ...(settings.mode === "no-id-token" ? {} : { id_token: token }),
        scope: "openid email profile",
      });
    }
    if (url.pathname === "/userinfo") {
      requests.userinfo++;
      if (request.headers.get("authorization") !== "Bearer oidc-access-token")
        return new Response(null, { status: 401 });
      return Response.json({
        ...(settings.mode === "missing-subject" ? {} : { sub: settings.sub }),
        id: "untrusted-profile-id",
        email: settings.email,
        name: "OIDC User",
        email_verified: true,
      });
    }
    return new Response(null, { status: 404 });
  },
});
