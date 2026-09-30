import { jwt } from "better-auth/plugins";
import { createJwk, signJWT } from "better-auth/plugins/jwt";
import { createAuthEndpoint } from "better-auth/api";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

export async function createJwtFixture(profile: string, baseURL: string) {
  const remoteKeys: { kid: string; privateKey: CryptoKey; publicKey: Record<string, unknown> }[] = [];
  async function rotateRemote() {
    const pair = await generateKeyPair("EdDSA", { extractable: true });
    const kid = crypto.randomUUID();
    remoteKeys.push({ kid, privateKey: pair.privateKey, publicKey: { ...await exportJWK(pair.publicKey), alg: "EdDSA", kid } });
    return { kid };
  }
  const options: Parameters<typeof jwt>[0] = {
    jwks: { keyPairConfigs: [{ alg: "PS256" }, { alg: "ES512" }] },
    ...(profile === "jwt-claims" ? { jwt: { audience: ["service-a", "service-b"], expirationTime: 2000000000.5 } } : {}),
    ...(profile === "jwt-date" ? { jwt: { audience: ["service-a", "service-b"], expirationTime: new Date(2000000000123) } } : {}),
    ...(profile === "jwt-relative" ? { jwt: { audience: ["service-a", "service-b"], expirationTime: "1.5s" } } : {}),
    ...(profile === "jwt-ps256" ? { jwks: { keyPairConfig: { alg: "PS256", modulusLength: 3072 } } } : {}),
    ...(profile === "jwt-es512" ? { jwks: { keyPairConfig: { alg: "ES512" } } } : {}),
    ...(profile === "jwt-advanced" ? { jwt: { definePayload: ({ user, session }) => ({ sessionId: session.id, userId: user.id, sessionUserId: session.userId, userAgent: session.userAgent }), getSubject: ({ session }) => session.id } } : {}),
    ...(["jwt-cache", "cookie-version-plugin-jwt"].includes(profile) ? { sessionCookieCache: true, jwt: { issuer: "ordinary-issuer", audience: "ordinary-audience" } } : {}),
    ...(profile === "organization-jwt" ? { sessionCookieCache: true, jwt: { definePayload: ({ user, session }) => ({ user, session }), getSubject: ({ session }) => session.id } } : {}),
    ...(profile === "jwt-remote" ? {
      jwks: { remoteUrl: `${baseURL}/__test/jwt/remote-jwks`, keyPairConfig: { alg: "EdDSA" } },
      jwt: { async sign(payload, header, config) {
        if (!remoteKeys.length) await rotateRemote();
        const key = config?.signingKeyId ? remoteKeys.find(key => key.kid === config.signingKeyId) : remoteKeys.at(-1);
        if (!key || (config?.signingAlgorithm && config.signingAlgorithm !== "EdDSA")) throw new Error("Invalid remote signing key");
        return new SignJWT(payload).setProtectedHeader({ ...header, alg: "EdDSA", kid: key.kid }).sign(key.privateKey);
      } },
    } : {}),
  };
  const plugins = (["organization-jwt", "cookie-version-plugin-jwt"].includes(profile) || profile.startsWith("jwt-") && !["jwt-rs256", "jwt-es256", "jwt-identity"].includes(profile)) ? [jwt(options), {
    id: "jwt-fixture",
    endpoints: {
      compatSignJwt: createAuthEndpoint.serverOnly({ method: "POST" }, async (ctx) => ({ token: await signJWT(ctx, { options, payload: ctx.body.payload, signingKeyId: ctx.body.kid, signingAlgorithm: ctx.body.alg, header: ctx.body.header }) })),
      compatRotateJwt: createAuthEndpoint.serverOnly({ method: "POST" }, async (ctx) => profile === "jwt-remote" ? rotateRemote() : { kid: (await createJwk(ctx, options)).id }),
      compatExpiredJwt: createAuthEndpoint.serverOnly({ method: "POST" }, async (ctx) => ({ kid: (await createJwk(ctx, { ...options, jwks: { ...options.jwks, rotationInterval: -1 } })).id })),
    },
  }] : [];
  return {
    plugins,
    async handle(request: Request, auth: any) {
      const path = new URL(request.url).pathname;
      if (path === "/__test/jwt/remote-jwks") return Response.json({ keys: remoteKeys.map(key => key.publicKey) });
      if (path !== "/__test/jwt/action") return;
      const body = await request.json();
      if (body.action === "verify") return Response.json(await auth.api.verifyJWT({ body }));
      if (body.action === "sign") return Response.json(await auth.api.compatSignJwt({ body }));
      if (body.action === "rotate") return Response.json(await auth.api.compatRotateJwt({ body }));
      if (body.action === "expired") return Response.json(await auth.api.compatExpiredJwt({ body }));
      if (body.action === "revoke") {
        const ctx = await auth.$context;
        await ctx.internalAdapter.deleteSession(body.token);
        return Response.json({ status: true });
      }
      throw new Error("Unknown JWT fixture action");
    },
  };
}
