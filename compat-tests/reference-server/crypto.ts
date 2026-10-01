import { symmetricDecrypt, symmetricEncrypt, symmetricDecodeJWT, symmetricEncodeJWT } from "better-auth/crypto";
import type { Database } from "bun:sqlite";

export function createCryptoFixture(profile: string, database: Database) {
  return {
    options: profile.startsWith("crypto-") ? {
      secrets: [
        { version: 2, value: "current-rotation-key-with-32-characters-123" },
        { version: 1, value: "previous-rotation-key-with-32-characters-456" },
      ],
      account: { encryptOAuthTokens: true, storeAccountCookie: true, storeStateStrategy: profile === "crypto-cookie" ? "cookie" as const : "database" as const },
    } : {},
    async handle(request: Request, auth: any): Promise<Response | null> {
      if (new URL(request.url).pathname !== "/__test/crypto") return null;
      const body = await request.json();
      if (body.operation === "state") {
        if (Object.hasOwn(body, "value")) {
          const adapter = (await auth.$context).internalAdapter;
          await adapter.deleteVerificationByIdentifier(body.state);
          await adapter.createVerificationValue({ identifier: body.state, value: typeof body.value === "string" ? body.value : JSON.stringify(body.value), expiresAt: new Date(Date.now() + 600_000) });
        }
        return Response.json({ value: (database.query("SELECT value FROM verification WHERE identifier = ?").get(body.state) as any)?.value ?? null });
      }
      if (body.operation === "user") {
        database.query('INSERT INTO user (id, email, name, emailVerified, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)')
          .run(body.id, body.email, "Cookie transfer", 1, Date.now(), Date.now());
        return Response.json({ id: body.id });
      }
      if (body.operation === "accounts") {
        return Response.json(database.query("SELECT a.id,a.userId,a.providerId,a.accountId,a.accessToken,a.refreshToken,a.idToken FROM account a JOIN user u ON a.userId=u.id WHERE u.email=?").all(body.email));
      }
      const key = body.secret ?? (body.secrets ? {
        currentVersion: body.secrets[0]?.version,
        keys: new Map(body.secrets.map((key: any) => [key.version, key.value])),
        legacySecret: body.legacySecret,
      } : (await auth.$context).secretConfig);
      const salt = body.salt ?? "better-auth-account";
      try {
        const value = body.operation === "encrypt" ? await symmetricEncrypt({ key, data: body.data }) :
          body.operation === "decrypt" ? await symmetricDecrypt({ key, data: body.data }) :
          body.operation === "encode" ? await symmetricEncodeJWT(body.data, key, salt, body.expiresIn ?? 3600) :
          await symmetricDecodeJWT(body.data, key, salt);
        return Response.json({ ok: true, value });
      } catch { return Response.json({ ok: false }); }
    },
  };
}
