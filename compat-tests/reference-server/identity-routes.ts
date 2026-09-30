import { Database } from "bun:sqlite";
import { anonymous, phoneNumber, siwe } from "better-auth/plugins";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

export function createIdentityFixture(database: Database, profile: string) {
  const outbox = new Map<string, { phoneNumber: string; code: string; purpose: string }[]>();
  const links: { anonymousId: string; newId: string }[] = [];
  let counter = 0;
  function send(message: { phoneNumber: string; code: string }, purpose: string) {
    outbox.set(message.phoneNumber, [...(outbox.get(message.phoneNumber) ?? []), { ...message, purpose }]);
  }
  const plugins = (profile.startsWith("anonymous") || profile === "oauth-proxy-anonymous") ? [anonymous({
    generateRandomEmail: () => `anonymous-${++counter}@example.com`,
    disableDeleteAnonymousUser: profile === "anonymous-disabled",
    onLinkAccount: async ({ anonymousUser, newUser }) => { links.push({ anonymousId: anonymousUser.user.id, newId: newUser.user.id }); },
  })] : (profile.startsWith("phone-number") || profile === "email-otp-reuse") ? [phoneNumber({
    sendOTP: async (message) => send(message, "verify"),
    sendPasswordResetOTP: async (message) => send(message, "reset"),
    phoneNumberValidator: (phone) => /^\+[0-9]{10,15}$/.test(phone),
    requireVerification: profile === "phone-number-options",
    signUpOnVerification: profile === "phone-number-options" ? undefined : { getTempEmail: (phone) => `${phone.slice(1)}@phone.example.com` },
  })] : profile.startsWith("siwe") ? [siwe({
    domain: "wallet.example.com",
    anonymous: profile !== "siwe-email",
    getNonce: async () => `identitynonce${String(++counter).padStart(8, "0")}`,
    verifyMessage: async ({ message, signature, address }) => {
      try {
        const bytes = hexToBytes(signature.slice(2));
        if (bytes.length !== 65) return false;
        const hash = keccak_256(utf8ToBytes(`\x19Ethereum Signed Message:\n${new TextEncoder().encode(message).length}${message}`));
        const recovered = secp256k1.recoverPublicKey(new Uint8Array([bytes[64] - 27, ...bytes.slice(0, 64)]), hash, { prehash: false });
        const publicKey = secp256k1.Point.fromBytes(recovered).toBytes(false);
        return `0x${bytesToHex(keccak_256(publicKey.slice(1)).slice(-20))}` === address.toLowerCase();
      } catch { return false; }
    },
  })] : [];
  return {
    plugins,
    reset() { outbox.clear(); links.length = 0; counter = 0; },
    async handle(request: Request): Promise<Response | null> {
      if (new URL(request.url).pathname !== "/__test/identity" || request.method !== "POST") return null;
      const body = await request.json();
      if (body.action === "links") return Response.json(links);
      if (body.action === "expire") {
        database.query('UPDATE "verification" SET "expiresAt" = ? WHERE "identifier" = ?').run(Date.now() - 1000, body.identifier);
        return Response.json({ success: true });
      }
      if (body.action === "phone") {
        database.query('UPDATE "user" SET "phoneNumber" = ?, "phoneNumberVerified" = ? WHERE "email" = ?').run(body.phoneNumber, body.verified ?? false, body.email);
        return Response.json({ success: true });
      }
      if (body.action === "wallets") return Response.json(database.query('SELECT "address", "chainId", "isPrimary", "userId" FROM "walletAddress" ORDER BY "chainId"').all().map((wallet: any) => ({...wallet,isPrimary:Boolean(wallet.isPrimary)})));
      return Response.json(outbox.get(body.phoneNumber) ?? []);
    },
  };
}
