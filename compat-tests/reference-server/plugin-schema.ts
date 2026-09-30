import config from "../schema-consumer/plugin-schema.json";
import { jwt } from "better-auth/plugins";

export const mappedPluginSchema = process.env.COMPAT_PROFILE === "plugin-schema" ? {
  apikey: config.apikey,
  deviceCode: config.deviceCode,
  passkey: config.passkey,
  twoFactor: config.twoFactor,
  jwks: config.jwks,
  walletAddress: config.walletAddress,
} : undefined;
export const mappedPluginExtras = mappedPluginSchema ? [jwt({ schema: { jwks: mappedPluginSchema.jwks } })] : [];
