import { betterAuth } from "better-auth";
import { deviceAuthorization, redeemDeviceCode } from "better-auth/plugins/device-authorization";
import { withDeviceGrantDatabase } from "./device-grant-database.mjs";

export async function captureDeviceRedemptionBackend(backend: string) {
    const options = {
      baseURL: "http://device-redemption.test",
      secret: "ordinary-device-redemption-contract-at-least-32-characters",
      logger: { disabled: true }, telemetry: { enabled: false }, plugins: [deviceAuthorization()],
    };
    return await withDeviceGrantDatabase(backend, options, async (auth: ReturnType<typeof betterAuth>) => {
    const context = await auth.$context;
    const { adapter } = context;
    const owner = await adapter.create<any>({ model: "user", data: {
      name: "Owner", email: "owner@device-redemption.test", emailVerified: false,
      createdAt: new Date(), updatedAt: new Date(),
    } });
    const cases = [];
    for (const mode of ["success", "authorization error", "preparation error"]) {
      const token = `ordinary-device:${mode}`;
      await adapter.create({ model: "deviceCode", data: {
        deviceCode: token, userCode: `ordinary-user:${mode}`, userId: owner.id,
        expiresAt: new Date(Date.now() + 3_600_000), status: "approved",
        clientId: "ordinary-client", scope: "initial",
      } });
      const events: string[] = [];
      const callbackError = new Error(`ordinary ${mode}`);
      let result: object | null = null;
      let error: string | null = null;
      try {
        const redeemed = await redeemDeviceCode({
          ctx: { context } as any,
          deviceCode: token,
          async authorizeRedemption(row) {
            events.push(`authorize:${row.scope}`);
            if (mode === "authorization error") throw callbackError;
            return { ownershipWhere: { field: "clientId", value: "ordinary-client" }, context: "issuer" };
          },
          async prepareRedemption(row, authorization) {
            events.push(`prepare:${row.scope}:${authorization}`);
            if (mode === "preparation error") throw callbackError;
            await adapter.update({ model: "deviceCode", where: [{ field: "id", value: row.id }], update: { scope: "prepared" } });
            return `issued:${authorization}`;
          },
        });
        result = {
          scope: redeemed.claimedDeviceCode.scope,
          authorizationContext: redeemed.authorizationContext,
          redemptionContext: redeemed.redemptionContext,
          userFound: redeemed.user.id === owner.id,
          lastPolledAt: redeemed.claimedDeviceCode.lastPolledAt !== undefined && redeemed.claimedDeviceCode.lastPolledAt !== null,
        };
      } catch (caught) {
        if (caught !== callbackError) throw caught;
        error = callbackError.message;
      }
      const remaining = await adapter.findOne<any>({ model: "deviceCode", where: [{ field: "deviceCode", value: token }] });
      cases.push({ name: mode, events, result, error, remaining: remaining ? {
        scope: remaining.scope,
        lastPolledAt: remaining.lastPolledAt !== undefined && remaining.lastPolledAt !== null,
      } : null });
    }
    return { backend, cases };
    });
}

export async function captureDeviceRedemption() {
  const backends = [];
  for (const backend of ["memory", "sqlite"]) backends.push(await captureDeviceRedemptionBackend(backend));
  return { version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version, backends };
}

if (import.meta.main) console.log(JSON.stringify(await captureDeviceRedemption(), null, 2));
