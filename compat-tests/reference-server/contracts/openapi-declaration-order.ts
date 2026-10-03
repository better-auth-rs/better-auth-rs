import { betterAuth } from "better-auth/minimal";
import { deviceAuthorization, openAPI } from "better-auth/plugins";

export async function captureOpenApiDeclarationOrder() {
  const cases = [];
  for (const name of ["custom-before-device", "device-before-custom"] as const) {
    const custom = {
      id: "ordinary-openapi-declaration-order",
      schema: {
        deviceCode: { fields: {
          label: {
            type: "string" as const,
            required: true,
            fieldName: "stored_label",
            defaultValue: "display-label",
          },
        } },
      },
    };
    const device = deviceAuthorization();
    const plugins = name === "custom-before-device"
      ? [custom, device, openAPI()]
      : [device, custom, openAPI()];
    const auth = betterAuth({
      baseURL: "http://openapi-declaration-order.test",
      secret: "ordinary-openapi-declaration-order-secret-at-least-32-characters",
      logger: { disabled: true },
      telemetry: { enabled: false },
      rateLimit: { enabled: false },
      plugins,
    });
    const document = await auth.api.generateOpenAPISchema();
    const component = document.components.schemas.DeviceCode;
    if (!component) throw new Error("The DeviceCode component must be present");
    cases.push({ name, component });
  }
  return {
    version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    cases,
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureOpenApiDeclarationOrder(), null, 2));
