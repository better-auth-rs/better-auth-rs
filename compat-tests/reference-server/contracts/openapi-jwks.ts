import { betterAuth } from "better-auth/minimal";
import { jwt, openAPI } from "better-auth/plugins";

export async function captureOpenApiJwks() {
  const cases = [];
  for (const name of ["default", "renamed", "disabled"] as const) {
    const path = name === "default" ? "/jwks" : "/keys";
    const auth = betterAuth({
      baseURL: "https://openapi-jwks.example.test",
      secret: "ordinary-openapi-jwks-secret-at-least-thirty-two-characters",
      telemetry: { enabled: false },
      logger: { disabled: true },
      rateLimit: { enabled: false },
      disabledPaths: name === "disabled" ? [path] : [],
      plugins: [jwt(name === "default" ? undefined : { jwks: { jwksPath: path } }), openAPI()],
    });
    const response = await auth.handler(new Request("https://openapi-jwks.example.test/api/auth/open-api/generate-schema"));
    const schema = await response.json();
    cases.push({
      name,
      status: response.status,
      defaultPathPresent: Object.hasOwn(schema.paths, "/jwks"),
      renamedPathPresent: Object.hasOwn(schema.paths, "/keys"),
      operation: schema.paths[path]?.get ?? null,
    });
  }
  const { version } = await Bun.file(new URL("../node_modules/better-auth/package.json", import.meta.url)).json();
  return { version, cases };
}

if (import.meta.main) {
  const destination = process.argv[2];
  if (!destination) throw new Error("Pass the absolute fixture destination path");
  await Bun.write(destination, `${JSON.stringify(await captureOpenApiJwks(), null, 2)}\n`);
}
