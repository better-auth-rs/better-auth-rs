import { expect } from "bun:test";

export const issuer = process.env.COMPAT_OIDC_URL;

export async function control(path: string, body?: unknown) {
  if (!issuer)
    throw new Error("COMPAT_OIDC_URL must name the shared OIDC test issuer");
  const response = await fetch(
    `${issuer}/__test/${path}`,
    body === undefined
      ? {}
      : {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        },
  );
  expect(response.status).toBe(200);
  return response.json();
}
