export const TS_BASE_URL = process.env.AUTH_BASE_URL_TS || "http://localhost:3100";
export const RUST_BASE_URL = process.env.AUTH_BASE_URL_RUST || "http://localhost:3200";
export const LOCAL_NO_PROXY = "localhost,127.0.0.1";

export async function requireHealthy(baseURL: string, label: string) {
  const response = await fetch(`${baseURL}/__health`, {
    headers: {
      connection: "close",
    },
  }).catch(() => null);

  if (!response?.ok) {
    throw new Error(`${label} server is not reachable at ${baseURL}`);
  }
}
