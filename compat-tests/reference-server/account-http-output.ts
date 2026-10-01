import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
async function fixture(scopeReturned = true) {
  const database = new Database(":memory:");
  const options = {
    database, baseURL: "http://localhost:3000", secret: "account-http-output-proof-secret-at-least-32-characters",
    logger: { disabled: true },
    emailAndPassword: { enabled: true, password: { hash: async (input: string) => input, verify: async () => true } },
    account: { storeAccountCookie: true, additionalFields: {
      scope: { type: "string", required: false, returned: scopeReturned, onUpdate: () => "after", transform: { output: (value: unknown) => value == null ? value : `${value}:out` } },
      idToken: { type: "string", required: false, transform: { output: (value: unknown) => value == null ? value : `${value}:out` } },
    } },
    socialProviders: { google: { clientId: "fixture", clientSecret: "fixture", refreshAccessToken: async () => ({
      accessToken: "new-access", accessTokenExpiresAt: new Date("2100-01-01T00:00:00Z"),
    }) } },
  };
  await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  const response = await auth.api.signUpEmail({ asResponse: true, body: { email: "account-output@example.test", name: "Account", password: "password123" } });
  if (response.status !== 200) throw new Error(`Signup failed: ${response.status}`);
  const user = (await response.json()).user;
  const headers = new Headers({ cookie: response.headers.getSetCookie().map((cookie: string) => cookie.split(";")[0]).join("; ") });
  const context = await auth.$context;
  const account = await context.internalAdapter.linkAccount({
    userId: user.id, accountId: "google-account", providerId: "google",
    accessToken: "old-access", refreshToken: "old-refresh", idToken: "old-id",
    scope: "before", accessTokenExpiresAt: new Date("2000-01-01T00:00:00Z"),
  });
  return { auth, account, headers, database };
}

export async function routeAccountHttpOutput(request: Request) {
  if (new URL(request.url).pathname !== "/__test/account-http-output") return null;
  const { operation } = await request.json();
  const { auth, account, headers, database } = await fixture(operation !== "list-accounts");
  try {
    const response = await auth.handler(new Request(`http://localhost:3000/api/auth/${operation}`, {
      method: operation === "list-accounts" ? "GET" : "POST",
      headers: {...Object.fromEntries(headers), "content-type":"application/json", "origin":"http://localhost:3000"},
      ...(operation === "list-accounts" ? {} : {body:JSON.stringify({accountId:account.id})}),
    }));
    const body = await response.json();
    const row = operation === "list-accounts" ? body.find((item:any)=>item.id===account.id) : body;
    const selected = operation === "list-accounts" ? {scopes: row.scopes, hasIdToken:Object.hasOwn(row,"idToken")} :
      Object.fromEntries(["accessToken","refreshToken","idToken","scope","scopes"].filter(key=>Object.hasOwn(row,key)).map(key=>[key,row[key]]));
    const stored = database.query("SELECT scope, idToken FROM account WHERE id = ?").get(account.id);
    return Response.json({status:response.status,body:selected,stored});
  } finally {database.close();}
}
