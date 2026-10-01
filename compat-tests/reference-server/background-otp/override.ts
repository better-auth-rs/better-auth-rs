import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { emailOTP } from "better-auth/plugins";

export async function overrideCase(reuse: boolean, outcome: "commit" | "rollback" | "after-error") {
  const database = new Database(":memory:");
  const events: string[] = [];
  const observations: unknown[] = [];
  const identifier = "email-verification-otp-override@example.com";
  const options: any = {
    database, baseURL: "http://localhost:3000", secret: "background-override-secret-at-least-thirty-two-characters",
    logger: {disabled: true}, rateLimit: {enabled: false},
    emailAndPassword: {enabled: true, password: {hash: async () => "fixture-hash", verify: async () => true}},
    emailVerification: {sendOnSignUp: true},
    plugins: [emailOTP({overrideDefaultEmailVerification: true, resendStrategy: reuse ? "reuse" : "rotate", generateOTP: () => "654321",
      sendVerificationOTP: async (message: any, endpoint: any) => {
        const user = await endpoint.context.internalAdapter.findUserByEmail(message.email);
        const verification = await endpoint.context.internalAdapter.findVerificationValue(identifier);
        observations.push({path: endpoint.path, body: endpoint.body, hasRequest: !!endpoint.request,
          userFound: !!user, value: verification?.value ?? null, otp: message.otp});
        events.push("sender");
      },
    })],
    databaseHooks: {
      verification: {create: {before: () => {events.push("verification:create.before");}, after: () => {events.push("verification:create.after");}},
        update: {before: () => {events.push("verification:update.before");}, after: () => {events.push("verification:update.after");}}},
      user: {create: {after: () => {events.push("user:create.after"); if(outcome === "after-error") throw new Error("after-error");}}},
      session: {create: {before: () => {events.push("session:create.before"); if(outcome === "rollback") throw new Error("session-rejected");}, after: () => {events.push("session:create.after");}}},
    },
  };
  await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  if (reuse) {
    await (await auth.$context).internalAdapter.createVerificationValue({identifier, value: "123456:0", expiresAt: new Date("2099-01-01T00:00:00Z")});
    events.length = 0;
  }
  let result: unknown;
  try {
    const response = await auth.api.signUpEmail({body: {name: "Override", email: "override@example.com", password: "fixture-password"}, asResponse: true});
    result = {status: response.status, thrown: null};
  } catch (error: any) { result = {status: null, thrown: error.message}; }
  const rows = database.query("select value, expiresAt from verification").all() as any[];
  const count = (table: string) => (database.query(`select count(*) as count from ${table}`).get() as any).count;
  const stored = {users: count("user"), accounts: count("account"), sessions: count("session"),
    verification: rows.map(row => ({value: row.value, originalExpiry: new Date(row.expiresAt).getTime() === Date.parse("2099-01-01T00:00:00Z")}))};
  database.close();
  return {reuse, outcome, result, events, observations, stored};
}
