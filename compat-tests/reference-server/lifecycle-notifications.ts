import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { getCurrentAuthEndpointContext } from "@better-auth/core/context";
import { createEmailVerificationToken } from "./node_modules/better-auth/dist/api/routes/email-verification.mjs";

export const endpoints = ["change-update", "change-confirm", "change-verify", "verify-confirm", "verify-legacy", "direct", "delete"] as const;
export const modes = [["default", "resolve"], ["default", "reject"], ["handler", "resolve"], ["handler", "reject"], ["handler", "sync-throw"], ["handler", "void"], ["handler-throw", "reject"]] as const;
export type Endpoint = typeof endpoints[number];
export type Scheduling = "default" | "handler" | "handler-throw";
export type Sender = "resolve" | "reject" | "sync-throw" | "void";
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return {promise, resolve};
}
const secret = "lifecycle-notification-contract-secret-thirty-two-characters";
export async function runCase(endpoint: Endpoint, transport: "http" | "native", scheduling: Scheduling, sender: Sender) {
  const database = new Database(":memory:");
  const gate = deferred(), entered = deferred(), finished = deferred();
  const events: string[] = [], contexts: unknown[] = [], logs: unknown[] = [], tasks: Promise<unknown>[] = [];
  let responseDone = false;
  function capture(phase: string, data: any, request: Request | undefined) {
    const current = getCurrentAuthEndpointContext();
    const payload = endpoint === "delete" ? null : JSON.parse(Buffer.from(data.token.split(".")[1], "base64url").toString());
    contexts.push({phase, path: current.path, body: current.body ?? null,
      request: !!request, requestPath: request ? new URL(request.url).pathname : null,
      email: data.user.email, verified: data.user.emailVerified, newEmail: data.newEmail ?? null,
      token: payload ? {email: payload.email, updateTo: payload.updateTo ?? null, requestType: payload.requestType ?? null} : null,
      urlPath: new URL(data.url).pathname, callbackURL: new URL(data.url).searchParams.get("callbackURL")});
  }
  function send(data: any, request: Request | undefined) {
    events.push("sender:start"); capture("start", data, request); entered.resolve();
    if (sender === "sync-throw") { finished.resolve(); throw new Error("sender-sync"); }
    if (sender === "void") { events.push("sender:void"); finished.resolve(); return; }
    return (async () => {
      await gate.promise; capture("released", data, request); events.push("sender:released"); finished.resolve();
      if (sender === "reject") throw new Error("sender-async");
    })();
  }
  const options: any = {
    database, baseURL: "http://localhost:3000", secret, rateLimit: {enabled: false},
    emailAndPassword: {enabled: true, password: {hash: async () => "fixture-hash", verify: async () => true}},
    emailVerification: {sendOnSignUp: false, sendVerificationEmail: send},
    user: {changeEmail: {enabled: true, updateEmailWithoutVerification: endpoint === "change-update",
      ...(endpoint === "change-confirm" ? {sendChangeEmailConfirmation: send} : {})},
      deleteUser: {enabled: true, sendDeleteAccountVerification: send}},
    logger: {level: "error", log: (_level: string, message: unknown, ...args: any[]) => {
      if (typeof message === "string" && message.startsWith("Failed to run background task")) {
        logs.push({message, error: args[0]?.message ?? null}); events.push(`log:${args[0]?.message ?? "unknown"}`);
      }
    }},
  };
  if (scheduling !== "default") options.advanced = {backgroundTasks: {handler: (task: Promise<unknown>) => {
    events.push("handler:received"); tasks.push(task);
    if (scheduling === "handler-throw") throw new Error("handler-sync");
  }}};
  await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  const signup = await auth.api.signUpEmail({body: {name: "Lifecycle", email: "old@example.com", password: "fixture-password"}, asResponse: true});
  const cookie = signup.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
  const verified = endpoint === "change-confirm";
  database.query("update user set emailVerified = ?").run(verified ? 1 : 0);
  const query: Record<string, string> = {};
  let path = "/change-email", method = "POST", body: any = {newEmail: "new@example.com", unknown: "drop"};
  let api: any = auth.api.changeEmail;
  if (endpoint.startsWith("verify-")) {
    path = "/verify-email"; method = "GET"; body = undefined; api = auth.api.verifyEmail;
    query.token = await createEmailVerificationToken(secret, "old@example.com", "new@example.com", 3600,
      endpoint === "verify-confirm" ? {requestType: "change-email-confirmation"} : undefined);
  } else if (endpoint === "direct") {
    path = "/send-verification-email"; body = {email: "old@example.com", unknown: "drop"}; api = auth.api.sendVerificationEmail;
  } else if (endpoint === "delete") {
    path = "/delete-user"; body = {unknown: "drop"}; api = auth.api.deleteUser;
  }
  const snapshot = () => ({
    email: (database.query("select email from user").get() as any).email,
    verified: !!(database.query("select emailVerified from user").get() as any).emailVerified,
    verifications: (database.query("select count(*) as count from verification").get() as any).count,
  });
  const operation = (async () => {
    try {
      const headers = {cookie, "content-type": "application/json", origin: "http://localhost:3000"};
      const response = transport === "http"
        ? await auth.handler(new Request(`http://localhost:3000/api/auth${path}${method === "GET" ? `?${new URLSearchParams(query)}` : ""}`, {method, headers, body: body ? JSON.stringify(body) : undefined}))
        : await api({body, query, headers, asResponse: true});
      return {status: response.status, thrown: null, cookie: response.headers.getSetCookie().some(value => value.startsWith("better-auth.session_token="))};
    } catch (error: any) { return {status: null, thrown: error.message, cookie: false}; }
    finally { responseDone = true; events.push("response"); }
  })();
  await entered.promise;
  const storedBeforeRelease = snapshot();
  const asynchronous = sender === "resolve" || sender === "reject";
  const scheduled = endpoint !== "direct" && scheduling !== "default" && asynchronous;
  if (!asynchronous || scheduled) await operation;
  const respondedBeforeRelease = responseDone;
  events.push("gate:release"); gate.resolve();
  const outcome = await operation;
  await finished.promise;
  const taskStates = (await Promise.allSettled(tasks)).map(result => result.status);
  const storedAfterResponse = snapshot();
  database.close();
  return {endpoint, transport, scheduling, sender, respondedBeforeRelease, storedBeforeRelease, storedAfterResponse, outcome, events, logs, contexts, taskStates};
}
