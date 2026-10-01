import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { emailOTP, twoFactor } from "better-auth/plugins";
import { getCurrentAuthEndpointContext } from "@better-auth/core/context";

export type Transport = "http" | "native";
export type Endpoint = "email-otp" | "two-factor";
export type Scheduling = "default" | "handler" | "handler-throw";
export type Sender = "resolve" | "reject" | "sync-throw" | "void" | "reject-immediate";
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return {promise, resolve};
}

export async function runCase(endpoint: Endpoint, transport: Transport, scheduling: Scheduling, sender: Sender) {
  const database = new Database(":memory:");
  const gate = deferred(), entered = deferred(), finished = deferred();
  const events: string[] = [], logs: {message: string, error: string | null}[] = [];
  const contexts: unknown[] = [], tasks: Promise<unknown>[] = [];
  let responseDone = false;
  const capture = (phase: string, original: any, request: Request | undefined) => {
    const current = getCurrentAuthEndpointContext();
    contexts.push({phase, sameContext: current === original, path: current.path,
      body: structuredClone(current.body), request: !!current.request,
      requestURL: current.request?.url ?? null, sameRequest: current.request === request,
      baseURL: current.context.baseURL});
  };
  function send(_data: any, supplied: any) {
    const context = getCurrentAuthEndpointContext();
    const request = supplied.request;
    events.push("sender:start");
    capture("start", context, request);
    entered.resolve();
    if (sender === "sync-throw") { finished.resolve(); throw new Error("sender-sync"); }
    if (sender === "reject-immediate") { finished.resolve(); return Promise.reject(new Error("sender-async")); }
    if (sender === "void") { events.push("sender:void"); finished.resolve(); return; }
    return (async () => {
      await gate.promise;
      capture("released", context, request);
      events.push("sender:released");
      finished.resolve();
      if (sender === "reject") throw new Error("sender-async");
    })();
  }
  const options: any = {
    database, baseURL: "http://localhost:3000", secret: "background-contract-secret-at-least-thirty-two-characters",
    rateLimit: {enabled: false},
    logger: {level: "error", log: (_level: string, message: unknown, ...args: any[]) => {
      if (typeof message === "string" && (message.startsWith("Failed to run background task") || message === "Failed to send two-factor OTP")) {
        logs.push({message, error: args[0]?.message ?? null});
        events.push(`log:${args[0]?.message ?? "unknown"}`);
      }
    }},
    emailAndPassword: {enabled: true, password: {hash: async () => "fixture-hash", verify: async () => true}},
    plugins: [emailOTP({sendVerificationOTP: send}), twoFactor({otpOptions: {sendOTP: send}})],
  };
  if (scheduling !== "default") options.advanced = {backgroundTasks: {handler: (promise: Promise<unknown>) => {
    events.push("handler:received"); tasks.push(promise);
    if (scheduling === "handler-throw") throw new Error("handler-sync");
  }}};
  await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  const signup = await auth.api.signUpEmail({body: {name: "Background", email: "background@example.com", password: "fixture-password"}, asResponse: true});
  const cookie = signup.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
  const path = endpoint === "email-otp" ? "/email-otp/send-verification-otp" : "/two-factor/send-otp";
  const body = endpoint === "email-otp" ? {email: "background@example.com", type: "sign-in", unknown: "input"} : {unknown: "input"};
  const count = () => (database.query("select count(*) as count from verification").get() as {count: number}).count;
  const operation = (async () => {
    try {
      const response = transport === "http"
        ? await auth.handler(new Request(`http://localhost:3000/api/auth${path}`, {method: "POST", headers: {"content-type": "application/json", origin: "http://localhost:3000", cookie}, body: JSON.stringify(body)}))
        : await (endpoint === "email-otp" ? auth.api.sendVerificationOTP : auth.api.sendTwoFactorOTP)({body: body as any, headers: {cookie}, asResponse: true});
      return {status: response.status, thrown: null, body: await response.text()};
    } catch (error: any) {
      return {status: null, thrown: error.message, body: null};
    } finally { responseDone = true; events.push("response"); }
  })();
  await entered.promise;
  const storedBeforeRelease = count();
  const asynchronous = sender === "resolve" || sender === "reject";
  if (asynchronous && scheduling !== "default") await operation;
  else await new Promise<void>(resolve => setTimeout(resolve, 0));
  const respondedBeforeRelease = responseDone;
  events.push("gate:release"); gate.resolve();
  const outcome = await operation;
  await finished.promise;
  const taskStates = (await Promise.allSettled(tasks)).map(result => result.status);
  await new Promise<void>(resolve => setTimeout(resolve, 0));
  const storedAfterResponse = count();
  database.close();
  return {endpoint, transport, scheduling, sender, respondedBeforeRelease, storedBeforeRelease, storedAfterResponse,
    outcome, events, logs, contexts, taskStates};
}
