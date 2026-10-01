import { Database } from "bun:sqlite";
import { unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { getCurrentAdapter, getCurrentAuthEndpointContext, getCurrentDBAdapterAsyncLocalStorage } from "@better-auth/core/context";
import { memoryAdapter } from "@better-auth/memory-adapter";

export type Outcome = "commit" | "rollback" | "after-hook-error";
export type Backend = "sqlite" | "memory";
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return {promise, resolve};
}
export async function transactionCase(transport: "http" | "native", scheduled: boolean, outcome: Outcome, backend: Backend = "sqlite") {
  const filename = join(tmpdir(), `background-transaction-${crypto.randomUUID()}.sqlite`);
  const database = backend === "sqlite" ? new Database(filename) : undefined;
  const observer = backend === "sqlite" ? new Database(filename) : undefined;
  const memory: Record<string, any[]> = {user: [], account: [], session: [], verification: []};
  const gate = deferred(), entered = deferred(), finishSignup = deferred(), finished = deferred();
  const events: string[] = [], phases: any[] = [], hookContexts: any[] = [], tasks: Promise<unknown>[] = [];
  let responseDone = false;
  const persistent = () => observer ? ({
    users: (observer.query("select count(*) as count from user").get() as any).count,
    accounts: (observer.query("select count(*) as count from account").get() as any).count,
    sessions: (observer.query("select count(*) as count from session").get() as any).count,
    name: (observer.query("select name from user").get() as any)?.name ?? null,
  }) : ({users: memory.user.length, accounts: memory.account.length, sessions: memory.session.length,
    name: memory.user[0]?.name ?? null});
  const attempt = async (operation: () => Promise<any>) => {
    try { const value = await operation(); return {found: !!value, name: value?.name ?? value?.user?.name ?? null, error: null}; }
    catch (error: any) { return {found: false, name: null, error: error.message}; }
  };
  const captureAfterHook = async (hook: string) => {
    const endpoint = getCurrentAuthEndpointContext();
    const adapter = await getCurrentAdapter(endpoint.context.adapter);
    const storage = await getCurrentDBAdapterAsyncLocalStorage();
    hookContexts.push({hook, baseAdapter: adapter === endpoint.context.adapter,
      transactionActive: storage.getStore()?.isTransactionActive ?? false,
      path: endpoint.path, request: !!endpoint.request, bodyName: endpoint.body.name,
      read: await attempt(() => endpoint.context.internalAdapter.findUserByEmail("transaction@example.com")),
    });
  };
  const options: any = {
    database: database ?? memoryAdapter(memory), baseURL: "http://localhost:3000", secret: "background-transaction-secret-at-least-thirty-two-characters",
    logger: {disabled: true}, rateLimit: {enabled: false},
    emailAndPassword: {enabled: true, password: {hash: async () => "fixture-hash", verify: async () => true}},
    emailVerification: {sendOnSignUp: true, sendVerificationEmail: async ({user}: any, request: Request | undefined) => {
      events.push("sender:called");
      const endpoint = getCurrentAuthEndpointContext();
      const originalAdapter = await getCurrentAdapter(endpoint.context.adapter);
      const storage = await getCurrentDBAdapterAsyncLocalStorage();
      const capture = async (phase: string, mutate: boolean) => {
        const current = getCurrentAuthEndpointContext();
        const adapter = await getCurrentAdapter(current.context.adapter);
        const pendingBefore = storage.getStore()?.pendingHooks.length ?? null;
        const item: any = {phase, sameEndpoint: endpoint === current, sameAdapter: adapter === originalAdapter,
          baseAdapter: adapter === current.context.adapter, transactionActive: storage.getStore()?.isTransactionActive,
          path: current.path, request: !!current.request, sameRequestURL: (current.request?.url ?? null) === (request?.url ?? null),
          bodyName: current.body.name, responseDone, pendingBefore,
          currentRead: await attempt(() => adapter.findOne({model: "user", where: [{field: "id", value: user.id}]})),
          internalRead: await attempt(() => current.context.internalAdapter.findUserByEmail(user.email)),
        };
        if (mutate) item.write = await attempt(() => current.context.internalAdapter.updateUser(user.id, {name: "Sender mutation"}));
        item.pendingAfter = storage.getStore()?.pendingHooks.length ?? null;
        phases.push(item);
      };
      events.push("sender:start");
      try {
        await capture("start", false);
        entered.resolve();
        await gate.promise;
        await capture("released", true);
        events.push("sender:done");
      } finally { finished.resolve(); }
    }},
    databaseHooks: {
      user: {create: {after: async () => {events.push("user:create.after"); await captureAfterHook("user:create"); if (outcome === "after-hook-error") throw new Error("after-hook-error");}},
        update: {after: async () => {events.push("user:update.after"); await captureAfterHook("user:update");}}},
      session: {create: {before: async () => {await finishSignup.promise; events.push("session:create.before"); if (outcome === "rollback") throw new Error("rollback-before-session");},
        after: async () => {events.push("session:create.after"); await captureAfterHook("session:create");}}},
    },
  };
  if (scheduled) options.advanced = {backgroundTasks: {handler: (promise: Promise<unknown>) => {events.push("handler:received"); tasks.push(promise);}}};
  if (database) await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  const body = {name: "Original", email: "transaction@example.com", password: "fixture-password"};
  const response = (async () => {
    try {
      const response = transport === "http"
        ? await auth.handler(new Request("http://localhost:3000/api/auth/sign-up/email", {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify(body)}))
        : await auth.api.signUpEmail({body, asResponse: true});
      return {status: response.status, thrown: null};
    } catch (error: any) {return {status: null, thrown: error.message};}
    finally {responseDone = true; events.push("response");}
  })();
  await entered.promise;
  const before = persistent();
  finishSignup.resolve();
  if (scheduled) await response;
  const atRelease = persistent();
  const responseBeforeRelease = responseDone;
  events.push("gate:release"); gate.resolve();
  const result = await response;
  await finished.promise;
  await Promise.all(tasks);
  const final = persistent();
  const context = await auth.$context;
  const freshRead = await attempt(() => context.internalAdapter.findUserByEmail(body.email));
  if (database && observer) { database.close(); observer.close(); await unlink(filename); }
  return {backend, transport, scheduled, outcome, result, responseBeforeRelease, before, atRelease, final, freshRead, phases, hookContexts, events};
}
