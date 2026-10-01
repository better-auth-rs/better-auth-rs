import { afterAll, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { emailOTP } from "better-auth/plugins";

const traces: unknown[] = [];
for (const rollback of [false, true]) {
  test(`scheduled override/${rollback ? "rollback" : "commit"}`, async () => {
    const database = new Database(":memory:");
    let release!: () => void, entered!: () => void;
    const gate = new Promise<void>(resolve => {release = resolve;});
    const ready = new Promise<void>(resolve => {entered = resolve;});
    const events: string[] = [], tasks: Promise<unknown>[] = [];
    const observations: unknown[] = [];
    const options: any = {
      database, baseURL: "http://localhost:3000", secret: "scheduled-override-secret-at-least-thirty-two-characters", logger: {disabled: true}, rateLimit: {enabled: false},
      emailAndPassword: {enabled: true, password: {hash: async () => "fixture-hash", verify: async () => true}},
      emailVerification: {sendOnSignUp: true},
      advanced: {backgroundTasks: {handler: (promise: Promise<unknown>) => {events.push("handler"); tasks.push(promise);}}},
      databaseHooks: {session: {create: {before: async () => {await ready; events.push("session:before"); if (rollback) throw new Error("rollback");}}},
        verification: {create: {after: () => {events.push("verification:after");}}}},
      plugins: [emailOTP({overrideDefaultEmailVerification: true, generateOTP: () => "123456", sendVerificationOTP: async (_message: any, endpoint: any) => {
        const user = await endpoint.context.internalAdapter.findUserByEmail("scheduled@example.com");
        observations.push({userFound: !!user, path: endpoint.path});
        events.push("sender:start"); entered();
        await gate; events.push("sender:released");
      }})],
    };
    await (await getMigrations(options)).runMigrations();
    const auth = betterAuth(options);
    let result: unknown;
    try {
      const response = await auth.api.signUpEmail({body: {name: "Scheduled", email: "scheduled@example.com", password: "fixture-password"}, asResponse: true});
      result = {status: response.status, thrown: null};
    } catch (error: any) {result = {status: null, thrown: error.message};}
    events.push("response");
    const count = (database.query("select count(*) as count from verification").get() as any).count;
    events.push("gate:release"); release();
    await Promise.all(tasks);
    const actual = {rollback, result, observations, events, count, tasks: tasks.length};
    traces.push(actual);
    expect(actual.tasks).toBe(3);
    expect(actual.observations).toEqual([{userFound: true, path: "/email-otp/send-verification-otp"}]);
    expect(actual.count).toBe(rollback ? 0 : 1);
    expect(actual.result).toEqual(rollback ? {status: null, thrown: "rollback"} : {status: 200, thrown: null});
    expect(events.indexOf("sender:start")).toBeLessThan(events.indexOf("session:before"));
    expect(events.indexOf("response")).toBeLessThan(events.indexOf("sender:released"));
    expect(events.filter(event => event === "verification:after")).toEqual(rollback ? [] : ["verification:after"]);
    database.close();
  });
}
afterAll(async () => {if (process.env.BACKGROUND_OTP_RESULTS) await Bun.write(`${process.env.BACKGROUND_OTP_RESULTS}/scheduled-override-results.json`, JSON.stringify(traces, null, 2));});
