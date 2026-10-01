import { fixture, runWithTransaction, type Mode, type Model } from "./account-verification-fixture";

type Input = { mode: Mode; model: Model; scenario: string; fault?: string; transaction?: string };
const fields = (value: any) => value == null ? null : Object.fromEntries(
  ["label", "hidden", "protected", "value"].filter(key => Object.hasOwn(value, key)).map(key => [key, value[key]]));

export async function runAccountVerificationFields(input: Input) {
  const f = await fixture(input.mode);
  const output: Record<string, any> = {};
  const snapshot = () => { const state = f.snapshot(); return { ...state, cached: fields(state.cached) }; };
  const checkpoint = (name: string, value?: any) => { output[name] = { value: fields(value), state: snapshot() }; };
  const capture = async (action: () => Promise<any>) => {
    try { const value = await action(); return { error: null, value: fields(value) }; }
    catch (error) { return { error: (error as Error).message, value: null }; }
  };
  try {
    if (input.scenario === "lifecycle") {
      const created = await f.create(input.model);
      checkpoint("created", created);
      f.events.length = 0;
      checkpoint("read", await f.read(input.model));
      f.events.length = 0;
      checkpoint("updated", await f.update(input.model, created.id));
      f.events.length = 0;
      checkpoint("explicit", await f.update(input.model, created.id, { label: "explicit" }));
      checkpoint("readExplicit", await f.read(input.model));
      if (input.model === "account") {
        const listed = await f.listAccounts();
        output.listed = { status: listed.status, body: listed.body.map((value: any) => ({ ...fields(value), scopes: value.scopes,
          privateKeys: ["password", "accessToken", "refreshToken", "idToken", "accessTokenExpiresAt", "refreshTokenExpiresAt", "scope"].filter(key => key in value) })) };
      }
    } else if (input.scenario === "explicit-null") {
      checkpoint("created", await f.create(input.model, { label: null, protected: "native", hidden: "native-secret" }));
    } else if (input.scenario === "hook-fields") {
      f.control.patch = { label: "hook", hidden: "hook-secret", protected: "hook-protected" };
      checkpoint("created", await f.create(input.model, { label: "request" }));
    } else if (input.scenario === "create-error") {
      f.control.fail = `${input.model}.${input.fault}`;
      const create = () => f.create(input.model, { label: "value" });
      output.result = await capture(() => input.transaction === "outside" ? create() : runWithTransaction(f.context.adapter, async () => {
        if (input.transaction === "caught") {
          output.caught = await capture(create);
          return null;
        }
        return create();
      }));
      checkpoint("final");
    } else if (input.scenario === "after-error") {
      f.control.fail = `${input.model}.create.after`;
      output.result = await capture(() => runWithTransaction(f.context.adapter, async () => {
        const created = await f.create(input.model, { label: "value" });
        output.insideAfter = f.events.some(event => event.kind === `${input.model}.create.after`);
        return created;
      }));
      checkpoint("final");
    } else if (input.scenario === "create-rollback") {
      output.result = await capture(() => runWithTransaction(f.context.adapter, async () => {
        output.inside = fields(await f.create("verification", { label: "value", hidden: "hidden-value" }));
        output.insideAfter = f.events.some(event => event.kind === "verification.create.after");
        throw new Error("rollback requested");
      }));
      checkpoint("final");
    } else if (["update-error", "update-rollback", "update-cache-error"].includes(input.scenario)) {
      const initial = await f.create("verification", { label: "initial" });
      f.events.length = 0;
      if (input.scenario !== "update-rollback") f.control.fail = input.scenario === "update-cache-error" ? "cache.set" : `verification.${input.fault}`;
      const update = () => f.update("verification", initial.id, { label: "replacement" });
      output.result = await capture(() => input.scenario === "update-rollback" ? runWithTransaction(f.context.adapter, async () => {
        output.inside = fields(await update());
        output.insideAfter = f.events.some(event => event.kind === "verification.update.after");
        throw new Error("rollback requested");
      }) : update());
      checkpoint("final");
    } else if (input.scenario === "consume") {
      await f.create("verification", { label: "value", hidden: "consume-secret" });
      f.events.length = 0;
      checkpoint("consumed", await f.context.internalAdapter.consumeVerificationValue("code"));
      checkpoint("again", await f.context.internalAdapter.consumeVerificationValue("code"));
    } else if (input.scenario === "create-cache-error") {
      f.control.fail = "cache.set";
      const create = () => f.create("verification", { label: "value" });
      output.result = await capture(() => input.transaction === "outside" ? create() : runWithTransaction(f.context.adapter, create));
      checkpoint("final");
    } else throw new Error(`Unknown field scenario: ${input.scenario}`);
    return output;
  } finally { f.close(); }
}

export async function routeAccountVerificationFields(request: Request) {
  if (new URL(request.url).pathname !== "/__test/account-verification-fields") return null;
  return Response.json(await runAccountVerificationFields(await request.json()));
}
