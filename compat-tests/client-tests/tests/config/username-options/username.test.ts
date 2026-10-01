import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

const profile = process.env.COMPAT_PROFILE!;
const layered = profile.startsWith("username-order-");
const post = profile === "username-order-post";
const pre = profile === "username-order-pre";
const password = "Password123!";
const control = async (ctx: any, body?: unknown) => (await fetch(`${ctx.baseURL}/__test/username`, body === undefined ? undefined : {
  method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
})).json();
const signup = (ctx: any, actor: string, email: string, fields: Record<string, unknown>) => ctx.rawRequest({
  actor, path: "/api/auth/sign-up/email", method: "POST", json: { email, name: actor, password, ...fields },
});
const native = async (ctx: any, actor: string, input: unknown) => {
  const response = await ctx.rawRequest({ actor, path: "/__test/username/native", method: "POST", json: input });
  expect(response.status).toBe(200);
  return response.body as any;
};

if (layered) {
  compatScenario("username layered signup and lookup preserve configured validation order", async ctx => {
    const email = ctx.uniqueEmail("layered");
    const created = await signup(ctx, "owner", email, { username: "ABC", displayUsername: "Fancy" });
    expect(created.status).toBe(200);
    expect((created.body as any).user.username).toBe("nnnABC");
    expect((created.body as any).user.displayUsername).toBe("dddFancy");
    const state = await control(ctx);
    expect(state.calls).toEqual([
      ...(post ? ["normalize:ABC", "validate:nABC"] : ["validate:ABC"]),
      "normalize:ABC", ...(post ? ["display:Fancy"] : []),
      "normalize:ABC", "display:Fancy", "normalize:nABC", "display:dFancy", "normalize:nnABC", "display:ddFancy",
    ]);
    expect(state.rows).toEqual([{ email, username: "nnnABC", displayUsername: "dddFancy" }]);
    expect(state.schema).toEqual({ username: true, displayUsername: true, mapped: post });
    const observations: unknown[] = [{ created, state }];
    await control(ctx, {});
    const available = await ctx.rawRequest({ path: "/api/auth/is-username-available", method: "POST", json: { username: "ABC" } });
    expect(available.body).toEqual({ available: true });
    const availability = await control(ctx);
    expect(availability.calls).toEqual(["validate:ABC", "normalize:ABC"]);
    observations.push({ available, availability });
    await control(ctx, {});
    const denied = await ctx.rawRequest({ path: "/api/auth/sign-in/username", method: "POST", json: { username: "ABC", password } });
    expect(denied.status).toBe(401);
    expect((denied.body as any).code).toBe("INVALID_USERNAME_OR_PASSWORD");
    const deniedState = await control(ctx);
    expect(deniedState.calls).toEqual(pre ? ["normalize:ABC", "validate:nABC", "normalize:nABC"] : ["validate:ABC", "normalize:ABC"]);
    observations.push({ denied, deniedState });
    await control(ctx, {});
    const loginInput = pre ? "nABC" : "nnABC";
    const signedIn = await ctx.rawRequest({ actor: "login", path: "/api/auth/sign-in/username", method: "POST", json: { username: loginInput, password } });
    expect(signedIn.status).toBe(200);
    expect((signedIn.body as any).user.id).toBe((created.body as any).user.id);
    const loggedIn = await control(ctx);
    expect(loggedIn.calls).toEqual(pre ? ["normalize:nABC", "validate:nnABC", "normalize:nnABC"] : ["validate:nnABC", "normalize:nnABC"]);
    observations.push({ signedIn, loggedIn });
    return observations;
  });

  compatScenario("native endpoints retain endpoint hooks while direct adapter writes use database hooks", async ctx => {
    const endpoint = await native(ctx, "native", { operation: "endpoint-signup", data: {
      email: ctx.uniqueEmail("native-endpoint"), name: "Native", password, username: "ABC", displayUsername: "Fancy",
    } });
    expect(endpoint.status).toBe(200);
    expect(endpoint.body.user.username).toBe("nnnABC");
    const endpointState = await control(ctx);
    expect(endpointState.events).toEqual([{ kind: "create", path: "/sign-up/email", http: false, username: "nnABC", displayUsername: "ddFancy" }]);
    const email = ctx.uniqueEmail("direct");
    const observations: unknown[] = [{ endpoint, state: endpointState }];
    for (const [operation, input, display] of [["create", "XYZ", "Native"], ["update", "DEF", "Changed"]]) {
      await control(ctx, {});
      const result = await native(ctx, "adapter", { operation, email, data: { ...(operation === "create" ? { email, name: "Adapter" } : {}), username: input, displayUsername: display } });
      expect(result.status).toBe(200);
      expect(result.body.username).toBe(`nn${input}`);
      expect(result.body.displayUsername).toBe(`dd${display}`);
      const state = await control(ctx);
      expect(state.calls).toEqual([
        ...(post ? [`normalize:${input}`, `validate:n${input}`] : [`validate:${input}`]),
        `normalize:${input}`, `normalize:${input}`, `display:${display}`, `normalize:n${input}`, `display:d${display}`,
      ]);
      expect(state.events).toEqual([{ kind: operation, path: null, http: false,
        username: operation === "create" ? `n${input}` : input,
        displayUsername: operation === "create" ? `d${display}` : display,
      }]);
      observations.push({ result, state });
    }
    await control(ctx, { echoUpdate: true });
    const overwritten = await native(ctx, "adapter", { operation: "update", email, data: { username: "GHI", displayUsername: "Echo" } });
    expect(overwritten.status).toBe(200);
    expect(overwritten.body.username).toBe("nGHI");
    expect(overwritten.body.displayUsername).toBe("dEcho");
    const overwrittenState = await control(ctx);
    expect(overwrittenState.calls).toEqual([
      ...(post ? ["normalize:GHI", "validate:nGHI"] : ["validate:GHI"]),
      "normalize:GHI", "normalize:GHI", "display:Echo", "normalize:GHI", "display:Echo",
    ]);
    observations.push({ overwritten, state: overwrittenState });
    return observations;
  });

  compatScenario("asynchronous username rejection preserves endpoint status and prevents writes", async ctx => {
    const observations: unknown[] = [];
    for (const mode of ["deny", "error"]) {
      for (const kind of ["signup", "native-signup", "adapter", "availability", "signin"]) {
        await control(ctx, { validator: mode });
        const data = { email: ctx.uniqueEmail(`${mode}-${kind}`), name: "Denied", password, username: "Rejected", displayUsername: "Display" };
        const result = kind === "signup" ? await signup(ctx, kind, data.email, data)
          : kind === "native-signup" ? await native(ctx, kind, { operation: "endpoint-signup", data })
          : kind === "adapter" ? await native(ctx, kind, { operation: "create", data })
          : await ctx.rawRequest({ path: kind === "availability" ? "/api/auth/is-username-available" : "/api/auth/sign-in/username", method: "POST", json: { username: "Rejected", password } });
        expect(result.status).toBe(mode === "error" ? 403 : ["availability", "signin"].includes(kind) ? 422 : 400);
        expect((result.body as any).code).toBe(mode === "error" ? "USERNAME_CALLBACK_REJECTED" : "INVALID_USERNAME");
        const state = await control(ctx);
        expect(state.users).toEqual([]);
        expect(state.rows).toEqual([]);
        expect(state.events).toEqual([]);
        expect(state.calls.filter((call: string) => call.startsWith("validate:"))).toHaveLength(1);
        observations.push({ kind, mode, result, state });
      }
    }
    return observations;
  });
}

if (profile === "username-normalization-disabled") {
  compatScenario("disabled normalization preserves independent case-sensitive usernames", async ctx => {
    const observations: unknown[] = [];
    for (const [actor, username] of [["upper", "Mixed_User"], ["lower", "mixed_user"]]) {
      const created = await signup(ctx, actor, ctx.uniqueEmail(actor), { username });
      expect(created.status).toBe(200);
      expect((created.body as any).user.username).toBe(username);
      expect((created.body as any).user.displayUsername).toBe(username);
      const available = await ctx.rawRequest({ path: "/api/auth/is-username-available", method: "POST", json: { username } });
      expect(available.body).toEqual({ available: false });
      const signedIn = await ctx.rawRequest({ actor: `${actor}-login`, path: "/api/auth/sign-in/username", method: "POST", json: { username, password } });
      expect(signedIn.status).toBe(200);
      expect((signedIn.body as any).user.id).toBe((created.body as any).user.id);
      observations.push({ created, available, signedIn });
    }
    const wrongCase = await ctx.rawRequest({ path: "/api/auth/sign-in/username", method: "POST", json: { username: "MIXED_USER", password } });
    expect(wrongCase.status).toBe(401);
    const updated = await ctx.rawRequest({ actor: "upper", path: "/api/auth/update-user", method: "POST", json: { username: "New_Case", displayUsername: " My Display " } });
    expect(updated.status).toBe(200);
    const state = await control(ctx);
    expect(state.rows.map((row: any) => row.username)).toEqual(["New_Case", "mixed_user"]);
    expect(state.rows[0].displayUsername).toBe(" My Display ");
    return { observations, wrongCase, updated, state };
  });
}

if (profile === "username-no-display") {
  compatScenario("displayUsername false removes storage and output but preserves display-only signup inference", async ctx => {
    const email = ctx.uniqueEmail("no-display");
    const created = await signup(ctx, "owner", email, { displayUsername: "Mixed_User" });
    expect(created.status).toBe(200);
    expect((created.body as any).user.username).toBe("mixed_user");
    expect((created.body as any).user).not.toHaveProperty("displayUsername");
    const updated = await ctx.rawRequest({ actor: "owner", path: "/api/auth/update-user", method: "POST", json: { username: "Next_User", displayUsername: "Discarded" } });
    expect(updated.status).toBe(200);
    const session = await ctx.rawRequest({ actor: "owner", path: "/api/auth/get-session" });
    expect((session.body as any).user.username).toBe("next_user");
    expect((session.body as any).user).not.toHaveProperty("displayUsername");
    const direct = await native(ctx, "adapter", { operation: "create", data: { email: ctx.uniqueEmail("direct-no-display"), name: "Adapter", username: "Server_User", displayUsername: "Discarded" } });
    expect(direct.status).toBe(200);
    expect(direct.body.username).toBe("server_user");
    expect(direct.body).not.toHaveProperty("displayUsername");
    const state = await control(ctx);
    expect(state.schema).toEqual({ username: true, displayUsername: false, mapped: false });
    expect(state.users.every((row: any) => !("displayUsername" in row))).toBe(true);
    expect(state.rows.every((row: any) => !("displayUsername" in row))).toBe(true);
    return { created, updated, session, direct, state };
  });
}

if (profile === "username-immutable-validation") {
  compatScenario("immutable usernames constrain HTTP and native endpoints but not direct adapter updates", async ctx => {
    const email = ctx.uniqueEmail("immutable");
    const created = await signup(ctx, "owner", email, { username: "First", displayUsername: " First " });
    expect(created.status).toBe(200);
    expect((created.body as any).user.displayUsername).toBe("First");
    const http = await ctx.rawRequest({ actor: "owner", path: "/api/auth/update-user", method: "POST", json: { username: "Next" } });
    expect(http.status).toBe(400);
    expect((http.body as any).code).toBe("USERNAME_IS_IMMUTABLE");
    const api = await native(ctx, "owner", { operation: "endpoint-update", data: { username: "Next" } });
    expect(api.status).toBe(400);
    expect(api.body.code).toBe("USERNAME_IS_IMMUTABLE");
    const direct = await native(ctx, "adapter", { operation: "update", email, data: { username: "Next" } });
    expect(direct.status).toBe(200);
    expect(direct.body.username).toBe("next");
    const sameDirect = await native(ctx, "adapter", { operation: "update", email, data: { username: "next" } });
    expect(sameDirect.status).toBe(400);
    expect(sameDirect.body.code).toBe("USERNAME_IS_ALREADY_TAKEN");
    const sameApi = await native(ctx, "owner", { operation: "endpoint-update", data: { username: "next" } });
    expect(sameApi.status).toBe(200);
    const state = await control(ctx);
    expect(state.rows[0].username).toBe("next");
    return { created, http, api, direct, sameDirect, sameApi, state };
  });

  compatScenario("username length uses UTF-16 and fractional limits before awaiting validators", async ctx => {
    const observations: unknown[] = [];
    for (const [index, value, status, code] of [[0, "abc", 400, "USERNAME_TOO_SHORT"], [1, "abcdefg", 400, "USERNAME_TOO_LONG"], [2, "😀😀", 200, null], [3, "abcdef", 200, null]] as const) {
      await control(ctx, {});
      const result = await signup(ctx, `length-${index}`, ctx.uniqueEmail(`length-${index}`), { username: value });
      expect(result.status).toBe(status);
      const state = await control(ctx);
      if (code) {
        expect((result.body as any).code).toBe(code);
        expect(state.calls).toEqual([]);
      } else {
        expect((result.body as any).user.username).toBe(value);
        expect(state.calls.filter((call: string) => call.startsWith("validate:"))).toEqual([`validate:${value}`]);
      }
      observations.push({ result, state });
    }
    return observations;
  });

  compatScenario("asynchronous display validation receives normalized input and fails before persistence", async ctx => {
    const observations: unknown[] = [];
    for (const mode of ["deny", "error"]) {
      await control(ctx, { displayValidator: mode });
      const result = await signup(ctx, mode, ctx.uniqueEmail(mode), { username: "Fresh", displayUsername: " Display " });
      expect(result.status).toBe(mode === "deny" ? 400 : 403);
      expect((result.body as any).code).toBe(mode === "deny" ? "INVALID_DISPLAY_USERNAME" : "USERNAME_CALLBACK_REJECTED");
      const state = await control(ctx);
      expect(state.calls).toEqual(["validate:Fresh", "display: Display ", "display-validate:Display"]);
      expect(state.rows).toEqual([]);
      expect(state.events).toEqual([]);
      observations.push({ result, state });
    }
    return observations;
  });

  compatScenario("nullable username updates and empty direct creates preserve truthy hook guards", async ctx => {
    const email = ctx.uniqueEmail("nullable");
    const created = await signup(ctx, "owner", email, { username: "First", displayUsername: "Display" });
    expect(created.status).toBe(200);
    const cleared = await native(ctx, "owner", { operation: "endpoint-update", data: { username: null, displayUsername: null } });
    expect(cleared.status).toBe(200);
    const empty = await native(ctx, "adapter", { operation: "create", data: { email: ctx.uniqueEmail("empty"), name: "Empty", username: "" } });
    expect(empty.status).toBe(200);
    expect(empty.body.username).toBe("");
    const state = await control(ctx);
    expect(state.rows[0].username).toBeNull();
    expect(state.rows[0].displayUsername).toBeNull();
    expect(state.rows[1].username).toBe("");
    return { created, cleared, empty, state };
  });
}
