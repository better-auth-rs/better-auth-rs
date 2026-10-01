import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { jwt } from "better-auth/plugins";
import { getCurrentAdapter } from "@better-auth/core/context";
import { CompactSign, importJWK } from "jose";
import { runJwtSessionScenario } from "./jwt-session";

export function createJwtAdapterFixture(baseURL: string) {
  return { async handle(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (["/health", "/__health"].includes(path)) return Response.json({status: "ok"});
    if (path === "/__test/reset-state") return Response.json({success: true});
    if (path === "/__test/jwt-session") return Response.json(await runJwtSessionScenario(baseURL, await request.json()));
    if (path !== "/__test/jwt-adapter") return new Response(null, {status: 404});
    const input = await request.json();
    const database = new Database(":memory:");
    const events: unknown[] = [];
    let failRead = input.failure === "read", failCreate = input.failure === "create";
    function context(ctx: any) {
      return {path: ctx.path ?? null, request: !!ctx.request, headers: !!ctx.headers,
        bodyKeys: Object.keys(ctx.body ?? {}).sort(), session: !!ctx.context.session,
        newSession: !!ctx.context.newSession, ...(input.operation === "native-context" ? {
          baseURL: ctx.context.baseURL, requestURL: ctx.request?.url ?? null,
          suppliedHeader: ctx.headers?.get("x-source") ?? null,
        } : {})};
    }
    const adapter: any = {};
    if (input.adapter !== "create-only") adapter.getJwks = async (ctx: any) => {
      events.push({event: "get", context: context(ctx)});
      if (failRead) throw new Error("JWT adapter read failed");
      if (input.empty) return null;
      return (await getCurrentAdapter(ctx.context.adapter)).findMany({model: "jwks"});
    };
    if (input.adapter !== "get-only") adapter.createJwk = async (data: any, ctx: any) => {
      events.push({event: "create", fields: Object.keys(data).sort(), date: data.createdAt instanceof Date, context: context(ctx)});
      if (failCreate) throw new Error("JWT adapter create failed");
      if (input.noStore) return {...data, id: "unstored-key"};
      return (await getCurrentAdapter(ctx.context.adapter)).create({model: "jwks", data});
    };
    const options: any = {
      database, baseURL, secret: "jwt-adapter-fixture-secret-at-least-thirty-two-characters",
      logger: {disabled: true}, rateLimit: {enabled: false},
      emailAndPassword: {enabled: true, password: {hash: async () => "fixture-hash", verify: async () => true}},
      session: {cookieCache: {enabled: true, strategy: "jwt"}},
      plugins: [jwt({adapter, sessionCookieCache: input.operation === "cookie", ...(input.operation === "override" ? {
        jwt: {issuer: "registered-issuer", audience: "registered-audience", expirationTime: 2000000000},
        jwks: {keyPairConfig: {alg: "ES256"}, disablePrivateKeyEncryption: true, rotationInterval: 3600},
      } : {jwks: {disablePrivateKeyEncryption: input.operation === "verify-claims"}})})],
    };
    if (input.operation === "native-context") options.baseURL = {allowedHosts: ["*.example"], fallback: input.fallback};
    await (await getMigrations(options)).runMigrations();
    const auth = betterAuth(options);
    let output: unknown;
    try {
      if (input.operation === "discovery") {
        if (input.transport === "http") {
          const response = await auth.handler(new Request(`${baseURL}/api/auth/jwks`));
          const text = await response.text();
          output = {status: response.status, keys: text ? (JSON.parse(text).keys?.length ?? null) : null};
        } else {
          const result = await auth.api.getJwks();
          output = {status: 200, keys: result.keys.length};
        }
      } else if (input.operation === "sign") {
        const result = await auth.api.signJWT({body: {payload: {sub: "fixture-user"}}});
        output = {signed: result.token.split(".").length === 3};
      } else if (input.operation === "sign-claims") {
        const result = await auth.api.signJWT({body: {payload: input.claims}});
        output = {claims: JSON.parse(Buffer.from(result.token.split(".")[1], "base64url").toString())};
      } else if (input.operation === "native-context") {
        const result = await auth.api.signJWT({body: {payload: {sub: "user", iat: 100}}, asResponse: false,
          ...(input.request ? {request: new Request(input.request, {headers: {"x-source": "request"}})} : {}),
          ...(input.headers ? {headers: new Headers(input.headers)} : {}),
        });
        output = {claims: JSON.parse(Buffer.from(result.token.split(".")[1], "base64url").toString())};
      } else if (input.operation === "native-token") {
        const signup = await auth.api.signUpEmail({body: {name: "JWT headers", email: "jwt-headers@example.com", password: "fixture-password"}, headers: {}, asResponse: true});
        const user = await signup.json();
        const cookie = signup.headers.getSetCookie().filter(value => value.startsWith("better-auth.session_token=")).map(value => value.split(";")[0]).join("; ");
        const results = [];
        for (const [name, headers] of [
          ["omitted", undefined], ["empty", {}],
          ["lowercase", {cookie}], ["mixed-case", {Cookie: cookie}],
        ] as const) {
          const response = await auth.api.getToken({...headers === undefined ? {} : {headers}, asResponse: true});
          const body = await response.json();
          results.push({name, status: response.status, body: body.token
            ? {token: true, subjectMatches: JSON.parse(Buffer.from(body.token.split(".")[1], "base64url").toString()).sub === user.user.id}
            : body, events: events.splice(0)});
        }
        output = {signupStatus: signup.status, results};
      } else if (input.operation === "override") {
        const overrideOptions = input.overrides;
        if (input.overrideCreate) overrideOptions.adapter = {async createJwk(data: any, ctx: any) {
          events.push({event: "override-create", context: context(ctx)});
          return (await getCurrentAdapter(ctx.context.adapter)).create({model: "jwks", data});
        }};
        const {token} = await auth.api.signJWT({body: {payload: {sub: "user", iat: 100}, overrideOptions}});
        const claims = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString());
        const algorithm = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString()).alg;
        const key: any = database.query("select * from jwks").get();
        const firstEvents = events.splice(0);
        let nextClaims = null, nextFailed = false;
        try {
          const next = await auth.api.signJWT({body: {payload: {sub: "next", iat: 100}}});
          nextClaims = JSON.parse(Buffer.from(next.token.split(".")[1], "base64url").toString());
        } catch { nextFailed = true; }
        output = {claims, algorithm, encrypted: typeof JSON.parse(key.privateKey) === "string", rotating: key.expiresAt != null, firstEvents, nextClaims, nextFailed};
      } else if (input.operation === "verify") {
        const header = input.header ?? {alg: "EdDSA", kid: "missing"};
        const token = input.malformed ? "a.b" : (input.headerEncoded ?? Buffer.from(JSON.stringify(header)).toString("base64url")) + ".e30.c2ln";
        output = await auth.api.verifyJWT({body: {token}});
      } else if (input.operation === "verify-claims") {
        await auth.api.signJWT({body: {payload: {sub: "seed"}}});
        const key: any = database.query("select * from jwks").get();
        const privateKey = await importJWK(JSON.parse(key.privateKey), "EdDSA");
        const payload = {iss: baseURL, aud: baseURL, ...input.claims};
        const token = await new CompactSign(new TextEncoder().encode(JSON.stringify(payload))).setProtectedHeader({alg: "EdDSA", kid: key.id}).sign(privateKey);
        events.length = 0;
        output = {accepted: (await auth.api.verifyJWT({body: {token}})).payload !== null};
      } else if (input.operation === "cookie") {
        const body = {name: "JWT fixture", email: "jwt@example.com", password: "fixture-password"};
        const response = input.transport === "http"
          ? await auth.handler(new Request(`${baseURL}/api/auth/sign-up/email`, {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify(body)}))
          : await auth.api.signUpEmail({body, headers: new Headers(), asResponse: true});
        const cookies = response.headers.getSetCookie();
        output = {status: response.status, cache: cookies.some(value => value.startsWith("better-auth.session_data="))};
        if (input.verifyFailure && response.status === 200) {
          failRead = true; failCreate = false;
          const tokenCookie = cookies.find(value => value.startsWith("better-auth.session_token="))!;
          let cacheCookie = cookies.find(value => value.startsWith("better-auth.session_data="))!;
          if (input.verifyHeader) {
            const parts = cacheCookie.split(";")[0].slice("better-auth.session_data=".length).split(".");
            parts[0] = Buffer.from(JSON.stringify(input.verifyHeader)).toString("base64url");
            cacheCookie = `better-auth.session_data=${parts.join(".")}`;
          }
          database.run("delete from session");
          events.push({event: "verify-cookie"});
          const session = await auth.handler(new Request(`${baseURL}/api/auth/get-session`, {headers: {cookie: `${tokenCookie.split(";")[0]}; ${cacheCookie.split(";")[0]}`}}));
          output = {...output as object, verifyStatus: session.status, verifiedSession: (await session.json()) !== null};
        }
      } else throw new Error("Unknown JWT adapter operation");
    } catch (error: any) { output = {thrown: true, message: error.message}; }
    const rows = (database.query("select count(*) as count from jwks").get() as {count: number}).count;
    const result = {events, output, rows};
    database.close();
    return Response.json(result);
  }};
}
