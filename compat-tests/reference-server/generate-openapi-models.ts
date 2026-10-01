#!/usr/bin/env bun

import assert from "node:assert/strict";
import { mkdir, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { loadUpstream } from "./openapi-descriptor-source.ts";

const args = Bun.argv.slice(2);
let modules = resolve("compat-tests/reference-server/node_modules");
let output: string | undefined;
let check = false;
for (let index = 0; index < args.length; index++) {
  if (args[index] === "--modules") modules = resolve(args[++index]!);
  else if (args[index] === "--output") output = resolve(args[++index]!);
  else if (args[index] === "--check") check = true;
  else throw new Error(`Unknown argument ${args[index]}`);
}
assert.ok(output, "Pass --output PATH for the model descriptor catalog");
const upstream = await loadUpstream(modules);
const { factories, context, generator, getAuthTables, organization, plugins, apiKey, versions } = upstream;
const ctx = await context(null);
const coreTables = getAuthTables({ plugins: [], session: { storeSessionInDatabase: true }, rateLimit: { storage: "database" } });
let guardedFunctions = 0;

function guardSchema(schema: any) {
  return Object.fromEntries(Object.entries(schema).map(([model, table]: [string, any]) => [model, {
    ...table,
    fields: Object.fromEntries(Object.entries(table.fields).map(([key, field]: [string, any]) => {
      const guarded = { ...field };
      for (const name of ["defaultValue", "onUpdate"]) if (typeof guarded[name] === "function") {
        guarded[name] = upstream.forbiddenPolicy;
        guardedFunctions++;
      }
      if (guarded.transform) guarded.transform = Object.fromEntries(Object.entries(guarded.transform).map(([name, value]) => {
        if (typeof value !== "function") return [name, value];
        guardedFunctions++;
        return [name, upstream.forbiddenPolicy];
      }));
      return [key, guarded];
    })),
  }]));
}
const title = (name: string) => name.charAt(0).toUpperCase() + name.slice(1);
async function rows(schema: any, projectInput: boolean): Promise<any[]> {
  const guarded = guardSchema(schema);
  const projected = await generator(ctx, { ...ctx.options, plugins: [{ id: "model-projection", schema: guarded }] });
  const userNames = projectInput ? Object.keys(schema.user?.fields ?? {}) : [];
  const inputAliases = Object.fromEntries(userNames.map((name, index) => [`__field${index}`, { ...guarded.user.fields[name], fieldName: undefined, unique: false, index: false }]));
  const inputOptions = { ...ctx.options, plugins: [{ id: "input-projection", schema: { user: { fields: inputAliases } } }] };
  const inputDocument = userNames.length ? await generator({ ...ctx, options: inputOptions }, inputOptions) : undefined;
  const inputSchema = inputDocument?.paths["/sign-up/email"].post.requestBody.content["application/json"].schema;
  return Object.entries(schema).map(([key, table]: [string, any]) => {
    const component = projected.components.schemas[title(key)];
    return {
      key,
      fields: Object.keys(table.fields).map(name => ({
        key: name, property: component.properties[name], required: component.required.includes(name),
        ...(key === "user" && inputSchema?.properties[`__field${userNames.indexOf(name)}`] !== undefined ? {
          inputProperty: inputSchema.properties[`__field${userNames.indexOf(name)}`],
          inputRequired: inputSchema.required?.includes(`__field${userNames.indexOf(name)}`) ?? false,
        } : {}),
      })),
    };
  });
}

const groups: any[] = [];
for (const [id, factory] of factories) {
  // LastLogin's optional declaration is captured separately from its runtime condition.
  const plugin = id === "last-login-method" ? plugins.lastLoginMethod({ storeInDatabase: true }) : factory();
  const schema = id === "core" ? coreTables : plugin.schema ?? {};
  const models = await rows(schema, id !== "core");
  for (const model of models) {
    if (id === "core" && model.key === "verification") model.condition = "verification-database";
    if (id === "core" && model.key === "rateLimit") {
      model.condition = "database-rate-limit";
      model.placement = "after-plugin-models";
    }
    if (id === "organization") {
      if (["team", "teamMember"].includes(model.key)) model.condition = "organization-teams";
      if (model.key === "organizationRole") model.condition = "organization-roles";
      for (const field of model.fields) {
        if ((model.key === "session" && field.key === "activeTeamId") || (model.key === "invitation" && field.key === "teamId")) {
          field.condition = "organization-teams";
        }
      }
    }
    if (id === "last-login-method") model.condition = "last-login-database";
    if (id === "username") for (const field of model.fields) {
      if (field.key === "displayUsername") field.condition = "display-username";
    }
  }
  groups.push({ kind: id === "core" ? "core" : "plugin", id: id === "core" ? null : id, models });
}

// Reconstruct only for validation. No composed components are written to the catalog.
function compose(ids: string[], conditions: Record<string, boolean>) {
  const tables = new Map<string, Map<string, any>>();
  const included = (record: any) => !record.condition || conditions[record.condition] === true;
  const merge = (model: any) => {
    if (!included(model)) return;
    const fields = tables.get(model.key) ?? new Map();
    for (const field of model.fields) if (included(field)) fields.set(field.key, field);
    tables.set(model.key, fields);
  };
  for (const model of groups[0].models) if (!model.placement) merge(model);
  for (const id of ids) for (const model of groups.find(group => group.id === id).models) merge(model);
  for (const model of groups[0].models) if (model.placement) merge(model);
  return Object.fromEntries([...tables].map(([model, fields]) => [title(model), {
    type: "object",
    properties: { id: { type: "string", readOnly: true }, ...Object.fromEntries([...fields].map(([key, field]) => [key, field.property])) },
    required: ["id", ...[...fields].filter(([key, field]) => key !== "id" && field.required).map(([key]) => key)],
  }]));
}
const defaults = { "verification-database": true, "database-rate-limit": false, "organization-teams": true, "organization-roles": true, "last-login-database": true, "display-username": true };
let scenarios = 0;
async function compare(name: string, configured: any[], ids: string[], options: any = {}, conditions = defaults) {
  const actualOptions = { ...ctx.options, ...options, plugins: configured };
  const actual = await generator({ ...ctx, options: actualOptions }, actualOptions);
  const expected = compose(ids, conditions);
  assert.deepEqual(expected, actual.components.schemas, name);
  assert.deepEqual(Object.keys(expected), Object.keys(actual.components.schemas), `${name} model order`);
  for (const model of Object.keys(expected)) {
    assert.deepEqual(Object.keys(expected[model].properties), Object.keys(actual.components.schemas[model].properties), `${name}.${model} field order`);
  }
  const input = new Map<string, any>();
  for (const id of ids) for (const row of groups.find(group => group.id === id).models.find((model: any) => model.key === "user")?.fields ?? []) {
    if (row.condition && !conditions[row.condition]) continue;
    if (row.inputProperty !== undefined) input.set(row.key, row.inputProperty);
    else input.delete(row.key);
  }
  const projected = actual.paths["/update-user"].post.requestBody.content["application/json"].schema.properties;
  for (const [name, property] of input) assert.deepEqual(projected[name], property, `${name} input projection`);
  scenarios++;
}
for (const [id, factory] of factories) {
  const configured = id === "last-login-method" ? plugins.lastLoginMethod({ storeInDatabase: true }) : factory();
  await compare(id, configured ? [configured] : [], id === "core" ? [] : [id]);
}
const secondaryStorage = { get: upstream.forbiddenPolicy, set: upstream.forbiddenPolicy, delete: upstream.forbiddenPolicy };
await compare("secondary omits verification but keeps documented session", [], [], { secondaryStorage }, { ...defaults, "verification-database": false });
await compare("secondary stores verification", [], [], { secondaryStorage, verification: { storeInDatabase: true } });
await compare("database rate-limit is last", [organization(true, true)], ["organization"], { rateLimit: { storage: "database" } }, { ...defaults, "database-rate-limit": true });
for (const teams of [false, true]) for (const roles of [false, true]) {
  await compare(`organization teams=${teams} roles=${roles}`, [organization(teams, roles)], ["organization"], {}, { ...defaults, "organization-teams": teams, "organization-roles": roles });
}
await compare("last-login cookie only", [plugins.lastLoginMethod()], ["last-login-method"], {}, { ...defaults, "last-login-database": false });
await compare("username without display username", [plugins.username({ displayUsername: false })], ["username"], {}, { ...defaults, "display-username": false });
await compare("shared user and session fragments", [plugins.admin(), plugins.phoneNumber(), plugins.anonymous(), plugins.username(), organization(true, false)], ["admin", "phone-number", "anonymous", "username", "organization"], {}, { ...defaults, "organization-roles": false });

for (const [configuration, expectedMax, expectedWindow] of [
  [{ rateLimit: { maxRequests: 7, timeWindow: 1234 } }, 7, 1234],
  [[{ configId: "first", rateLimit: { maxRequests: 7, timeWindow: 1234 } }, { configId: "second" }], 10, 86400000],
] as const) {
  const document = await generator(ctx, { ...ctx.options, plugins: [apiKey(configuration)] });
  assert.equal(document.components.schemas.Apikey.properties.rateLimitMax.default, expectedMax);
  assert.equal(document.components.schemas.Apikey.properties.rateLimitTimeWindow.default, expectedWindow);
  scenarios++;
}
assert.equal(upstream.policyCalls(), 0);
assert.ok(guardedFunctions > 0);
assert.deepEqual(groups[0].models.find((model: any) => model.key === "user").fields.map((field: any) => field.key), ["name", "email", "emailVerified", "image", "createdAt", "updatedAt"]);

const catalog = {
  formatVersion: 1, versions, groups,
  conditions: {
    "verification-database": "!options.secondaryStorage || options.verification.storeInDatabase",
    "database-rate-limit": "options.rateLimit.storage === 'database'",
    "organization-teams": "organization.teams.enabled",
    "organization-roles": "organization.dynamicAccessControl.enabled",
    "last-login-database": "lastLoginMethod.storeInDatabase",
    "display-username": "username.displayUsername !== false",
  },
  runtimeRules: {
    session: "Always include Session: the upstream OpenAPI generator forces storeSessionInDatabase=true for schema collection.",
    order: "Merge core models, configured plugin groups in registration order, then database rateLimit. An overwritten model or field retains its first insertion position.",
    overrides: "Apply effective field policies last for each logical model. Recompute required for overridden fields; do not union a stale required set.",
    corePrecedence: "Core fields, plugin schema fields in registration order, then application additionalFields. Component projection uses logical keys, not modelName or fieldName.",
    functions: "Function defaults are already absent. Do not create stand-in UserFieldConfig factories. Project actual configured policies without executing callbacks.",
    apiKeyDefaults: [
      { model: "apikey", field: "rateLimitMax", source: "One configuration: normalized rateLimit.maxRequests; otherwise 10." },
      { model: "apikey", field: "rateLimitTimeWindow", source: "One configuration: normalized rateLimit.timeWindow; otherwise 86400000." },
    ],
    extensionFields: "Merge actual plugin-specific additions such as DeviceAuthorization grant.deviceCodeSchemaFields before schema overrides.",
  },
};
const serialized = JSON.stringify(catalog, null, 2) + "\n";
if (check) assert.equal(await readFile(output, "utf8"), serialized, `Regenerate ${output}`);
else {
  await mkdir(dirname(output), { recursive: true });
  await Bun.write(output, serialized);
}
console.log(`${check ? "Verified" : "Generated"} ${groups.length} groups, ${groups.reduce((count, group) => count + group.models.length, 0)} model fragments, ${groups.reduce((count, group) => count + group.models.reduce((sum: number, model: any) => sum + model.fields.length, 0), 0)} field rows; ${scenarios} composition scenarios passed; ${guardedFunctions} guarded functions, ${upstream.policyCalls()} calls.`);
