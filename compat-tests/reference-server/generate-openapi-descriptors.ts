#!/usr/bin/env bun

import assert from "node:assert/strict";
import { mkdir, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { loadUpstream } from "./openapi-descriptor-source.ts";

const args = Bun.argv.slice(2);
let modules = resolve("compat-tests/reference-server/node_modules");
let output: string | undefined;
let check = false;
for (let index = 0; index < args.length; index++) {
  const arg = args[index];
  if (arg === "--modules") modules = resolve(args[++index]!);
  else if (arg === "--output") output = resolve(args[++index]!);
  else if (arg === "--check") check = true;
  else throw new Error(`Unknown argument ${arg}`);
}
assert.ok(output, "Pass --output PATH for the endpoint descriptor catalog");

const { versions, factories, context, organization, generator, getEndpoints, forbiddenPolicy, policyCalls } = await loadUpstream(modules);

function methods(endpoint: any): string[] {
  const method = endpoint.options.method;
  return Array.isArray(method) ? method : method === undefined ? [] : [method];
}
function documentMethods(methods: string[]) {
  return [...methods.filter(method => ["GET", "DELETE"].includes(method)),
    ...methods.filter(method => ["POST", "PATCH", "PUT"].includes(method))];
}
function documentPath(path: string) {
  return path.split("/").map(segment => segment.startsWith(":") ? `{${segment.slice(1)}}` : segment).join("/");
}
function json(value: any) {
  return JSON.parse(JSON.stringify(value));
}


// Synthetic routes reuse the installed generator. No schema parser or endpoint handler runs here.
async function project(ctx: any, entries: [string, any][]) {
  const endpoints: Record<string, any> = {
    standard: { path: "/__descriptor-standard", options: { method: "GET" } },
  };
  entries.forEach(([, endpoint], index) => {
    endpoints[`endpoint${index}`] = {
      path: `/__descriptor/${index}${endpoint.path ?? ""}`,
      options: {
        ...endpoint.options, method: ["GET", "POST"],
        metadata: { ...endpoint.options.metadata, SERVER_ONLY: false },
      },
    };
  });
  return await generator(ctx, { ...ctx.options, plugins: [{ id: "descriptor-projection", endpoints }] });
}

const groups: any[] = [];
let omittedStandardResponses = 0;
let validatedOperations = 0;
for (const [id, factory] of factories) {
  const plugin = factory();
  const ctx = await context(plugin);
  const base = getEndpoints(ctx, { ...ctx.options, plugins: [] }).api;
  const entries = Object.entries(id === "core" ? base : plugin.endpoints ?? {}) as [string, any][];
  const projected = await project(ctx, entries);
  const standardResponses = projected.paths["/__descriptor-standard"].get.responses;
  const actual = await generator(ctx, ctx.options);
  const descriptors = entries.map(([key, endpoint], index) => {
    const declared = endpoint.options.metadata?.openapi ?? {};
    const projection = projected.paths[documentPath(`/__descriptor/${index}${endpoint.path ?? ""}`)];
    const metadata: any = {};
    for (const name of ["description", "operationId", "tags"]) {
      if (declared[name] !== undefined) metadata[name] = json(declared[name]);
    }
    metadata.parameters = projection.get.parameters;
    if (projection.post.requestBody !== undefined) metadata.requestBody = projection.post.requestBody;
    const responses = Object.fromEntries(Object.entries(declared.responses ?? {}).filter(([status, response]) => {
      if (!isDeepStrictEqual(json(response), standardResponses[status])) return true;
      omittedStandardResponses++;
      return false;
    }));
    if (Object.keys(responses).length) metadata.responses = json(responses);
    if (endpoint.options.metadata?.SERVER_ONLY === true) metadata.serverOnly = true;
    const originalMethods = methods(endpoint);
    const descriptor = {
      key, path: endpoint.path ?? null, methods: originalMethods,
      documentMethodOrder: documentMethods(originalMethods), metadata,
    };
    const included = endpoint.path && id !== "open-api" && !metadata.serverOnly && (id === "core" || !Object.hasOwn(base, key));
    if (included) for (const method of descriptor.documentMethodOrder) {
      const operation = actual.paths[documentPath(endpoint.path)][method.toLowerCase()];
      assert.deepEqual(metadata.parameters, operation.parameters, `${id}.${key} parameters`);
      assert.deepEqual({ ...standardResponses, ...responses }, operation.responses, `${id}.${key} responses`);
      if (["POST", "PUT", "PATCH"].includes(method)) {
        const body = metadata.requestBody ?? (id === "core" ? { content: { "application/json": { schema: { type: "object", properties: {} } } } } : undefined);
        assert.deepEqual(body, operation.requestBody, `${id}.${key} requestBody`);
      }
      assert.equal(Object.hasOwn(metadata, "security"), false);
      validatedOperations++;
    }
    return descriptor;
  });
  groups.push({ kind: id === "core" ? "core" : "plugin", id: id === "core" ? null : id, endpoints: descriptors });
}

const org = groups.find(group => group.id === "organization");
const orgKeys = (teams: boolean, roles: boolean) => Object.keys(organization(teams, roles).endpoints);
const baseKeys = orgKeys(false, false);
const teamKeys = orgKeys(true, false).filter(key => !baseKeys.includes(key));
const roleKeys = orgKeys(false, true).filter(key => !baseKeys.includes(key));
assert.equal(teamKeys.length, 9);
assert.equal(roleKeys.length, 5);
assert.equal(org.endpoints.length, 37);
assert.deepEqual(groups[0].endpoints.find((endpoint: any) => endpoint.key === "getSession").documentMethodOrder, ["GET", "POST"]);
assert.ok(groups.find(group => group.id === "api-key").endpoints.find((endpoint: any) => endpoint.key === "verifyApiKey").metadata.serverOnly);
assert.equal(groups.find(group => group.id === "passkey").endpoints.length, 7);

const baselineContext = await context(null);
const baselineCore = await generator(baselineContext, baselineContext.options);
for (const featureOptions of [
  { emailAndPassword: undefined, user: {}, session: { deferSessionRefresh: false } },
  { emailAndPassword: { enabled: false }, user: { deleteUser: { enabled: false }, changeEmail: { enabled: false } } },
  { emailAndPassword: { enabled: true, disableSignUp: true }, user: { deleteUser: { enabled: true }, changeEmail: { enabled: true } }, session: { deferSessionRefresh: true } },
]) {
  const instance = await context(null, featureOptions);
  assert.deepEqual(Object.keys(getEndpoints(instance, instance.options).api), groups[0].endpoints.map((endpoint: any) => endpoint.key));
  assert.deepEqual((await generator(instance, instance.options)).paths, baselineCore.paths);
}
const disabledPaths = ["/sign-up/email", "/delete-user", "/get-session"];
const disabledContext = await context(null, { disabledPaths });
const filteredPaths = { ...baselineCore.paths };
for (const path of disabledPaths) delete filteredPaths[path];
assert.deepEqual((await generator(disabledContext, disabledContext.options)).paths, filteredPaths);

// Counter fixtures prove that document projection reads schemas without evaluating policies.
const fields = {
  factory: { type: "string", required: true, defaultValue: forbiddenPolicy },
  transformed: { type: "string", transform: { input: forbiddenPolicy, output: forbiddenPolicy } },
};
const probe = organization(true, true, Object.fromEntries(["organization", "member", "invitation", "team", "organizationRole"].map(name => [name, { additionalFields: { ...fields } }])));
const probeContext = await context(probe);
const probeEntries = Object.entries(probe.endpoints) as [string, any][];
const probeDocument = await project(probeContext, probeEntries);
assert.equal(policyCalls(), 0);

const schemaRoot = "/content/application~1json/schema";
const organizationOverlays = [
  { key: "createOrganization", model: "organization", schemaPointer: schemaRoot, mergeOrder: ["base", "additionalFields"], partial: false, source: "routes/crud-org.mjs:20" },
  { key: "updateOrganization", model: "organization", schemaPointer: `${schemaRoot}/properties/data`, mergeOrder: ["additionalFields", "base"], partial: true, source: "routes/crud-org.mjs:166" },
  { key: "createInvitation", model: "invitation", schemaPointer: schemaRoot, mergeOrder: ["base", "additionalFields"], partial: false, source: "routes/crud-invites.mjs:37" },
  { key: "addMember", model: "member", schemaPointer: schemaRoot, mergeOrder: ["base", "additionalFields"], partial: false, source: "routes/crud-members.mjs:20" },
  { key: "createTeam", model: "team", schemaPointer: schemaRoot, mergeOrder: ["base", "additionalFields"], partial: false, source: "routes/crud-team.mjs:18" },
  { key: "updateTeam", model: "team", schemaPointer: `${schemaRoot}/properties/data`, mergeOrder: ["base", "additionalFields"], partial: true, source: "routes/crud-team.mjs:216" },
  { key: "createOrgRole", model: "organizationRole", schemaPointer: `${schemaRoot}/properties/additionalFields`, mergeOrder: ["additionalFields"], partial: false, fieldPolicy: "capture-before-update-constructor", source: "routes/crud-access-control.mjs:29" },
  { key: "updateOrgRole", model: "organizationRole", schemaPointer: `${schemaRoot}/allOf/0/properties/data`, mergeOrder: ["base", "additionalFields"], partial: false, fieldPolicy: "force-required-false", source: "routes/crud-access-control.mjs:436" },
];
function pointer(value: any, path: string) {
  return path.split("/").slice(1).reduce((result, part) => result?.[part.replaceAll("~1", "/").replaceAll("~0", "~")], value);
}
const changed: string[] = [];
probeEntries.forEach(([key, endpoint], index) => {
  const body = probeDocument.paths[documentPath(`/__descriptor/${index}${endpoint.path ?? ""}`)].post.requestBody;
  const template = org.endpoints.find((descriptor: any) => descriptor.key === key).metadata.requestBody;
  if (!isDeepStrictEqual(body, template)) changed.push(key);
});
assert.deepEqual(new Set(changed), new Set(organizationOverlays.map(overlay => overlay.key)));
for (const overlay of organizationOverlays) {
  const index = probeEntries.findIndex(([key]) => key === overlay.key);
  const endpoint = probeEntries[index]![1];
  const body = probeDocument.paths[documentPath(`/__descriptor/${index}${endpoint.path ?? ""}`)].post.requestBody;
  const schema = pointer(body, overlay.schemaPointer);
  assert.ok(schema.properties.factory, `${overlay.key} additional-field target`);
  assert.equal(schema.required?.includes("factory") ?? false, !overlay.partial && overlay.fieldPolicy !== "force-required-false");
}

const catalog = {
  formatVersion: 1, versions, groups,
  organizationConditions: { "teams.enabled": teamKeys, "dynamicAccessControl.enabled": roleKeys },
};
const overlays = {
  formatVersion: 1,
  source: "better-auth/dist/plugins/organization",
  schemaSource: "better-auth/dist/db/to-zod.mjs",
  generatorSource: "better-auth/dist/plugins/open-api/generator.mjs",
  endpoints: organizationOverlays,
  fieldRules: {
    include: "field.input !== false; returned and defaults do not change the client schema",
    required: "field.required !== false, unless the endpoint applies partial",
    optional: "required:false is nullish; endpoint partial adds omission but does not add null",
    types: {
      string: { type: "string" }, number: { type: "number" }, boolean: { type: "boolean" },
      date: { type: "string" }, json: { type: "string" },
      "string[]": { type: "array", items: { type: "string" } },
      "number[]": { type: "array", items: { type: "number" } }, enum: {},
    },
    nullish: "Append null to type; without type, emit anyOf:[schema,{type:'null'}]",
    ordering: "Merge schema properties in endpoint mergeOrder. An overwritten key retains its first insertion position. Rebuild required in final property order.",
    policies: "Do not execute defaultValue, validators or transforms. Do not emit defaults from toZodSchema.",
    roleTiming: "createOrgRole captures the original policy before updateOrgRole mutates every role field.required=false. Final component models see the mutated policy.",
  },
};
for (const [path, value] of [[output, catalog], [resolve(dirname(output), "organization-overlays.json"), overlays]] as const) {
  const serialized = JSON.stringify(value, null, 2) + "\n";
  if (check) assert.equal(await readFile(path, "utf8"), serialized, `Regenerate ${path}`);
  else {
    await mkdir(dirname(path), { recursive: true });
    await Bun.write(path, serialized);
  }
}
console.log(`${check ? "Verified" : "Generated"} ${groups.length} groups, ${groups.reduce((count, group) => count + group.endpoints.length, 0)} descriptors and ${validatedOperations} projected operations; ${omittedStandardResponses} redundant standard responses removed; policy calls: ${policyCalls()}.`);
