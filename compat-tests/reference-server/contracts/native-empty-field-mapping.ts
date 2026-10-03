import { ok } from "node:assert/strict";
import type { BetterAuthOptions } from "better-auth";
import { getAuthTables } from "@better-auth/core/db";
import { initGetFieldName } from "@better-auth/core/db/adapter";
import { getSchema } from "better-auth/db";
import { organization } from "better-auth/plugins";

export async function captureNativeEmptyFieldMapping() {
  const cases = [];
  for (const [name, model, field, custom] of [
    ["user-name", "user", "name", "stored_user_name"],
    ["organization-name", "organization", "name", "stored_organization_name"],
    ["verification-created-at", "verification", "createdAt", "stored_verification_created_at"],
  ] as const) {
    const views = [];
    for (const [view, alias] of [
      ["omitted", undefined], ["empty", ""], ["custom", custom], ["space", " "],
    ] as const) {
      const declaration = alias === undefined ? {} : { fields: { [field]: alias } };
      const options: BetterAuthOptions = model === "organization"
        ? { plugins: [organization({ schema: { organization: declaration } })] }
        : { [model]: declaration };
      const schema = getAuthTables(options);
      const physicalColumn = initGetFieldName({ schema, usePlural: false })({ model, field });
      const physicalSchema = getSchema(options);
      ok(Object.hasOwn(physicalSchema[schema[model].modelName].fields, physicalColumn),
        "The resolved native column exists in the physical schema");
      views.push({ view, declaration, physicalColumn });
    }
    cases.push({ name, model, field, views });
  }
  return {
    version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    cases,
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureNativeEmptyFieldMapping(), null, 2));
