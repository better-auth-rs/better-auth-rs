import { getAuthTables } from "@better-auth/core/db";
import { getSchema } from "better-auth/db";
import { organization } from "better-auth/plugins";

export async function captureEmptyModelName() {
  const cases = [];
  for (const model of ["user", "organization", "rateLimit"] as const) {
    const views = [];
    for (const [view, modelName] of [
      ["omitted", undefined],
      ["empty", ""],
      ["custom", `display_${model}`],
      ["space", " "],
    ] as const) {
      const declaration = modelName === undefined ? {} : { modelName };
      const options = model === "organization"
        ? { plugins: [organization({ schema: { organization: declaration } })] }
        : model === "rateLimit"
          ? { rateLimit: { storage: "database" as const, ...declaration } }
          : { user: declaration };
      const tableName = getAuthTables(options)[model].modelName;
      views.push({
        view,
        hasModelName: Object.hasOwn(declaration, "modelName"),
        modelName: modelName ?? null,
        tableName,
        schemaTableNames: Object.keys(getSchema(options)),
      });
    }
    cases.push({ model, views });
  }
  return {
    version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    cases,
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureEmptyModelName(), null, 2));
