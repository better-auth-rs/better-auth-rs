import { expect } from "bun:test";

export type DateOutputCase = {
  mode: "database" | "cache" | "database-cache";
  kind: "number" | "null" | "undefined" | "object" | "invalid-date";
};
export const dateCases: DateOutputCase[] = ["database", "cache", "database-cache"].flatMap(mode =>
  ["number", "null", "undefined", "object", "invalid-date"].map(kind => ({ mode, kind }) as DateOutputCase));

export async function assertDateOutput(input: DateOutputCase, invoke: (input: DateOutputCase) => Promise<any>) {
  const result = await invoke(input);
  const database = input.mode !== "cache";
  const cache = input.mode !== "database";
  const createError = input.mode === "database-cache" && ["null", "undefined", "object"].includes(input.kind);
  const cached = cache && (!database || input.kind === "number");
  expect(result).toEqual({
    createError,
    createdHasExpiry: !createError && (!database || input.kind !== "undefined"),
    createdExpiry: createError ? null : !database ? "2100-01-01T00:00:00.000Z"
      : input.kind === "number" ? 4_102_444_800_000
      : input.kind === "object" ? { unknown: true } : null,
    rowsBefore: database ? 1 : 0,
    cacheBefore: cached ? 1 : 0,
    createEvents: [...(database ? ["output"] : []), ...(cached ? ["cache.set"] : []), ...(createError ? [] : ["after"])],
    consumeFound: createError ? null : !(database && input.kind === "null"),
    rowsAfter: createError ? 1 : 0,
  });
  return result;
}
