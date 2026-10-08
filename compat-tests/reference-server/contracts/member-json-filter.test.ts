import { expect, test } from "bun:test";
import { assertMemberJsonFilter, captureMemberJsonFilter } from "./member-json-filter-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/member-json-filter-1.7.6.json", import.meta.url)).json();

test("Member JSON filters preserve complete list results, counts, callbacks, storage and Memory errors", async () => {
  const diagnostics: unknown[] = [];
  try {
    const captured = await captureMemberJsonFilter({ diagnostics });
    assertMemberJsonFilter(captured, diagnostics);
    expect(captured).toStrictEqual(fixture);
  } catch (error) {
    console.error(JSON.stringify(diagnostics, null, 2));
    throw error;
  }
});
