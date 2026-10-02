import { expect, test } from "bun:test";
import { captureUserDisplayQuery } from "./user-display-query";

const expected = await Bun.file(new URL("../../../tests/fixtures/user-display-query-1.7.6.json", import.meta.url)).json();
const captured = await captureUserDisplayQuery();

test("declared User display queries project one page before an unpaged count", () => {
  expect(captured.version).toBe("1.7.6");
  expect(captured.backends.map(({ backend, queries }) => ({ backend, names: queries.map(({ name }) => name) }))).toStrictEqual(
    ["memory", "sqlite"].map((backend) => ({ backend, names: [
      "logical-label", "physical-label", "pre-transform-label", "numeric-string",
      "numeric-string-in", "boolean-string", "paginated-total",
    ] })),
  );
  expect(captured).toStrictEqual(expected);
});
