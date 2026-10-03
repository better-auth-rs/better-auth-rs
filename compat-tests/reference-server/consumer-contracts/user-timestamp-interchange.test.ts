import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/user-timestamp-writer-format-1.7.6.json";
import { captureUserTimestampInterchange, timestampInput } from "./user-timestamp-interchange";

test("ordinary User timestamps remain readable across both SQLite adapters", async () => {
  const actual = await captureUserTimestampInterchange();
  expect(actual).toStrictEqual(expected);
  for (const row of actual.rows) {
    expect(row.storedAfter).toStrictEqual(row.storedBefore);
    for (const read of row.reads) {
      expect(read.timestamps).toStrictEqual(timestampInput);
    }
  }
  expect(actual.rows[0].storedBefore).toStrictEqual(actual.rows[1].storedBefore);
  expect(actual.rows[0].storedAfter).toStrictEqual(actual.rows[1].storedAfter);
});
