import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";

test("SQLite UTF-16 parameters preserve Bun's surrogate pairing", () => {
  using database = new Database(":memory:");
  const read = database.query<{ value: string }, [string]>("SELECT ? AS value");
  for (const [units, value] of [
    [[0xd800, 0x40], "\u{10040}"],
    [[0xdc00, 0x41], "\u{10041}"],
    [[0xd83d, 0xde00], "\u{1f600}"],
    [[0xdfff, 0xffff], "\u{10ffff}"],
    [[0xd800, 0xd800, 0x40], "\u{10000}@"],
    [[0xd800], "\ufffd\ufffd\ufffd"],
    [[0xdc00], "\ufffd\ufffd\ufffd"],
    [[0x61, 0, 0x62], "a\0b"],
  ] as const) {
    expect(read.get(String.fromCharCode(...units))).toEqual({ value });
  }
});
