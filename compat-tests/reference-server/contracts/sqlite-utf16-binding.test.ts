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
    [[0xfeff], ""],
    [[0xfffe], ""],
    [[0xfeff, 0x41], "A"],
    [[0xfffe, 0x4100], "A"],
    [[0xfffe, 0x41], "\u{4100}"],
    [[0xfeff, 0xd800, 0x40], "\u{10040}"],
    [[0x41, 0xfeff], "A\ufeff"],
    [[0xfeff, 0xfffe], "\ufffe"],
  ] as const) {
    expect(read.get(String.fromCharCode(...units))).toEqual({ value });
  }
});

test("SQLite BOM conversion preserves the UTF-8 text bytes", () => {
  using database = new Database(":memory:");
  const read = database.query("SELECT ? AS value, hex(?) AS hex");
  for (const [input, value, hex] of [
    ["\ufeff", "", ""],
    ["\ufeffA", "A", "41"],
    ["\ufffe\u4100", "A", "41"],
    ["\ufffeA", "\u4100", "E48480"],
    ["A\ufeff", "A\ufeff", "41EFBBBF"],
    ["\ufeff\ufffe", "\ufffe", "EFBFBE"],
  ]) {
    expect(read.get(input, input)).toEqual({ value, hex });
  }
});

test("SQLite returns invalid UTF-8 with replacement characters without changing stored bytes", () => {
  using database = new Database(":memory:");
  database.exec("CREATE TABLE observations (value TEXT)");
  for (const [bytes, value] of [
    ["EDA080", "\ufffd\ufffd\ufffd"],
    ["EDB080", "\ufffd\ufffd\ufffd"],
    ["F09F98", "\ufffd"],
    ["EFBFBD", "\ufffd"],
    ["610062", "a\0b"],
  ]) {
    database.exec("DELETE FROM observations");
    database.exec(`INSERT INTO observations VALUES (CAST(X'${bytes}' AS TEXT))`);
    expect(database.query("SELECT value, hex(value) AS bytes FROM observations").get()).toEqual({ value, bytes });
  }
});
