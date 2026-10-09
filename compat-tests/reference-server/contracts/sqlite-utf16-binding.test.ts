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


for (const [encodingIndex, encoding] of ["UTF-8", "UTF-16le", "UTF-16be"].entries()) {
  test(`SQLite UTF-16 writes preserve ${encoding} storage and parameter affinity`, () => {
    using database = new Database(":memory:");
    database.exec(`PRAGMA encoding = '${encoding}'`);
    database.exec("CREATE TABLE observations (value TEXT)");
    expect(database.query("SELECT encoding FROM pragma_encoding").get()).toEqual({ encoding });
    const insert = database.query("INSERT INTO observations VALUES (?)");
    const update = database.query("UPDATE observations SET value = ? WHERE value = ?");
    const read = database.query("SELECT value, typeof(value) AS storage_type, hex(CAST(value AS BLOB)) AS bytes FROM observations WHERE value = ?");
    for (const [units, value, encodings] of [
      [[], "", ["", "", ""]],
      [[0xd800, 0x40], "\u{10040}", ["F0908180", "00D84000", "D8000040"]],
      [[0xdc00, 0x41], "\u{10041}", ["F0908181", "00DC4100", "DC000041"]],
      [[0xd83d, 0xde00], "\u{1f600}", ["F09F9880", "3DD800DE", "D83DDE00"]],
      [[0xdfff, 0xffff], "\u{10ffff}", ["F48FBFBF", "FFDFFFFF", "DFFFFFFF"]],
      [[0xd800, 0xd800, 0x40], "\u{10000}@", ["F090808040", "00D800D84000", "D800D8000040"]],
      [[0xd800], "\ufffd\ufffd\ufffd", ["EDA080", "00D8", "D800"]],
      [[0xdc00], "\ufffd\ufffd\ufffd", ["EDB080", "00DC", "DC00"]],
      [[0x61, 0, 0x62], "a\0b", ["610062", "610000006200", "006100000062"]],
      [[0xfeff], "", ["", "", ""]],
      [[0xfffe], "", ["", "", ""]],
      [[0xfeff, 0x41], "A", ["41", "4100", "0041"]],
      [[0xfffe, 0x4100], "A", ["41", "4100", "0041"]],
      [[0xfffe, 0x41], "\u4100", ["E48480", "0041", "4100"]],
      [[0xfeff, 0xd800, 0x40], "\u{10040}", ["F0908180", "00D84000", "D8000040"]],
      [[0x41, 0xfeff], "A\ufeff", ["41EFBBBF", "4100FFFE", "0041FEFF"]],
      [[0xfeff, 0xfffe], "\ufffe", ["EFBFBE", "FEFF", "FFFE"]],
      [[0x41, 0xfffe], "A\ufffe", ["41EFBFBE", "4100FEFF", "0041FFFE"]],
      [[0x41, 0xfffe, 0x42], "A\ufffeB", ["41EFBFBE42", "4100FEFF4200", "0041FFFE0042"]],
      [[0xffff], "\uffff", ["EFBFBF", "FFFF", "FFFF"]],
      [[0x41, 0xffff], "A\uffff", ["41EFBFBF", "4100FFFF", "0041FFFF"]],
      [[0x41, 0xffff, 0x42], "A\uffffB", ["41EFBFBF42", "4100FFFF4200", "0041FFFF0042"]],
      [[0x22, 0x41, 0xffff, 0x42, 0x22], "\"A\uffffB\"", ["2241EFBFBF4222", "22004100FFFF42002200", "00220041FFFF00420022"]],
      [[0xfffe, 0x00d8], "\ufffd\ufffd\ufffd", ["EDA080", "00D8", "D800"]],
    ] as const) {
      const input = String.fromCharCode(...units);
      const expected = { value, storage_type: "text", bytes: encodings[encodingIndex] };
      database.exec("DELETE FROM observations");
      expect(insert.run(input).changes).toBe(1);
      expect(read.get(input)).toEqual(expected);
      expect(update.run("sentinel", input).changes).toBe(1);
      expect(update.run(input, "sentinel").changes).toBe(1);
      expect(read.get(input)).toEqual(expected);
    }
    database.exec("CREATE TABLE affinities (untyped, numeric_value NUMERIC, text_value TEXT)");
    database.exec("INSERT INTO affinities VALUES (7, 7, '7')");
    const input = "\ufeff7";
    expect(database.query(`
      SELECT untyped = ? AS untyped, numeric_value = ? AS numeric_value,
             text_value = ? AS text_value, 7 = ? AS literal_number, '7' = ? AS literal_text
      FROM affinities
    `).get(input, input, input, input, input)).toEqual({
      untyped: 0,
      numeric_value: 1,
      text_value: 1,
      literal_number: 0,
      literal_text: 1,
    });
  });
}


for (const encoding of ["UTF-8", "UTF-16le", "UTF-16be"]) {
  test(`SQLite ${encoding} ID queries and complete LIKE patterns retain driver semantics`, () => {
    using database = new Database(":memory:");
    database.exec(`PRAGMA encoding = '${encoding}'`);
    database.exec("CREATE TABLE member (id TEXT, user_id TEXT, role TEXT)");
    for (const [input, value] of [["\ufeffnode", "node"], ["A\uffffB", "A\uffffB"], ["42", "42"]]) {
      database.exec("DELETE FROM member");
      database.query("INSERT INTO member (id, user_id) VALUES (?, ?)").run(input, input);
      for (const column of ["id", "user_id"]) {
        expect(database.query(`SELECT id, user_id FROM member WHERE ${column} = ?`).all(input))
          .toEqual([{ id: value, user_id: value }]);
        expect(database.query(`SELECT id, user_id FROM member WHERE ${column} IN (?, ?)`).all("missing", input))
          .toEqual([{ id: value, user_id: value }]);
      }
    }
    for (const [operator, units, actual, matches] of [
      ["contains", [0xd800], "x\u{10025}", true],
      ["contains", [0xd800], "x\u{10025}y", false],
      ["starts_with", [0xd800], "\u{10025}", true],
      ["starts_with", [0xd800], "\u{10025}x", false],
      ["ends_with", [0xd800], "x\ufffd", true],
      ["ends_with", [0xd800], "x\ufffdy", false],
      ["contains", [0xfeff, 0x41], "x\ufeffA", true],
      ["contains", [0xfeff, 0x41], "xA", false],
      ["starts_with", [0xfffe], "\u2500", true],
      ["starts_with", [0xfffe], "plain", false],
      ["starts_with", [0x5f], "x", true],
      ["starts_with", [0x5f], "", false],
      ["contains", [0x5c, 0x5f], "\\x", true],
      ["contains", [0x5c, 0x5f], "x", false],
    ] as const) {
      database.exec("DELETE FROM member");
      database.query("INSERT INTO member (id, role) VALUES ('member', ?)").run(actual);
      const value = String.fromCharCode(...units);
      const pattern = operator === "starts_with" ? `${value}%` : operator === "ends_with" ? `%${value}` : `%${value}%`;
      expect(database.query("SELECT id FROM member WHERE role LIKE ?").all(pattern))
        .toEqual(matches ? [{ id: "member" }] : []);
    }
    database.exec("CREATE TABLE device_code (scope TEXT)");
    for (const [operator, mode, units, actual, matched] of [
      ["eq", "insensitive", [0xd800, 0x41], "\u{10061}", 1],
      ["eq", "insensitive", [0xd800, 0x41], "\u{10041}", 0],
      ["in", "insensitive", [0xd800, 0x41], "\u{10061}", 1],
      ["not_in", "insensitive", [0xd800, 0x41], "\u{10061}", 0],
      ["contains", "insensitive", [0xd800], "x\u{10025}", 1],
      ["contains", "insensitive", [0xd800], "x\u{10025}y", 0],
      ["contains", "sensitive", [0xfeff, 0x41], "xA", 0],
      ["contains", "sensitive", [0xfeff, 0x41], "x\ufeffA", 1],
    ] as const) {
      database.exec("DELETE FROM device_code");
      database.query("INSERT INTO device_code VALUES (?)").run(actual);
      const value = String.fromCharCode(...units);
      const predicate = operator === "contains"
        ? mode === "insensitive" ? "LOWER(scope) LIKE LOWER(?)" : "scope LIKE ?"
        : operator === "eq" ? "LOWER(scope) = ?"
        : operator === "in" ? "LOWER(scope) IN (?)" : "LOWER(scope) NOT IN (?)";
      const parameter = operator === "contains" ? `%${value}%` : value.toLowerCase();
      expect(database.query(`SELECT ${predicate} AS matched FROM device_code`).get(parameter)).toEqual({ matched });
    }
  });
}
