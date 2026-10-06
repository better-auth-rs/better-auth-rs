const ordinaryDate = "2030-01-02T03:04:05.000Z";

export function deviceWhereScenarios() {
  const cases = [];
  const add = (name, field, stored, operator, value, extra = {}) => cases.push({ name, field, stored, operator, value, ...extra });
  for (const operator of ["eq", "ne", "lt", "lte", "gt", "gte"]) {
    for (const value of [1, 2, 3]) add(`number-${operator}-${value}`, "quantity", 2, operator, value);
  }
  for (const operator of ["contains", "starts_with", "ends_with"]) {
    add(`text-${operator}-match`, "label", "AlphaBeta", operator, operator === "ends_with" ? "Beta" : "Alpha");
    add(`text-${operator}-miss`, "label", "AlphaBeta", operator, "absent");
    add(`text-${operator}-insensitive`, "label", "AlphaBeta", operator, operator === "ends_with" ? "BETA" : "ALPHA", { mode: "insensitive" });
    add(`text-${operator}-wildcard`, "label", "AlphaBeta", operator, "%");
    add(`null-${operator}`, "label", null, operator, "a");
    add(`null-${operator}-insensitive`, "label", null, operator, "a", { mode: "insensitive" });
  }
  for (const operator of ["eq", "ne", "in", "not_in"]) {
    const set = operator === "in" || operator === "not_in";
    add(`text-${operator}-insensitive`, "label", "AlphaBeta", operator, set ? ["ALPHABETA"] : "ALPHABETA", { mode: "insensitive" });
    add(`null-${operator}`, "label", null, operator, set ? [null] : null);
    add(`missing-${operator}`, "label", undefined, operator, set ? [null] : null);
    add(`date-${operator}-same-object`, "moment", new Date(ordinaryDate), operator, null, { sourceValue: set ? "returned-array" : "returned" });
    add(`date-${operator}-new-object`, "moment", new Date(ordinaryDate), operator, set ? [new Date(ordinaryDate)] : new Date(ordinaryDate));
  }
  add("number-numeric-string", "quantity", 2, "gte", " 2 ");
  add("number-mixed-candidates", "quantity", 2, "in", ["2", "invalid"]);
  add("number-string-candidates", "quantity", 2, "in", ["2", "3"]);
  add("number-nan", "quantity", 2, "ne", NaN);
  add("number-infinity", "quantity", 2, "lt", Infinity);
  add("text-utf16-order", "label", "\u{10000}", "lt", "\uE000");
  add("text-lowercase-expansion", "label", "İ", "eq", "i\u0307", { mode: "insensitive" });
  add("text-underscore-pattern", "label", "ab", "contains", "a_");
  add("text-backslash-pattern", "label", "a\\b", "contains", "a\\b");
  add("text-numeric-coercion", "label", "2", "gte", 2);
  add("text-insensitive-range", "label", "Alpha", "lt", "alpha", { mode: "insensitive" });
  add("text-mixed-insensitive-candidates", "label", "Alpha", "in", ["ALPHA", null], { mode: "insensitive" });
  add("null-range", "quantity", null, "lt", 1);
  add("missing-range", "quantity", undefined, "lt", 1);
  add("null-range-value", "quantity", 2, "gt", null);
  add("boolean-string-true", "flag", true, "eq", "true");
  add("boolean-string-false", "flag", false, "eq", "false");
  add("boolean-candidates", "flag", true, "in", [true]);
  add("date-range", "moment", new Date(ordinaryDate), "gte", new Date(ordinaryDate));
  add("date-iso-string", "moment", new Date(ordinaryDate), "eq", ordinaryDate);
  add("date-invalid-query", "moment", new Date(ordinaryDate), "eq", new Date(NaN));
  add("array-contains", "labels", ["Alpha", "Beta"], "contains", "Alpha");
  add("array-insensitive-contains", "labels", ["Alpha", "Beta"], "contains", "alpha", { mode: "insensitive" });
  add("array-eq-same-object", "labels", ["Alpha", "Beta"], "eq", null, { sourceValue: "returned" });
  add("array-eq-new-object", "labels", ["Alpha", "Beta"], "eq", ["Alpha", "Beta"]);
  add("json-eq-same-object", "payload", { owner: "Alpha" }, "eq", null, { sourceValue: "returned" });
  add("json-eq-new-object", "payload", { owner: "Alpha" }, "eq", { owner: "Alpha" });
  add("serial-reference-string", "ownerRef", "owner", "eq", "owner", { serial: true, sourceValue: "owner" });
  add("serial-reference-null", "ownerRef", null, "eq", null, { serial: true });
  add("serial-reference-candidates", "ownerRef", "owner", "in", null, { serial: true, sourceValue: "owner-array" });
  add("mapped-physical-name", "label", "Alpha", "eq", "Alpha", { physical: true });
  add("transaction-text", "label", "Alpha", "eq", "ALPHA", { mode: "insensitive", transaction: true });
  add("transaction-range-miss", "quantity", 2, "lt", 1, { transaction: true });
  add("transaction-pattern-error", "label", null, "starts_with", "a", { transaction: true });
  return cases;
}
