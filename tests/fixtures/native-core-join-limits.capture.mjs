import { capture } from "./native-core-joins.capture.mjs";

const limits = [
  ["half", 0.5],
  ["oneAndHalf", 1.5],
  ["negativeOne", -1],
  ["nan", Number.NaN],
  ["positiveInfinity", Number.POSITIVE_INFINITY],
  ["negativeInfinity", Number.NEGATIVE_INFINITY],
];

export async function captureLimits() {
  const cases = [];
  for (const backend of ["memory", "sqlite"]) {
    for (const joins of [false, true]) {
      for (const [limitKind, limit] of limits) {
        const input = { backend, joins, limitKind };
        try {
          const { limit: _jsonLimit, ...observation } = await capture(backend, joins, {
            path: "accounts", mode: "sync", limit,
          });
          cases.push({ ...input, observation });
        } catch (error) {
          cases.push({ ...input, error: {
            name: error.name, message: error.message,
            ...(error.code === undefined ? {} : { code: error.code }),
          } });
        }
      }
    }
  }
  return { version: "1.7.6", cases };
}

if (import.meta.main) console.log(JSON.stringify(await captureLimits(), null, 2));
