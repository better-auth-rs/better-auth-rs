import { capture } from "./organization-native-joins.capture";

const observations = [];
for (const backend of ["memory", "sqlite"]) for (const joins of [false, true]) {
  observations.push(await capture(backend, joins, {
    path: "organizations", mode: "parent-read", limit: 2, unconfiguredLogo: true,
  }));
}
console.log(JSON.stringify({ version: "1.7.6", cases: observations }, null, 2));
