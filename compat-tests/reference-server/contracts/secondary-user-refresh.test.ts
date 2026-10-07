import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { secondaryUserRefreshScenarios } from "./secondary-user-refresh-capture.mjs";

test("User cache refresh preserves failure boundaries, committed hooks, and surviving parallel writes", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/secondary-user-refresh-1.7.6.json", import.meta.url), "utf8"));
  expect(fixture.version).toBe("1.7.6");
  expect(fixture.cases.map((sample: { backend: string; scenario: string }) => [sample.backend, sample.scenario])).toStrictEqual(
    ["memory", "sqlite"].flatMap(backend => secondaryUserRefreshScenarios.map(scenario => [backend, scenario.name])),
  );
  const capture = fileURLToPath(new URL("secondary-user-refresh-capture.mjs", import.meta.url));
  const child = Bun.spawn([process.execPath, "--no-install", capture], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  expect({ status, stderr }).toStrictEqual({ status: 0, stderr: "" });
  expect(JSON.parse(stdout)).toStrictEqual(fixture);
}, 30_000);
