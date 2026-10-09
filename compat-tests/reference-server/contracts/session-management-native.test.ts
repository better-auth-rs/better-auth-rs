import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("Session management preserves native hooks and reads the correct session authority", async () => {
  const expected = await Bun.file(new URL("../../../tests/fixtures/session-management-native-1.7.6.json", import.meta.url)).json();
  const capture = fileURLToPath(new URL("session-management-native-capture.mjs", import.meta.url));
  const child = Bun.spawn([process.execPath, "--no-install", capture], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  expect({ status, stderr }).toStrictEqual({ status: 0, stderr: "" });
  const actual = JSON.parse(stdout);
  expect(actual.version).toBe("1.7.6");
  expect(actual.cases).toHaveLength(60);
  expect(actual).toStrictEqual(expected);
}, 60_000);
