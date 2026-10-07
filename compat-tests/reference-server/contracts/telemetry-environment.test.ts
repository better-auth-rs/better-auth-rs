import { expect, test } from "bun:test";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

test("initialization environment metadata and suppression match the Rust fixture", () => {
  const result = Bun.spawnSync({
    cmd: [process.execPath, fileURLToPath(new URL("./telemetry-environment.mjs", import.meta.url))],
    env: { ...process.env, TELEMETRY_ENVIRONMENT_OUTPUT: "" },
    stdout: "pipe", stderr: "pipe",
  });
  expect(result.exitCode, result.stderr.toString()).toBe(0);
}, 30000);

test("CPU errors replace complete system metadata and stop later host probes", () => {
  const endpoint = "https://telemetry-cpu-error.test/capture";
  const output = process.env.TELEMETRY_CPU_ERROR_OUTPUT;
  const cases: Record<string, { exitCode: number; stdout: string; stderr: string }> = {};
  const systemKeys = ["systemPlatform", "systemRelease", "systemArchitecture", "cpuCount", "cpuModel", "cpuSpeed", "memory", "isWSL", "isDocker", "isTTY"];
  const fallback = Object.fromEntries(systemKeys.map(key => [key, null]));
  for (const mode of ["cpus", "model"]) {
    const result = Bun.spawnSync({
      cmd: [process.execPath, fileURLToPath(new URL("./telemetry-environment.mjs", import.meta.url)), "--cpu-error", mode],
      env: {
        ...process.env,
        NODE_ENV: "production",
        TEST: "",
        CF_PAGES: "1",
        BETTER_AUTH_TELEMETRY: "1",
        BETTER_AUTH_TELEMETRY_DEBUG: "",
        BETTER_AUTH_TELEMETRY_ENDPOINT: endpoint,
      },
      stdout: "pipe", stderr: "pipe",
    });
    const captured = { exitCode: result.exitCode, stdout: result.stdout.toString(), stderr: result.stderr.toString() };
    cases[mode] = captured;
    if (output) writeFileSync(output, JSON.stringify({ cases }, null, 2) + "\n");
    expect(result.exitCode, JSON.stringify(captured)).toBe(0);
    const observation = JSON.parse(captured.stdout);
    expect(observation.cpuError).toBe(mode);
    expect(observation.direct).toHaveLength(1);
    expect(observation.auth).toHaveLength(1);
    expect(observation.fetches).toEqual([endpoint]);
    for (const event of [...observation.direct, ...observation.auth]) {
      expect(event.payload.systemInfo).toEqual(fallback);
      expect(Object.keys(event.payload.systemInfo)).toEqual(systemKeys);
      expect(Object.hasOwn(event.payload.systemInfo, "deploymentVendor")).toBe(false);
    }
    const probes = mode === "cpus" ? ["cpus"] : ["cpus", "platform", "release", "arch", "model"];
    expect(observation.probes).toEqual({ direct: probes, auth: probes });
  }
}, 30000);
