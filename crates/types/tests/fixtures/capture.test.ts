import { expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import captures from "./core_auth_responses.json";

test("capture records both runtimes after starting its own reference server", async () => {
  const directory = await mkdtemp(join(tmpdir(), "better-auth-types-capture-"));
  const output = join(directory, "responses.json");
  const reservation = Bun.serve({ port: 0, fetch: () => new Response(null) });
  const port = reservation.port;
  reservation.stop(true);
  const capture = Bun.spawn([process.execPath, `${import.meta.dir}/capture.ts`, output], {
    env: { ...process.env, TYPES_FIXTURE_PORT: String(port) },
    stdout: "pipe",
    stderr: "pipe",
  });
  try {
    const [code, stdout, stderr] = await Promise.all([
      capture.exited,
      new Response(capture.stdout).text(),
      new Response(capture.stderr).text(),
    ]);
    expect(code, `${stdout}\n${stderr}`).toBe(0);
    const recorded: typeof captures = JSON.parse(await readFile(output, "utf8"));
    expect(recorded.map((entry) => entry.version)).toEqual(captures.map((entry) => entry.version));
    for (const entry of recorded) {
      expect(entry.signup.user).toEqual(entry.getSession.user);
      expect(entry.signup.token).toBe(entry.getSession.session.token);
      expect(entry.getSession.session.userId).toBe(entry.signup.user.id);
      expect(entry.unauthenticatedGetSession).toBeNull();
    }
  } finally {
    capture.kill();
    await capture.exited;
    await rm(directory, { recursive: true, force: true });
  }
}, 15_000);

test("capture rejects an occupied port without contacting the existing server", async () => {
  const directory = await mkdtemp(join(tmpdir(), "better-auth-types-capture-"));
  const output = join(directory, "responses.json");
  const original = "existing fixture must not be overwritten\n";
  await writeFile(output, original);
  let requests = 0;
  const fixture = captures[1];
  const existing = Bun.serve({
    port: 0,
    fetch(request) {
      requests++;
      switch (new URL(request.url).pathname) {
        case "/__health":
          return Response.json({ ok: true });
        case "/api/auth/sign-up/email":
          return Response.json(fixture.signup, {
            headers: { "set-cookie": "better-auth.session_token=fixture-session-token; Path=/" },
          });
        case "/api/auth/get-session":
          return Response.json(request.headers.has("cookie") ? fixture.getSession : null);
        default:
          return new Response(null, { status: 404 });
      }
    },
  });
  const capture = Bun.spawn([process.execPath, `${import.meta.dir}/capture.ts`, output], {
    env: { ...process.env, TYPES_FIXTURE_PORT: String(existing.port) },
    stdout: "pipe",
    stderr: "pipe",
  });
  try {
    const [code, stdout, stderr] = await Promise.all([
      capture.exited,
      new Response(capture.stdout).text(),
      new Response(capture.stderr).text(),
    ]);
    expect(code, `${stdout}\n${stderr}`).not.toBe(0);
    expect(requests).toBe(0);
    expect(await readFile(output, "utf8")).toBe(original);
  } finally {
    capture.kill();
    await capture.exited;
    existing.stop(true);
    await rm(directory, { recursive: true, force: true });
  }
}, 15_000);
