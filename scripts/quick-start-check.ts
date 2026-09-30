import assert from "node:assert/strict";
import { copyFile, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const guide = await Bun.file(
  join(root, "docs/content/docs/quick-start.mdx"),
).text();
const app = await mkdtemp(join(tmpdir(), "better-auth-quick-start-"));
const listener = Bun.serve({ port: 0, fetch: () => new Response() });
const port = listener.port;
listener.stop(true);
const address = (text: string) => text.replaceAll(":3000", `:${port}`);
const target = resolve(root, process.env.CARGO_TARGET_DIR ?? "target");

async function run(command: string[], cwd = root, env = process.env) {
  const child = Bun.spawn(command, {
    cwd,
    env,
    stdout: "pipe",
    stderr: "inherit",
  });
  const [code, output] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
  ]);
  assert.equal(code, 0, `${command[0]} failed:\n${output}`);
  return output;
}

let server: ReturnType<typeof Bun.spawn> | undefined;
try {
  const dependencies = guide.match(/```toml[^\n]*\n([\s\S]*?)```/)?.[1];
  const source = guide.match(
    /```rust title="src\/main.rs"\n([\s\S]*?)```/,
  )?.[1];
  assert(dependencies, "quick-start must contain Cargo.toml dependencies");
  assert(source, "quick-start must contain the complete src/main.rs");
  const localDependencies = dependencies.replace(
    'git = "https://github.com/better-auth-rs/better-auth-rs", branch = "master"',
    `path = ${JSON.stringify(root)}`,
  );
  assert.notEqual(
    localDependencies,
    dependencies,
    "test the local better-auth source",
  );
  await mkdir(join(app, "src"));
  await Bun.write(
    join(app, "Cargo.toml"),
    `[package]\nname = "better-auth-quick-start"\nversion = "0.0.0"\nedition = "2024"\n\n[workspace]\n\n${localDependencies}`,
  );
  await Bun.write(join(app, "src/main.rs"), address(source));
  // Seed dependency versions from the checked-in consumer; Cargo updates only the temporary lock.
  await copyFile(
    join(root, "compat-tests/schema-consumer/Cargo.lock"),
    join(app, "Cargo.lock"),
  );
  await run([
    "cargo",
    "run",
    "--locked",
    "-p",
    "better-auth-cli",
    "--",
    "generate",
    "--output",
    join(app, "src/auth_schema.rs"),
  ]);
  await run([
    "cargo",
    "build",
    "--manifest-path",
    join(app, "Cargo.toml"),
    "--target-dir",
    target,
  ]);
  server = Bun.spawn([join(target, "debug/better-auth-quick-start")], {
    cwd: app,
    env: {
      ...process.env,
      AUTH_SECRET: "quick-start-test-secret-at-least-32-characters",
    },
    stdout: "inherit",
    stderr: "inherit",
  });
  let ready = false;
  for (let attempt = 0; attempt < 600; attempt++) {
    assert.equal(
      server.exitCode,
      null,
      "quick-start server exited before readiness",
    );
    try {
      await fetch(`http://localhost:${port}/auth/get-session`);
      ready = true;
      break;
    } catch (error) {
      if (
        !(error instanceof Error) ||
        !("code" in error) ||
        error.code !== "ConnectionRefused"
      ) {
        throw error;
      }
      await Bun.sleep(100);
    }
  }
  assert(ready, "quick-start server did not start within 60 seconds");
  const commands = guide
    .slice(guide.indexOf("## Register and sign in"))
    .match(/^curl(?:[^\n]*\\\n)*[^\n]*/gm);
  assert(commands, "quick-start must contain curl commands");
  assert.equal(
    commands.length,
    3,
    "quick-start must register, sign in, and get the session",
  );
  const responses = [];
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    COOKIE_JAR: join(app, "cookies"),
  };
  for (const command of commands) {
    const response = JSON.parse(
      await run(["sh", "-c", address(command)], app, env),
    );
    responses.push(response);
    if (typeof response?.token === "string") env.SESSION_TOKEN = response.token;
  }
  const [signup, signin, session] = responses;
  assert(signup.user?.id, "registration must return a user");
  assert.equal(signin.user?.id, signup.user.id);
  assert.equal(
    session?.user?.id,
    signup.user.id,
    "documented authentication must return the signed-in user",
  );
  assert(
    session?.session?.id,
    "documented authentication must return a session",
  );
  console.log(
    "Quick-start source and curl examples passed with the default cookie configuration.",
  );
} finally {
  server?.kill();
  if (server) await server.exited;
  await rm(app, { recursive: true, force: true });
}
