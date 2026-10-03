import { equal, ok } from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Database } from "bun:sqlite";
import { getAdapter } from "better-auth/db/adapter";

export const timestampInput = {
  createdAt: "2030-01-02T03:04:05.000Z",
  updatedAt: "2030-01-02T03:04:06.123Z",
};

type Timestamps = { createdAt: string; updatedAt: string };
type UserDateRow = { id: string; createdAt: Date; updatedAt: Date };
type RawRow = {
  createdAt: string;
  createdAtType: string;
  updatedAt: string;
  updatedAtType: string;
};

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function publicTimestamps(value: unknown): Timestamps {
  ok(object(value), "the serialized User timestamps must be an object");
  ok(Object.hasOwn(value, "createdAt") && typeof value.createdAt === "string", "the User response requires createdAt");
  ok(Object.hasOwn(value, "updatedAt") && typeof value.updatedAt === "string", "the User response requires updatedAt");
  return { createdAt: value.createdAt, updatedAt: value.updatedAt };
}

async function consumerExecutable() {
  const artifactPath = process.env.BETTER_AUTH_TIMESTAMP_ARTIFACTS;
  ok(artifactPath, "consumer-check must provide BETTER_AUTH_TIMESTAMP_ARTIFACTS");
  const manifest = fileURLToPath(new URL("../../schema-consumer/Cargo.toml", import.meta.url));
  const executables: string[] = [];
  for (const line of (await Bun.file(artifactPath).text()).trimEnd().split("\n")) {
    const message: unknown = JSON.parse(line);
    if (object(message)
      && message.reason === "compiler-artifact"
      && message.manifest_path === manifest
      && object(message.target)
      && message.target.name === "user_timestamp_interchange"
      && Array.isArray(message.target.kind)
      && message.target.kind.includes("example")
      && typeof message.executable === "string") {
      executables.push(message.executable);
    }
  }
  equal(executables.length, 1, "Cargo must return exactly one timestamp example executable");
  const executable = executables[0];
  ok(executable, "the selected Cargo artifact must have an executable");
  return executable;
}

async function run(executable: string, arguments_: string[]): Promise<unknown> {
  const child = Bun.spawn([executable, ...arguments_], {
    stdout: "pipe",
    stderr: "inherit",
  });
  const [exit, output] = await Promise.allSettled([
    child.exited,
    new Response(child.stdout).text(),
  ]);
  if (exit.status === "rejected") throw exit.reason;
  if (output.status === "rejected") throw output.reason;
  equal(exit.value, 0, `the timestamp consumer must succeed; stdout=${output.value}`);
  return JSON.parse(output.value);
}

function raw(database: Database, id: string) {
  const row = database.query<RawRow, [string]>(
    'SELECT "createdAt", typeof("createdAt") AS "createdAtType", "updatedAt", typeof("updatedAt") AS "updatedAtType" FROM "user" WHERE "id" = ?',
  ).get(id);
  ok(row, "the raw observer must find the created User row");
  for (const name of ["createdAt", "createdAtType", "updatedAt", "updatedAtType"]) {
    ok(Object.hasOwn(row, name), `the raw observation requires ${name}`);
  }
  return {
    createdAt: { storageClass: row.createdAtType, value: row.createdAt },
    updatedAt: { storageClass: row.updatedAtType, value: row.updatedAt },
  };
}

export async function captureUserTimestampInterchange() {
  const executable = await consumerExecutable();
  const directory = await mkdtemp(join(tmpdir(), "better-auth-user-timestamps-"));
  try {
    const path = join(directory, "timestamps.sqlite");
    const created = await run(executable, ["init-write", path]);
    ok(object(created) && typeof created.id === "string", "the Rust writer must return its actual User ID");
    const rustId = created.id;
    const database = new Database(path);
    let upstream;
    try {
      const adapter = await getAdapter({
        database,
        baseURL: "http://user-timestamp-interchange.test",
        secret: "ordinary-user-timestamp-interchange-secret-at-least-32-characters",
        advanced: { database: { generateId: () => "timestamp-upstream" } },
      });
      const user = await adapter.create<{
        name: string; email: string; emailVerified: boolean; createdAt: Date; updatedAt: Date;
      }, UserDateRow>({
        model: "user",
        data: {
          name: "Timestamp Upstream",
          email: "upstream@user-timestamp-interchange.test",
          emailVerified: false,
          createdAt: new Date(timestampInput.createdAt),
          updatedAt: new Date(timestampInput.updatedAt),
        },
      });
      const ids = [user.id, rustId];
      const storedBefore = ids.map((id) => raw(database, id));
      const reads: Timestamps[] = [];
      for (const id of ids) {
        const row = await adapter.findOne<UserDateRow>({ model: "user", where: [{ field: "id", value: id }] });
        ok(row, "the upstream adapter must find the created User row");
        reads.push(publicTimestamps(JSON.parse(JSON.stringify({ createdAt: row.createdAt, updatedAt: row.updatedAt }))));
      }
      upstream = { ids, storedBefore, reads };
    } finally {
      database.close();
    }
    const rust = await run(executable, ["read", path, JSON.stringify(upstream.ids)]);
    ok(Array.isArray(rust), "the Rust reader must return timestamp observations");
    equal(rust.length, 2, "the Rust reader must return both User observations");
    const rustReads = rust.map(publicTimestamps);
    const observer = new Database(path);
    try {
      const writers = ["better-auth", "better-auth-rs"];
      return {
        version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
        database: "sqlite",
        input: timestampInput,
        rows: upstream.ids.map((id, index) => ({
          writer: writers[index],
          storedBefore: upstream.storedBefore[index],
          reads: [
            { reader: "better-auth", timestamps: upstream.reads[index] },
            { reader: "better-auth-rs", timestamps: rustReads[index] },
          ],
          storedAfter: raw(observer, id),
        })),
      };
    } finally {
      observer.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

if (import.meta.main) console.log(JSON.stringify(await captureUserTimestampInterchange(), null, 2));
