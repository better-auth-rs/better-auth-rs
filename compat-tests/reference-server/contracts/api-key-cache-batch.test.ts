import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { apiKey } from "@better-auth/api-key";

type Mode = "get" | "refill";
type Slot = "get" | "hash" | "id";
const COUNT = 12;
const FIRST = Array.from({ length: 10 }, (_, index) => index);
const FINISH_ORDER = [...FIRST].reverse().concat([11, 10]);

class BatchGate {
  readonly starts: number[] = [];
  readonly finishes: number[] = [];
  readonly rows = Array.from({ length: COUNT }, () => ({
    started: Promise.withResolvers<void>(),
    finished: Promise.withResolvers<void>(),
    slots: new Map<Slot, ReturnType<typeof Promise.withResolvers<void>>>(),
    completed: 0,
  }));
  activeRows = 0;
  maximumRows = 0;
  activeCalls = 0;
  maximumCalls = 0;
  completedCalls = 0;

  constructor(readonly mode: Mode) {}

  async run<T>(index: number, slot: Slot, action: () => T): Promise<T> {
    const row = this.rows[index];
    if (row.slots.size === 0) {
      this.starts.push(index);
      this.maximumRows = Math.max(this.maximumRows, ++this.activeRows);
      row.started.resolve();
    }
    const barrier = Promise.withResolvers<void>();
    row.slots.set(slot, barrier);
    this.maximumCalls = Math.max(this.maximumCalls, ++this.activeCalls);
    try {
      await barrier.promise;
      return action();
    } finally {
      this.activeCalls--;
      this.completedCalls++;
      row.completed++;
      if (row.completed === (this.mode === "get" ? 1 : 2)) {
        this.activeRows--;
        this.finishes.push(index);
        row.finished.resolve();
      }
    }
  }

  release(index: number) {
    for (const slot of this.rows[index].slots.values()) slot.resolve();
  }

  async firstWave() {
    await Promise.all(FIRST.map(index => this.rows[index].started.promise));
    expect(this.starts).toEqual(FIRST);
    expect(this.activeRows).toBe(10);
    expect(this.maximumRows).toBe(10);
  }

  async finishReversed() {
    for (const index of FINISH_ORDER) {
      await this.rows[index].started.promise;
      this.release(index);
      await this.rows[index].finished.promise;
    }
  }
}

async function fixture(fallbackToDatabase: boolean) {
  const values = new Map<string, string>();
  const keyRows = new Map<string, number>();
  const indexWrites: { ids: string[]; completedCalls: number; activeRows: number }[] = [];
  let gate: BatchGate | undefined;
  const customStorage = {
    get(key: string) {
      const index = key.startsWith("api-key:by-id:") ? keyRows.get(key.slice("api-key:by-id:".length)) : undefined;
      if (gate?.mode === "get" && index !== undefined) {
        return gate.run(index, "get", () => values.get(key) ?? null);
      }
      return Promise.resolve(values.get(key) ?? null);
    },
    set(key: string, value: string) {
      if (gate?.mode === "refill") {
        if (key.startsWith("api-key:by-ref:")) {
          indexWrites.push({ ids: JSON.parse(value), completedCalls: gate.completedCalls, activeRows: gate.activeRows });
        } else {
          const index = keyRows.get(JSON.parse(value).id);
          if (index === undefined) throw new Error("Unexpected ordinary API key cache row");
          const slot = key.startsWith("api-key:by-id:") ? "id" : "hash";
          return gate.run(index, slot, () => { values.set(key, value); });
        }
      }
      values.set(key, value);
      return Promise.resolve();
    },
    delete(key: string) {
      values.delete(key);
      return Promise.resolve();
    },
  };
  const auth = betterAuth({
    secret: "api-key-cache-batch-contract-secret-at-least-32-characters",
    baseURL: "http://api-key-cache-batch.test",
    logger: { disabled: true },
    emailAndPassword: { enabled: true },
    plugins: [apiKey({ storage: "secondary-storage", fallbackToDatabase, customStorage, deferUpdates: false })],
  });
  const signup = await auth.api.signUpEmail({
    body: { name: "Cache Owner", email: "owner@api-key-cache-batch.test", password: "ordinary-fixture-password" },
    returnHeaders: true,
  });
  const headers = new Headers({ cookie: signup.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ") });
  const ids: string[] = [];
  const names: string[] = [];
  for (let index = 0; index < COUNT; index++) {
    const name = `Ordinary key ${String(index).padStart(2, "0")}`;
    const key = await auth.api.createApiKey({ headers, body: { name } });
    keyRows.set(key.id, index);
    ids.push(key.id);
    names.push(name);
  }
  const refKey = `api-key:by-ref:${signup.response.user.id}`;
  const list = () => auth.api.listApiKeys({ headers });
  return {
    values, ids, names, refKey, indexWrites, list,
    async arm(mode: Mode) {
      if (mode === "get" && fallbackToDatabase) await list();
      if (mode === "refill") values.clear();
      gate = new BatchGate(mode);
      return gate;
    },
  };
}

test("uses pinned Better Auth and API Key 1.7.6", async () => {
  for (const name of ["better-auth", "@better-auth/api-key", "@better-auth/core"]) {
    const packageJson = await Bun.file(`${import.meta.dir}/../node_modules/${name}/package.json`).json();
    expect(packageJson.version).toBe("1.7.6");
  }
});

for (const fallback of [false, true]) {
  test(`cached list bounds gets to 10 keys and retains index order (fallback=${fallback})`, async () => {
    const data = await fixture(fallback);
    const gate = await data.arm("get");
    const pending = data.list();
    await gate.firstWave();
    await gate.finishReversed();
    const result = await pending;
    expect(gate.maximumRows).toBe(10);
    expect(gate.maximumCalls).toBe(10);
    expect(gate.finishes).toEqual(FINISH_ORDER);
    expect(result.total).toBe(COUNT);
    expect(result.apiKeys.map(key => key.id)).toEqual(data.ids);
    expect(result.apiKeys.map(key => key.name)).toEqual(data.names);
  });
}

test("database fallback bounds refill to 10 keys and publishes the index after both writes per key", async () => {
  const data = await fixture(true);
  const gate = await data.arm("refill");
  const pending = data.list();
  await gate.firstWave();
  // Each active key has a hashed-key write and a by-id write in the pinned adapter.
  expect(gate.activeCalls).toBe(20);
  expect(data.indexWrites).toEqual([]);
  await gate.finishReversed();
  const result = await pending;
  expect(gate.maximumRows).toBe(10);
  expect(gate.maximumCalls).toBe(20);
  expect(gate.finishes).toEqual(FINISH_ORDER);
  expect(data.indexWrites).toEqual([{ ids: data.ids, completedCalls: COUNT * 2, activeRows: 0 }]);
  expect(JSON.parse(data.values.get(data.refKey)!)).toEqual(data.ids);
  expect(result.total).toBe(COUNT);
  expect(result.apiKeys.map(key => key.id)).toEqual(data.ids);
  expect(result.apiKeys.map(key => key.name)).toEqual(data.names);
});

for (const [mode, fallback] of [["get", false], ["get", true], ["refill", true]] as const) {
  test(`${mode} rejects before blocked peers finish and starts no queued keys (fallback=${fallback})`, async () => {
    const data = await fixture(fallback);
    const gate = await data.arm(mode);
    const failure = new Error(`ordinary ${mode} storage rejection`);
    const outcome = data.list().then(result => result, error => error);
    await gate.firstWave();
    gate.rows[0].slots.get(mode === "get" ? "get" : "id")!.reject(failure);
    expect(await outcome).toBe(failure);
    expect(gate.starts).toEqual(FIRST);
    expect(gate.rows[1].completed).toBe(0);
    expect(data.indexWrites).toEqual([]);
    for (const index of FIRST) gate.release(index);
    await Promise.all(FIRST.map(index => gate.rows[index].finished.promise));
    expect(gate.starts).toEqual(FIRST);
    expect(gate.finishes.toSorted((a, b) => a - b)).toEqual(FIRST);
    expect(gate.maximumRows).toBe(10);
    expect(gate.activeRows).toBe(0);
    expect(data.indexWrites).toEqual([]);
    if (mode === "refill") {
      expect(data.values.has(`api-key:by-id:${data.ids[1]}`)).toBe(true);
      expect(data.values.has(data.refKey)).toBe(false);
    }
  });
}
