import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

test("Member User singular joins select existing rows before output projection", async () => {
  const expected = JSON.parse(readFileSync(new URL("../../../tests/fixtures/organization-member-singular-existing-contract.json", import.meta.url), "utf8"));
  expect(expected.version).toBe("1.7.6");
  expect(expected.kind).toBe("handwritten-expectations");
  expect(expected.cases.map(value => value.name)).toEqual(["ordinary", "existing-duplicates", "missing"]);
  const scenarios = ["memory", "sqlite"].flatMap(backend => expected.cases.map(value => ({
    name: value.name,
    backends: [backend],
    userFields: expected.userFields,
    userSeeds: value.userSeeds ?? {},
    missingChild: value.missingChild ?? false,
    selected: backend === "sqlite" ? value.nativeSql : value.first,
    selectedFallback: value.first,
  })));
  const capture = fileURLToPath(new URL("organization-member-join-reference-capture.mjs", import.meta.url));
  const child = Bun.spawn([process.execPath, "--no-install", capture, "--scenarios-stdin"], {
    stdin: new Response(JSON.stringify(scenarios)), stdout: "pipe", stderr: "pipe",
  });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  expect({ status, stderr }).toEqual({ status: 0, stderr: "" });
  const captured = JSON.parse(stdout);
  expect(captured.version).toBe(expected.version);
  expect(captured.boundaries).toHaveLength(12);
  expect(captured.cases).toHaveLength(24);
  const json = value => JSON.parse(JSON.stringify(value, (_, field) => field?.type === "date" ? field.value : field));
  for (const observed of captured.cases) {
    const selection = expected.cases.find(value => value.name === observed.scenario);
    expect(selection).toBeDefined();
    expect(observed.after).toStrictEqual(observed.before);
    expect(observed.operations).toHaveLength(4);
    const selected = observed.backend === "sqlite" && observed.joins ? selection.nativeSql : selection.first;
    const user = selected === null ? null : expected.users[selected];
    const member = { ...expected.member, ...(selection.missingChild ? { ownerRef: "missing-user" } : {}) };
    for (const operation of observed.operations) {
      expect(operation.storageUnchanged).toBe(true);
      if (!observed.populated) {
        expect(operation.returned).toBe(true);
        expect(operation.result).toBeNull();
        expect(operation.json).toBeNull();
        expect(operation.events.filter(event => event[0] === "output")).toStrictEqual([]);
        continue;
      }
      const callbacks = [
        ...["role", "label", "detail", "ownerRef"].map(name => ["output", `member.${name}`, member[name]]),
        ...(user === null ? [] : ["name", "image", "memberRef"].map(name => ["output", `user.${name}`, user[name]])),
      ];
      const queries = [["query", "findOne", "member"]];
      expect(operation.events).toStrictEqual(observed.joins ? [...queries, ...callbacks] : [
        ...queries, ...callbacks.slice(0, 4), ["query", "findOne", "user"], ...callbacks.slice(4),
      ]);
      if (user === null && operation.surface === "organization") {
        if (operation.path === "by-id") {
          expect(operation.returned).toBe(false);
          expect(operation.error).toStrictEqual({
            name: "TypeError", message: "null is not an object (evaluating 'user.id')",
            sameCallbackError: false, properties: {}, keys: [],
          });
        } else {
          expect(operation.returned).toBe(true);
          expect(operation.result).toBeNull();
          expect(operation.json).toBeNull();
        }
        continue;
      }
      const child = user === null || operation.surface === "adapter"
        ? user : Object.fromEntries(["id", "name", "email", "image"].map(name => [name, user[name]]));
      const result = { ...member, user: child };
      expect(operation.returned).toBe(true);
      expect(operation.result).toStrictEqual(result);
      expect(operation.json).toStrictEqual(json(result));
    }
  }
}, 60_000);
