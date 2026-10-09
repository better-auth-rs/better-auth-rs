import { expect, test } from "bun:test";
import type { DBFieldAttribute } from "@better-auth/core/db";
import type { BetterAuthOptions } from "better-auth";
import { date, row as account, setup, type Fields } from "./account-id-input-support";

const collision = "stored-parent-property";
const user = (id: string, name: string): Fields => ({
  id, name, email: `${id}@native-join-property-collision.test`, emailVerified: true,
  image: null, createdAt: date(0), updatedAt: date(0),
});

async function check(many: boolean, alias: boolean, joins: boolean, reject: boolean, missing = false) {
  const fixture = await setup("memory");
  try {
    const childModel = many ? "account" : "user";
    const parentModel = many ? "user" : "account";
    const physical = alias ? `linked_${childModel}` : childModel;
    const parentId = many ? "joined-owner" : "parent-account";
    const childId = many ? "child-account" : "joined-owner";
    const valueField = many ? "accessToken" : "name";
    const fields: Record<string, DBFieldAttribute> = {
      [physical]: { type: "string" },
      relationMirror: { type: "string", fieldName: physical },
    };
    const options: BetterAuthOptions = {
      advanced: { database: { joins } },
      user: many ? { additionalFields: fields } : { modelName: physical },
      account: many ? { modelName: physical } : { additionalFields: fields },
    };
    const writer = (await fixture.reader(options, [])).context.adapter;
    const create = (model: string, data: Fields) => writer.create({ model, data, forceAllowId: true });
    const parentData = {
      ...(many ? user(parentId, "Parent") : { ...account(parentId), userId: childId }),
      [physical]: collision,
    };
    const selected = missing ? [] : many ? [
      { ...account(childId, "first", "Before"), userId: parentId },
      { ...account("second-account", "second", "Second"), userId: parentId },
    ] : [user(childId, "Before")];
    // An unrelated row keeps an aliased Memory table present when the relationship is empty.
    await create(childModel, many ? account("unrelated-account", "unrelated", "Unrelated") : user("unrelated-user", "Unrelated"));
    await create(parentModel, parentData);
    for (const child of selected) await create(childModel, child);
    const where = [{ field: "id", value: parentId }];
    const beforeParent = await writer.findOne({ model: parentModel, where });
    const beforeChildren = await writer.findMany({ model: childModel });
    const beforeAccounts = structuredClone(fixture.storage());
    const changed = selected.map((child, index) => index === 0
      ? { ...child, [valueField]: "After", updatedAt: date(1) }
      : child);
    const joined = (rows: Fields[]) => many ? rows : rows[0] ?? null;
    const rawBefore = joins ? joined(selected) : collision;
    const rawAfter = joins ? joined(changed) : collision;
    const expectedChildren = beforeChildren.map(child => !missing && child.id === childId
      ? { ...child, [valueField]: "After", updatedAt: date(1) }
      : child);
    const events: unknown[][] = [];
    const failure = new TypeError("raw-relation-output-rejected");
    let captured: unknown;
    let capturedChild: Fields | undefined;
    const parentFields: Record<string, DBFieldAttribute> = {
      [physical]: { type: "string", transform: { async output(value) {
        captured = value;
        expect(value).toStrictEqual(rawBefore);
        events.push(["collision", structuredClone(value)]);
        if (joins && !missing) capturedChild = (many ? (value as Fields[])[0] : value) as Fields;
        if (!missing) {
          const written = await writer.update({
            model: childModel, where: [{ field: "id", value: childId }],
            update: { [valueField]: "After", updatedAt: date(1) },
          });
          expect(written).toStrictEqual(changed[0]);
          events.push(["write", structuredClone(written)]);
          expect(value).toStrictEqual(rawAfter);
          if (joins) expect(many ? (value as Fields[])[0] : value).toBe(capturedChild);
          events.push(["collision-after-write", structuredClone(value)]);
        }
        if (reject) throw failure;
        return value;
      } } },
      relationMirror: { type: "string", fieldName: physical, transform: { output(value) {
        expect(value).toBe(captured);
        expect(value).toStrictEqual(rawAfter);
        events.push(["mirror", structuredClone(value)]);
        return value;
      } } },
    };
    const childFields: Record<string, DBFieldAttribute> = {
      [valueField]: { type: "string", transform: { output(value) {
        events.push(["child", value]);
        return `visible:${value}`;
      } } },
    };
    const reader = (await fixture.reader({
      ...options,
      user: many ? { additionalFields: parentFields } : { modelName: physical, additionalFields: childFields },
      account: many ? { modelName: physical, additionalFields: childFields } : { additionalFields: parentFields },
    }, [])).context.adapter;
    const operation = () => reader.findOne({ model: parentModel, where, join: { [childModel]: true } });
    if (reject) {
      let caught: unknown;
      try { await operation(); } catch (error) { caught = error; }
      expect(caught).toBe(failure);
    } else {
      const output = await operation();
      const projected = changed.map(child => ({ ...child, [valueField]: `visible:${child[valueField]}` }));
      expect(output).toStrictEqual({
        ...beforeParent, [physical]: rawAfter, relationMirror: rawAfter, [childModel]: joined(projected),
      });
      expect(output?.relationMirror).toBe(captured);
      if (alias) expect(output?.[physical]).toBe(captured);
      if (joins && !missing) {
        const child = (many ? (output?.[childModel] as Fields[])[0] : output?.[childModel]) as Fields;
        expect(child).not.toBe(capturedChild);
        expect(child.createdAt).toBe(capturedChild?.createdAt);
        if (many) expect(output?.[childModel]).not.toBe(captured);
      }
    }
    expect(events).toStrictEqual([
      ["collision", rawBefore],
      ...(!missing ? [["write", changed[0]], ["collision-after-write", rawAfter]] : []),
      ...(!reject ? [["mirror", rawAfter], ...changed.map(child => ["child", child[valueField]])] : []),
    ]);
    expect(await writer.findOne({ model: parentModel, where })).toStrictEqual(beforeParent);
    expect(await writer.findMany({ model: childModel })).toStrictEqual(expectedChildren);
    const expectedAccounts = !many || alias ? beforeAccounts : beforeAccounts.map((child: Fields) =>
      !missing && child.id === childId ? { ...child, accessToken: "After", updatedAt: date(1) } : child);
    expect(fixture.storage()).toStrictEqual(expectedAccounts);
  } finally { fixture.close(); }
}

for (const many of [false, true]) for (const alias of [false, true]) for (const joins of [false, true]) for (const reject of [false, true]) {
  test(`Memory ${many ? "User→Account[]" : "Account→User"} ${alias ? "physical alias" : "logical name"} collision joins=${joins}, reject=${reject}`, async () => {
    await check(many, alias, joins, reject);
  });
}

for (const many of [false, true]) for (const alias of [false, true]) {
  test(`Memory empty ${many ? "Account[]" : "User"} ${alias ? "physical alias" : "logical name"} replaces the raw parent property`, async () => {
    await check(many, alias, true, false, true);
  });
}
