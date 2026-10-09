import { expect, test } from "bun:test";
import type { DBFieldAttribute } from "@better-auth/core/db";
import type { BetterAuthOptions } from "better-auth";
import { organization } from "better-auth/plugins";
import { date, row as account, setup, type Fields } from "./account-id-input-support";

const collision = "stored-parent-property";
const user = (id: string, name: string): Fields => ({
  id, name, email: `${id}@native-join-property-collision.test`, emailVerified: true,
  image: null, createdAt: date(0), updatedAt: date(0),
});

type OrganizationRelation = "member-user" | "team-members" | "membership-team";
const team = (id: string, name: string): Fields => ({
  id, name, organizationId: "relation-organization", createdAt: date(0), updatedAt: null,
});
const teamMember = (id: string, userId: string, teamId: string): Fields => ({
  id, userId, teamId, createdAt: date(0),
});

async function check(many: boolean, alias: boolean, joins: boolean, reject: boolean, missing = false, relation?: OrganizationRelation) {
  const fixture = await setup("memory");
  try {
    const childModel = relation === "team-members" ? "teamMember" : relation === "membership-team" ? "team" : relation ? "user" : many ? "account" : "user";
    const parentModel = relation === "member-user" ? "member" : relation === "team-members" ? "team" : relation ? "teamMember" : many ? "user" : "account";
    const physical = alias ? `linked_${childModel}` : childModel;
    const parentId = many ? "joined-owner" : "parent-account";
    const childId = many ? "child-account" : "joined-owner";
    const valueField = childModel === "teamMember" ? "userId" : childModel === "account" ? "accessToken" : "name";
    const fields: Record<string, DBFieldAttribute> = {
      [physical]: { type: "string" },
      relationMirror: { type: "string", fieldName: physical },
    };
    const configure = (parentFields: Record<string, DBFieldAttribute>, childFields: Record<string, DBFieldAttribute>): BetterAuthOptions => {
      if (!relation) return {
        advanced: { database: { joins } },
        user: many ? { additionalFields: parentFields } : { modelName: physical, additionalFields: childFields },
        account: many ? { modelName: physical, additionalFields: childFields } : { additionalFields: parentFields },
      };
      const plugin = organization({ teams: { enabled: true } });
      const schema = { ...plugin.schema };
      schema[parentModel] = { ...schema[parentModel], fields: { ...schema[parentModel].fields, ...parentFields } };
      if (childModel !== "user") schema[childModel] = {
        ...schema[childModel], modelName: physical, fields: { ...schema[childModel].fields, ...childFields },
      };
      return {
        advanced: { database: { joins } },
        user: childModel === "user" ? { modelName: physical, additionalFields: childFields } : undefined,
        plugins: [{ ...plugin, schema }],
      };
    };
    const writer = (await fixture.reader(configure(fields, {}), [])).context.adapter;
    const create = (model: string, data: Fields) => writer.create({ model, data, forceAllowId: true });
    const parentData = {
      ...(relation === "member-user" ? { id: parentId, organizationId: "relation-organization", userId: childId, role: "member", createdAt: date(0) }
        : relation === "team-members" ? team(parentId, "Parent")
        : relation === "membership-team" ? teamMember(parentId, "owner", childId)
        : many ? user(parentId, "Parent") : { ...account(parentId), userId: childId }),
      [physical]: collision,
    };
    const child = (id: string, value: string, selected: boolean): Fields => childModel === "teamMember"
      ? teamMember(id, value, selected ? parentId : "unrelated-team")
      : childModel === "team" ? team(id, value)
      : childModel === "account" ? { ...account(id, id, value), userId: selected ? parentId : "owner" }
      : user(id, value);
    const selected = missing ? [] : relation
      ? [child(childId, "Before", true), ...(many ? [child("second-child", "Second", true)] : [])]
      : many ? [
        { ...account(childId, "first", "Before"), userId: parentId },
        { ...account("second-account", "second", "Second"), userId: parentId },
      ] : [user(childId, "Before")];
    // An unrelated row keeps an aliased Memory table present when the relationship is empty.
    await create(childModel, relation ? child("unrelated-child", "Unrelated", false)
      : many ? account("unrelated-account", "unrelated", "Unrelated") : user("unrelated-user", "Unrelated"));
    await create(parentModel, parentData);
    for (const row of selected) await create(childModel, row);
    const where = [{ field: "id", value: parentId }];
    const beforeParent = await writer.findOne({ model: parentModel, where });
    const beforeChildren = await writer.findMany({ model: childModel });
    const beforeAccounts = structuredClone(fixture.storage());
    const update = { [valueField]: "After", ...(childModel === "teamMember" ? {} : { updatedAt: date(1) }) };
    const changed = selected.map((child, index) => index === 0 ? { ...child, ...update } : child);
    const joined = (rows: Fields[]) => many ? rows : rows[0] ?? null;
    const rawBefore = joins ? joined(selected) : collision;
    const rawAfter = joins ? joined(changed) : collision;
    const expectedChildren = beforeChildren.map(child => !missing && child.id === childId
      ? { ...child, ...update }
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
            update,
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
    const reader = (await fixture.reader(configure(parentFields, childFields), [])).context.adapter;
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
    const expectedAccounts = childModel !== "account" || alias ? beforeAccounts : beforeAccounts.map((child: Fields) =>
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

for (const relation of ["member-user", "team-members", "membership-team"] as const) {
  const many = relation === "team-members";
  for (const alias of [false, true]) for (const joins of [false, true]) for (const reject of [false, true]) {
    test(`Memory ${relation} ${alias ? "physical alias" : "logical name"} collision joins=${joins}, reject=${reject}`, async () => {
      await check(many, alias, joins, reject, false, relation);
    });
  }
  for (const alias of [false, true]) {
    test(`Memory empty ${relation} ${alias ? "physical alias" : "logical name"} replaces the raw parent property`, async () => {
      await check(many, alias, true, false, true, relation);
    });
  }
}
