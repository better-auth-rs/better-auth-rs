import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("username signup hooks preserve endpoint input and update fields independently", async (ctx) => {
  const results = [];
  for (const [index, fields, username, displayUsername] of [
    [0, { username: "MixedCase" }, "MixedCase", "MixedCase"],
    [1, { displayUsername: "DisplayOnly" }, "DisplayOnly", "DisplayOnly"],
    [2, { username: "EmptyDisplay", displayUsername: "" }, "EmptyDisplay", "EmptyDisplay"],
    [3, { displayUsername: "Display with spaces" }, null, "Display with spaces"],
  ] as const) {
    const actor = ctx.actor(`signup-${index}`);
    const result = await actor.client.signUp.email({
      email: ctx.uniqueEmail(`username-${index}`), name: "Username", password: "Password123!", ...fields,
    } as any);
    expect(result.error).toBeNull();
    expect((result.data!.user as any).username).toBe(username?.toLowerCase() ?? null);
    expect((result.data!.user as any).displayUsername).toBe(displayUsername);
    const snapshot = await fetch(`${ctx.baseURL}/__test/user-admission`, {
      method: "POST", headers: { "content-type": "application/json" }, body: "{}",
    }).then((response) => response.json());
    expect(snapshot.events.at(-1)).toMatchObject({
      username: username?.toLowerCase() ?? null, bodyUsername: username, bodyDisplayUsername: displayUsername,
    });
    results.push({ user: result.data!.user, event: snapshot.events.at(-1) });
  }

  const actor = ctx.actor("signup-0");
  expect((await actor.client.updateUser({ username: "NewUsername" } as any)).error).toBeNull();
  const renamed = await actor.client.getSession();
  expect((renamed.data!.user as any).username).toBe("newusername");
  expect((renamed.data!.user as any).displayUsername).toBe("MixedCase");
  expect((await actor.client.updateUser({ displayUsername: "New Display" } as any)).error).toBeNull();
  const displayed = await actor.client.getSession();
  expect((displayed.data!.user as any).username).toBe("newusername");
  expect((displayed.data!.user as any).displayUsername).toBe("New Display");
  return { results, renamed: renamed.data, displayed: displayed.data };
});
