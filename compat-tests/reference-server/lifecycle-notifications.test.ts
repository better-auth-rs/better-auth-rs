import {expect, test} from "bun:test";
import {endpoints, modes, runCase} from "./lifecycle-notifications";
for (const endpoint of endpoints) for (const transport of ["http", "native"] as const) for (const [scheduling, sender] of modes) {
  test(`${endpoint}/${transport}/${scheduling}/${sender}`, async () => {
    const result = await runCase(endpoint, transport, scheduling, sender);
    const asynchronous = sender === "resolve" || sender === "reject";
    const scheduled = asynchronous && scheduling !== "default" && endpoint !== "direct";
    expect(result.respondedBeforeRelease).toBe(!asynchronous || scheduled);
    const snapshot = {email: ["change-update", "verify-legacy"].includes(endpoint) ? "new@example.com" : "old@example.com",
      verified: endpoint === "change-confirm", verifications: endpoint === "delete" ? 1 : 0};
    expect(result.storedBeforeRelease).toEqual(snapshot);
    expect(result.storedAfterResponse).toEqual(snapshot);
    const failure = sender === "sync-throw" ? "sender-sync" : endpoint === "direct" && sender === "reject" ? "sender-async" : null;
    expect(result.outcome.status).toBe(failure ? transport === "http" ? 500 : null : 200);
    expect(result.outcome.thrown).toBe(failure && transport === "native" ? failure : null);
    expect(result.outcome.cookie).toBe(["change-update", "verify-legacy"].includes(endpoint) && !failure);
    const errors = [];
    if (scheduled && scheduling === "handler-throw") errors.push("handler-sync");
    if (sender === "reject" && endpoint !== "direct") errors.push("sender-async");
    expect(result.logs).toEqual(errors.map(error => ({message: "Failed to run background task:", error})));
    expect(result.taskStates).toEqual(scheduled ? ["fulfilled"] : []);
    expect(result.events[0]).toBe("sender:start");
    if (scheduled) {
      expect(result.events.indexOf("handler:received")).toBe(1);
      expect(result.events.indexOf("response")).toBeLessThan(result.events.indexOf("gate:release"));
    } else expect(result.events).not.toContain("handler:received");
    if (asynchronous) expect(result.events.indexOf("gate:release")).toBeLessThan(result.events.indexOf("sender:released"));
    expect(result.contexts).toHaveLength(asynchronous ? 2 : 1);
    for (const context of result.contexts as any[]) {
      expect(context.request).toBe(transport === "http");
      expect(context.email).toBe(["direct", "delete", "change-confirm"].includes(endpoint) ? "old@example.com" : "new@example.com");
      expect(context.callbackURL).toBe("/");
    }
  });
}
