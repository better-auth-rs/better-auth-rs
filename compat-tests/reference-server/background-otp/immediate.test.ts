import { expect, test } from "bun:test";
import { runCase } from "./fixture";

for (const endpoint of ["email-otp", "two-factor"] as const) for (const transport of ["http", "native"] as const) {
  for (const scheduling of ["default", "handler", "handler-throw"] as const) {
    test(`immediate rejection/${endpoint}/${transport}/${scheduling}`, async () => {
      const actual = await runCase(endpoint, transport, scheduling, "reject-immediate");
      const scheduled = scheduling !== "default";
      expect(actual.outcome).toEqual({status: 200, thrown: null, body: JSON.stringify(endpoint === "email-otp" ? {success: true} : {status: true})});
      expect(actual.events).toEqual(["sender:start", ...(scheduled ? ["handler:received"] : []),
        ...(scheduling === "handler-throw" ? ["log:handler-sync"] : []), "log:sender-async", "response", "gate:release"]);
      expect(actual.logs).toEqual([
        ...(scheduling === "handler-throw" ? [{message: "Failed to run background task:", error: "handler-sync"}] : []),
        {message: endpoint === "email-otp" ? "Failed to run background task:" : "Failed to send two-factor OTP", error: "sender-async"},
      ]);
      expect(actual.taskStates).toEqual(scheduled ? ["fulfilled"] : []);
      expect(actual.storedBeforeRelease).toBe(1);
      expect(actual.storedAfterResponse).toBe(1);
    });
  }
}
