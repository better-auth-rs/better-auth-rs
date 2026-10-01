import { expect, test } from "bun:test";
import { runCase, type Endpoint, type Transport, type Scheduling, type Sender } from "./background-notifications";

for (const endpoint of ["reset", "phone"] as Endpoint[]) for (const transport of ["http", "native"] as Transport[]) {
  for (const scheduling of ["default", "handler", "handler-throw"] as Scheduling[]) for (const sender of ["resolve", "reject", "sync-throw", "void"] as Sender[]) {
    test(`${endpoint}/${transport}/${scheduling}/${sender}`, async () => {
      const result = await runCase(endpoint, transport, scheduling, sender);
      const asynchronous = sender === "resolve" || sender === "reject";
      const scheduled = asynchronous && scheduling !== "default";
      expect(result.respondedBeforeRelease).toBe(!asynchronous || scheduled);
      expect(result.storedBeforeRelease).toBe(1);
      expect(result.storedAfterResponse).toBe(1);
      expect(result.taskStates).toEqual(scheduled ? ["fulfilled"] : []);
      const failure = sender === "sync-throw" ? "sender-sync"
        : endpoint === "phone" && scheduling === "default" && sender === "reject" ? "sender-async" : null;
      if (failure) expect(result.outcome).toEqual(transport === "http"
        ? {status: 500, thrown: null, body: ""} : {status: null, thrown: failure, body: null});
      else {
        expect(result.outcome.status).toBe(200);
        expect(result.outcome.thrown).toBeNull();
        expect(JSON.parse(result.outcome.body!)).toEqual(endpoint === "reset"
          ? {status: true, message: "If this email exists in our system, check your email for the reset link"}
          : {message: "code sent"});
      }
      const errors = [];
      if (scheduled && scheduling === "handler-throw") errors.push("handler-sync");
      if (sender === "reject" && !failure) errors.push("sender-async");
      expect(result.logs).toEqual(errors.map(error => ({message: "Failed to run background task:", error})));
      expect(result.events[0]).toBe("sender:start");
      if (scheduled) {
        expect(result.events.indexOf("handler:received")).toBe(1);
        expect(result.events.indexOf("response")).toBeLessThan(result.events.indexOf("gate:release"));
        expect(result.events.indexOf("gate:release")).toBeLessThan(result.events.indexOf("sender:released"));
      } else {
        expect(result.events).not.toContain("handler:received");
        if (asynchronous) expect(result.events.indexOf("sender:released")).toBeLessThan(result.events.indexOf("response"));
      }
      const path = endpoint === "reset" ? "/request-password-reset" : "/phone-number/send-otp";
      const context = {
        sameContext: true, path,
        body: endpoint === "reset" ? {email: "background@example.com"} : {phoneNumber: "+15550000001"},
        request: transport === "http", requestURL: transport === "http" ? `http://localhost:3000/api/auth${path}` : null,
        sameRequest: true, baseURL: "http://localhost:3000/api/auth",
      };
      expect(result.contexts).toEqual([
        {phase: "start", ...context}, ...(asynchronous ? [{phase: "released", ...context}] : []),
      ]);
    });
  }
}
