import assert from "node:assert/strict";
import { deviceGrantInputs, observeGrantRow, withDeviceGrantFixture } from "./device-grant-capture.mjs";
import { observeValue } from "./device-where-capture.mjs";

const deviceCode = "ordinary-grant-device";
const userCode = "ABCD2345";
const tables = ["user", "session", "account", "verification", "deviceCode"];
export const deviceGrantFailures = ["authorizeRequest", "getVerificationContext", "assertSessionRedemption"];

export async function captureDeviceGrantFailures(backend, diagnostics) {
  const cases = [];
  for (const failure of deviceGrantFailures) {
    for (const baseline of deviceGrantInputs.filter(input => input.mode === "authorized")) {
      const input = { ...baseline, failure };
      cases.push(await withDeviceGrantFixture(input, backend, async ({ context, owner, events, callbackError, readRow, call, request }) => {
        const diagnostic = { backend, input, steps: [] };
        diagnostics.push(diagnostic);
        const storage = async () => Object.fromEntries(await Promise.all(tables.map(async model => [model,
          await context.adapter.findMany({ model, sortBy: { field: "id", direction: "asc" } }),
        ])));
        const prior = {};
        const stages = [
          { phase: "authorizeRequest", name: "issuance", row: "issued", args: ["deviceCode", "POST", "/device/code", input.body] },
          { phase: "getVerificationContext", name: "verification", row: "claimed", args: ["deviceVerify", "GET", "/device", undefined, { user_code: userCode }, true] },
          { phase: null, name: "approval", row: "approved", args: ["deviceApprove", "POST", "/device/approve", { userCode }, undefined, true] },
          { phase: "assertSessionRedemption", name: "redemption", args: ["deviceToken", "POST", "/device/token", {
            grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: deviceCode, client_id: "ordinary-grant-client",
          }] },
        ];
        for (const stage of stages) {
          if (stage.phase !== failure) {
            const response = await call(...stage.args);
            diagnostic.steps.push({ name: stage.name, response });
            assert.equal(response.status, 200);
            prior[stage.name] = response;
            prior[stage.row] = observeGrantRow(await readRow());
            continue;
          }
          const before = await storage();
          diagnostic.before = observeValue(before);
          let response = null;
          let error = null;
          try {
            const returned = await request(...stage.args);
            response = { status: returned.status,
              headers: [...returned.headers].sort(([a], [b]) => a.localeCompare(b)), body: await returned.text() };
          } catch (caught) {
            diagnostic.thrown = { name: caught.name, message: caught.message, stack: caught.stack };
            assert.equal(caught, callbackError, "Native dispatch must retain the original callback error");
            error = { name: caught.name, message: caught.message };
          }
          const after = await storage();
          diagnostic.after = observeValue(after);
          diagnostic.response = response;
          diagnostic.error = error;
          diagnostic.events = events;
          assert.ok(error || response?.status === 500, "The callback failure must reject the selected endpoint");
          for (const model of tables.filter(model => model !== "deviceCode")) {
            assert.deepEqual(after[model], before[model], `${failure} must preserve every ${model} field`);
          }
          assert.equal(before.session.length, 1, "The setup creates exactly one owner session");
          const expected = structuredClone(before.deviceCode);
          if (failure === "getVerificationContext") {
            assert.equal(expected.length, 1);
            expected[0].userId = owner.id;
          }
          assert.deepEqual(after.deviceCode, expected, "Only verification ownership may change before the failed callback");
          assert.equal(events.filter(event => event.phase === failure).length, 1);
          assert.equal(events.at(-1).phase, failure, "The failed callback must stop the lifecycle");
          const visibleDevice = rows => rows.map(row => {
            assert.equal(typeof row.id, "string");
            assert.ok(row.id.length > 0);
            assert.equal(row.deviceCode, deviceCode);
            assert.equal(row.userCode, userCode);
            assert.ok(new Date(row.expiresAt).getTime() > Date.now());
            assert.ok(row.userId == null || row.userId === owner.id);
            return JSON.parse(JSON.stringify({ ...row, id: "<device-id>", expiresAt: "<device-expiry>",
              ...(row.userId != null ? { userId: "<owner-id>" } : {}) }));
          });
          return { input, prior, response, error, events,
            before: visibleDevice(before.deviceCode), after: visibleDevice(after.deviceCode),
            unchanged: { user: true, session: true, account: true, verification: true }, sessionCount: after.session.length };
        }
        assert.fail(`Missing Device grant failure stage ${failure}`);
      }));
    }
  }
  return cases;
}
