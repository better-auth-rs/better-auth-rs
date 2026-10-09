import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { phoneNumber } from "better-auth/plugins";

const phone = "+15551230001";
const email = "phone@admission.test";

for (const sqlite of [false, true]) {
  for (const customName of [false, true]) {
    test(`${sqlite ? "SQLite" : "Memory"}: phone signup prepares fields before temporary identity and verified proof with customName=${customName}`, async () => {
      const database = sqlite ? new Database(":memory:") : null;
      const memory = { user: [], session: [], account: [], verification: [] };
      const events: [string, any][] = [];
      const sources: any[] = [];
      const reserved: Record<string, any> = Object.fromEntries([
        ["phoneNumber", undefined, "string"],
        ["code", "username", "string"],
        ["disableSession", "displayUsername", "boolean"],
        ["updatePhoneNumber", "banReason", "boolean"],
      ].map(([name, fieldName, type]) => [name, {
        type, required: false, ...(fieldName ? { fieldName } : {}),
        validator: { input: { "~standard": { validate() {
          throw new Error(`Reserved route field ${name} reached the user validator`);
        } } } },
      }]));
      const proof = { type: "boolean", input: false, required: false, defaultValue: false };
      const options: any = {
        database: database ?? memoryAdapter(memory),
        baseURL: "https://admission.test",
        secret: "phone-admission-contract-secret-at-least-thirty-two-characters",
        logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
        user: {
          additionalFields: {
            ...Object.fromEntries(["email", "name"].map(name => [name, {
              type: "string", required: false,
              validator: { input: { "~standard": { validate(input: any) {
                events.push([name, { input }]);
                return { value: { source: "parsed" } };
              } } } },
            }])),
            phoneNumberVerified: proof,
            metadata: {
              type: "json", required: false,
              validator: { input: { "~standard": { validate(input: any) {
                events.push(["metadata", { input }]);
                return { value: { source: "parsed", input } };
              } } } },
            },
            ...reserved,
          },
          validateUserInfo({ user, source }: any) {
            events.push(["admission", structuredClone(user)]);
            sources.push(structuredClone(source));
          },
        },
        databaseHooks: { user: { create: {
          before(user: any) { events.push(["before", structuredClone(user)]); },
          after(user: any) { events.push(["after", structuredClone(user)]); },
        } } },
        plugins: [phoneNumber({
          sendOTP() { throw new Error("Verification must not send a new OTP"); },
          verifyOTP({ phoneNumber, code }) {
            expect({ phoneNumber, code }).toStrictEqual({ phoneNumber: phone, code: "123456" });
            events.push(["verify", {}]);
            return true;
          },
          signUpOnVerification: {
            getTempEmail(value) {
              expect(value).toBe(phone);
              events.push(["temp-email", {}]);
              return email.toUpperCase();
            },
            ...(customName ? { getTempName(value: string) {
              expect(value).toBe(phone);
              events.push(["temp-name", {}]);
              return "Phone Owner";
            } } : {}),
          },
          callbackOnVerification({ phoneNumber, user }) {
            expect(phoneNumber).toBe(phone);
            events.push(["verified", structuredClone(user)]);
          },
        }), {
          id: "phone-signup-field-contract",
          schema: { user: { fields: { phoneNumber: reserved.phoneNumber, phoneNumberVerified: proof } } },
        }],
      };
      try {
        if (database) await (await getMigrations(options)).runMigrations();
        const auth = betterAuth(options);
        const response = await auth.handler(new Request("https://admission.test/api/auth/phone-number/verify", {
          method: "POST",
          headers: { "content-type": "application/json", origin: "https://admission.test" },
          body: JSON.stringify({
            phoneNumber: phone, code: "123456", disableSession: true, updatePhoneNumber: false,
            email: "client@admission.test", name: "Client", metadata: { source: "client" },
          }),
        }));
        expect(response.status).toBe(200);
        expect(sources).toStrictEqual([{ method: "phone-number", action: "create-user" }]);
        expect(events.map(([phase]) => phase)).toStrictEqual([
          "verify", "email", "name", "metadata", "temp-email", ...(customName ? ["temp-name"] : []),
          "admission", "before", "after", "verified",
        ]);
        expect(events.slice(0, 4)).toStrictEqual([
          ["verify", {}], ["email", { input: "client@admission.test" }],
          ["name", { input: "Client" }], ["metadata", { input: { source: "client" } }],
        ]);
        const admitted = events.at(-4)![1];
        const name = customName ? "Phone Owner" : phone;
        const metadata = { source: "parsed", input: { source: "client" } };
        expect(admitted).toStrictEqual({
          createdAt: expect.any(Date), updatedAt: expect.any(Date),
          email, name, phoneNumberVerified: true, metadata, phoneNumber: phone,
        });
        expect(Object.keys(admitted)).toStrictEqual([
          "createdAt", "updatedAt", "email", "name", "phoneNumberVerified", "metadata", "phoneNumber",
        ]);
        expect(events.at(-3)![1]).toStrictEqual(admitted);
        const context = await auth.$context;
        const stored = await context.adapter.findOne<any>({ model: "user", where: [{ field: "email", value: email }] });
        expect(stored).toStrictEqual({
          id: expect.any(String), name, email, emailVerified: false,
          image: sqlite ? null : undefined,
          createdAt: admitted.createdAt, updatedAt: admitted.updatedAt,
          phoneNumberVerified: true, metadata, phoneNumber: phone,
          code: sqlite ? null : undefined, disableSession: sqlite ? null : undefined,
          updatePhoneNumber: sqlite ? null : undefined,
        });
        expect(events.at(-2)![1]).toStrictEqual(stored);
        expect(events.at(-1)![1]).toStrictEqual(stored);
        expect(await response.json()).toStrictEqual(JSON.parse(JSON.stringify({ status: true, token: null, user: stored })));
        expect(await context.adapter.count({ model: "user" })).toBe(1);
        expect(await context.adapter.count({ model: "session" })).toBe(0);
        expect(await context.adapter.count({ model: "account" })).toBe(0);
        expect(await context.adapter.count({ model: "verification" })).toBe(0);
      } finally {
        database?.close();
      }
    });
  }
}
