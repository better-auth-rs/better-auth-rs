import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

if (process.env.COMPAT_PROFILE === "username-writes") {
  compatScenario("OTP and phone signup apply endpoint, database and adapter username policies", async ctx => {
    const email = ctx.uniqueEmail("otp-username");
    const sent = await ctx.rawRequest({ path: "/api/auth/email-otp/send-verification-otp", method: "POST", json: { email, type: "sign-in" } });
    expect(sent.status).toBe(200);
    const otp = await ctx.rawRequest({ actor: "otp", path: "/api/auth/sign-in/email-otp", method: "POST", json: { email, otp: "123456", name: "OTP", username: "Email", displayUsername: "Mail" } });
    expect(otp.status).toBe(200);
    expect((otp.body as any).user.username).toBe("nnnEmail");
    expect((otp.body as any).user.displayUsername).toBe("dddMail");
    const phone = await ctx.rawRequest({ actor: "phone", path: "/api/auth/phone-number/verify", method: "POST", json: { phoneNumber: "+15551234567", code: "246810", username: "Phone", displayUsername: "Mobile" } });
    expect(phone.status).toBe(200);
    expect((phone.body as any).user.username).toBe("nnnPhone");
    expect((phone.body as any).user.displayUsername).toBe("dddMobile");
    const state = await (await fetch(`${ctx.baseURL}/__test/username`)).json();
    expect(state.rows).toEqual([
      { email, username: "nnnEmail", displayUsername: "dddMail" },
      { email: "15551234567@phone.example.com", username: "nnnPhone", displayUsername: "dddMobile" },
    ]);
    return { sent, otp, phone, state };
  });

  compatScenario("native admin provisioning applies database and adapter username policies", async ctx => {
    const created = await ctx.rawRequest({ path: "/__test/username/native", method: "POST", json: {
      operation: "admin-create", data: { email: ctx.uniqueEmail("admin-username"), name: "Provisioned", data: { username: "Admin", displayUsername: "Operator" } },
    } });
    expect(created.status).toBe(200);
    expect((created.body as any).status).toBe(200);
    expect((created.body as any).body.user.username).toBe("nnAdmin");
    expect((created.body as any).body.user.displayUsername).toBe("ddOperator");
    const state = await (await fetch(`${ctx.baseURL}/__test/username`)).json();
    expect(state.calls).toEqual(["validate:Admin", "normalize:Admin", "normalize:Admin", "display:Operator", "normalize:nAdmin", "display:dOperator"]);
    expect(state.rows[0].username).toBe("nnAdmin");
    const adminEmail = ctx.uniqueEmail("admin-actor");
    const actor = await ctx.rawRequest({ path: "/__test/username/native", method: "POST", json: {
      operation: "admin-create", data: { email: adminEmail, name: "Administrator", role: "admin", password: "Password123!" },
    } });
    expect((actor.body as any).status).toBe(200);
    const login = await ctx.rawRequest({ actor: "admin", path: "/api/auth/sign-in/email", method: "POST", json: { email: adminEmail, password: "Password123!" } });
    expect(login.status).toBe(200);
    const userId = (created.body as any).body.user.id;
    const duplicate = await ctx.rawRequest({ actor: "admin", path: "/api/auth/admin/update-user", method: "POST", json: { userId, data: { username: "nAdmin" } } });
    expect(duplicate.status).toBe(400);
    expect((duplicate.body as any).code).toBe("USERNAME_IS_ALREADY_TAKEN");
    await fetch(`${ctx.baseURL}/__test/username`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    const updated = await ctx.rawRequest({ actor: "admin", path: "/api/auth/admin/update-user", method: "POST", json: { userId, data: { username: "Changed", displayUsername: "Updated" } } });
    expect(updated.status).toBe(200);
    expect((updated.body as any).username).toBe("nnChanged");
    expect((updated.body as any).displayUsername).toBe("ddUpdated");
    const after = await (await fetch(`${ctx.baseURL}/__test/username`)).json();
    expect(after.calls).toEqual(["validate:Changed", "normalize:Changed", "normalize:Changed", "display:Updated", "normalize:nChanged", "display:dUpdated"]);
    return { created, state, actor, login, duplicate, updated, after };
  });
}
