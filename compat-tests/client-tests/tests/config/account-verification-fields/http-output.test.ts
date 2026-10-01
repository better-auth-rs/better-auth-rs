import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

for (const operation of ["get-access-token", "refresh-token", "list-accounts"]) {
  compatScenario(`Account ${operation} preserves refresh projection and returned filtering`, async ctx => {
    const response = await fetch(`${ctx.baseURL}/__test/account-http-output`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({operation}),
    });
    if (!response.ok) throw new Error(`Account HTTP fixture ${response.status}: ${await response.text()}`);
    const result = await response.json();
    expect(result.status).toBe(200);
    if (operation === "list-accounts") {
      expect(result.body).toEqual({scopes:[],hasIdToken:false});
      expect(result.stored).toEqual({scope:"before",idToken:"old-id"});
    } else {
      expect(result.body.accessToken).toBe("new-access");
      expect(result.body.idToken).toBe("old-id:out");
      if (operation === "get-access-token") expect(result.body.scopes).toEqual(["before:out"]);
      else expect(result.body.scope).toBe("after:out");
      expect(result.stored).toEqual({scope:"after",idToken:"old-id:out"});
    }
    return ctx.snapshot(result);
  });
}
