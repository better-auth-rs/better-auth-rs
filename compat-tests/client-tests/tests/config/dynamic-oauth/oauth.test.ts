import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
compatScenario("Resolved tenant provider trust gates linking and persists tenant-bound OAuth state", async ctx => {
  const response = await fetch(`${ctx.baseURL}/__test/dynamic-oauth`, {method:"POST"});
  expect(response.status).toBe(200);
  const rows = await response.json();
  expect(rows[0]).toMatchObject({tenant:"b",status:401,signedIn:false,accounts:[]});
  expect(rows[1]).toMatchObject({tenant:"a",status:200,signedIn:true,accounts:[{providerId:"google",accountId:"provider-a",sameUser:true}]});
  for (const row of rows) expect(row).toMatchObject({redirectURI:`https://${row.tenant}.tenant.test/api/auth/callback/google`,statePersisted:true,stateCallback:`https://${row.tenant}.tenant.test/done`,stateBound:true});
  return rows;
});
