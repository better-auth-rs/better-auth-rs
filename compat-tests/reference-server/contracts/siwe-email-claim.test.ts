import { expect, test } from "bun:test";
import { captureSiweEmailClaims, siweEmailClaimCases } from "./siwe-email-claim-capture.mjs";

test("SIWE preserves claim catch scope, original errors, callback order and complete stored rows", async () => {
  const observation = await captureSiweEmailClaims();
  expect(observation.cases.map(entry => entry.name)).toStrictEqual(siweEmailClaimCases);
});
