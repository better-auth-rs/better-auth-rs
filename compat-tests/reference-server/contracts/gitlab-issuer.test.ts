import { expect, test } from "bun:test";
import { captureGitLabIssuer } from "./gitlab-issuer-capture.mjs";

test("GitLab issuer matches endpoint targets and complete JSON-visible token/profile results", async () => {
  const expected = await Bun.file(new URL("../../../tests/fixtures/gitlab-issuer-1.7.6.json", import.meta.url)).json();
  expect(await captureGitLabIssuer()).toStrictEqual(expected);
});
