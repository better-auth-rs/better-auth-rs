import { expect, test } from "bun:test";
import fixture from "../../../tests/fixtures/native-core-joins-1.7.6.json";
import { capture } from "../../../tests/fixtures/native-core-joins.capture.mjs";

for (const observation of fixture.cases) {
  test(`${observation.backend} joins=${observation.joins} ${observation.path} ${observation.mode} limit=${observation.limit}`, async () => {
    expect(await capture(observation.backend, observation.joins, {
      path: observation.path,
      mode: observation.mode,
      limit: observation.limit ?? undefined,
    })).toEqual(observation);
  });
}
