import { compatScenario } from "../../../support/scenario";
import { contracts, type StorageMode } from "./contracts";

const modes: Record<string, StorageMode> = {
  "database-lifecycle": "database",
  "database-lifecycle-cache": "cache",
  "database-lifecycle-database": "database-cache",
  "database-lifecycle-preserved": "preserved",
};
const mode = modes[process.env.COMPAT_PROFILE!];
if (!mode) throw new Error("Unknown database lifecycle profile");
for (const contract of contracts.filter(contract => !contract.modes || contract.modes.includes(mode))) {
  compatScenario(contract.name, ctx => contract.run(async body => {
    const response = await fetch(`${ctx.baseURL}/__test/database-lifecycle`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
    });
    if (!response.ok) throw new Error(`Fixture HTTP ${response.status}: ${await response.text()}`);
    return response.json();
  }, mode));
}
