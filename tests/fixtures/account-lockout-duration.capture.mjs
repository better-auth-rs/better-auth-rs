const modules = `${import.meta.dir}/../../compat-tests/reference-server/node_modules`;
const { twoFactor } = await import(`${modules}/better-auth/dist/plugins/two-factor/index.mjs`);
const { recordTwoFactorFailure } = await import(`${modules}/better-auth/dist/plugins/two-factor/verify-two-factor.mjs`);

export const anchorMillis = 2_000_000_000_123;

export async function capture(name, seconds) {
  const plugin = twoFactor(name === "omitted" ? {} : {
    accountLockout: { durationSeconds: seconds },
  });
  const events = [];
  const context = {
    context: {
      getPlugin(id) {
        if (id !== "two-factor") throw new Error(`Unexpected plugin: ${id}`);
        return plugin;
      },
      adapter: {
        async incrementOne(input) {
          events.push(JSON.parse(JSON.stringify(input)));
          return { failedVerificationCount: 10 };
        },
      },
    },
  };
  const originalNow = Date.now;
  try {
    Date.now = () => anchorMillis;
    await recordTwoFactorFailure(context, "twoFactor", { id: "ordinary-date-calculation" });
  } finally {
    Date.now = originalNow;
  }
  return { name, configured: seconds ?? null, anchorMillis, events };
}

if (import.meta.main) {
  const cases = [];
  for (const [name, seconds] of [["omitted", undefined], ["zero", 0], ["fractional", 1.5]]) {
    cases.push(await capture(name, seconds));
  }
  console.log(JSON.stringify({ version: "1.7.6", cases }, null, 2));
}
