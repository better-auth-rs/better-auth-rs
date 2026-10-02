const modules = `${import.meta.dir}/../../compat-tests/reference-server/node_modules`;
const { twoFactor } = await import(`${modules}/better-auth/dist/plugins/two-factor/index.mjs`);
const { recordTwoFactorFailure } = await import(`${modules}/better-auth/dist/plugins/two-factor/verify-two-factor.mjs`);

export async function captureAccountLockoutClock() {
  const maxAttempts = 2;
  const durationSeconds = 1.5;
  const plugin = twoFactor({ accountLockout: { maxFailedAttempts: maxAttempts, durationSeconds } });
  const cases = [];
  let failedVerificationCount = 0;
  let lockedUntil = null;

  for (const name of ["below", "threshold"]) {
    const startMillis = 2_000_000_000_123;
    const incrementCompletedMillis = 2_000_000_002_123;
    let clockMillis = startMillis;
    const events = [];
    const requests = [];
    const ctx = {
      context: {
        getPlugin(id) {
          if (id !== "two-factor") throw new Error(`Unexpected plugin: ${id}`);
          return plugin;
        },
        adapter: {
          async incrementOne(input) {
            events.push({ type: "incrementOne" });
            requests.push(JSON.parse(JSON.stringify(input)));
            if (input.increment.failedVerificationCount !== undefined) {
              failedVerificationCount += input.increment.failedVerificationCount;
              await Promise.resolve();
              clockMillis = incrementCompletedMillis;
            }
            if (input.set) lockedUntil = input.set.lockedUntil.toISOString();
            return { failedVerificationCount };
          },
        },
      },
    };
    const originalNow = Date.now;
    try {
      Date.now = () => {
        events.push({ type: "clock", millis: clockMillis });
        return clockMillis;
      };
      await recordTwoFactorFailure(ctx, "twoFactor", { id: "ordinary-clock" });
    } finally {
      Date.now = originalNow;
    }
    cases.push({ name, startMillis, incrementCompletedMillis, events, requests,
      stored: { failedVerificationCount, lockedUntil } });
  }
  return {
    version: (await Bun.file(`${modules}/@better-auth/core/package.json`).json()).version,
    maxAttempts, durationSeconds, cases,
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureAccountLockoutClock(), null, 2));
