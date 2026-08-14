import { test } from "bun:test";
import diff from "microdiff";
import { createAuthClient } from "better-auth/client";
import { RAW_DIFF_ALLOWLIST } from "./allowlist";
import { RUST_BASE_URL, TS_BASE_URL, requireHealthy } from "./config";
import {
  type GitHubEmailRecord,
  readChangeEmailConfirmation,
  promoteAdmin,
  readTwoFactorOtp,
  readVerificationEmail,
  removeCredentialAccount,
  resetServerState,
  seedDeleteUserToken,
  seedOAuthAccount,
  setGitHubProfile,
  seedResetPasswordToken,
  setOAuthRefreshMode,
  setResetPasswordMode,
  setSocialProfile,
} from "./controls";
import { normalizeClientValue } from "./normalize";
import { createTracingFetch, type TraceEntry } from "./trace";

type ScenarioServerContext = {
  baseURL: string;
  actor(name?: string): {
    client: ReturnType<typeof createAuthClient>;
    fetch(input: string | URL | Request, init?: RequestInit): Promise<Response>;
  };
  uniqueEmail(prefix: string): string;
  uniqueToken(prefix: string): string;
  snapshot<T>(value: T): unknown;
  rawRequest(args: {
    actor?: string;
    path: string;
    method?: string;
    body?: BodyInit;
    headers?: HeadersInit;
    json?: unknown;
    redirect?: RequestRedirect;
  }): Promise<{
    status: number;
    location: string | null;
    body: unknown;
  }>;
  resetServerState(): Promise<unknown>;
  setResetPasswordMode(mode: "capture" | "throw"): Promise<unknown>;
  seedResetPasswordToken(args: {
    email: string;
    token: string;
    expiresAt: string;
  }): Promise<unknown>;
  setOAuthRefreshMode(mode: "success" | "error"): Promise<unknown>;
  setSocialProfile(args: {
    sub?: string;
    email?: string;
    name?: string;
    image?: string | null;
    emailVerified?: boolean;
    idTokenValid?: boolean;
  }): Promise<unknown>;
  setGitHubProfile(args: {
    id?: string;
    login?: string;
    name?: string | null;
    email?: string | null;
    avatarUrl?: string | null;
    emails?: GitHubEmailRecord[];
  }): Promise<unknown>;
  seedOAuthAccount(args: {
    email: string;
    providerId?: string;
    accountId?: string;
    accessToken?: string | null;
    refreshToken?: string | null;
    idToken?: string | null;
    accessTokenExpiresAt?: string | null;
    refreshTokenExpiresAt?: string | null;
    scope?: string | null;
  }): Promise<string>;
  readVerificationEmail(args: {
    email: string;
  }): Promise<unknown>;
  readTwoFactorOtp(args: {
    email: string;
  }): Promise<unknown>;
  readChangeEmailConfirmation(args: {
    email: string;
  }): Promise<unknown>;
  seedDeleteUserToken(args: {
    email: string;
    token: string;
    expiresAt: string;
  }): Promise<unknown>;
  removeCredentialAccount(args: {
    email: string;
  }): Promise<unknown>;
  promoteAdmin(args: {
    email: string;
  }): Promise<unknown>;
};

type ScenarioRun = {
  observation: unknown;
  traces: TraceEntry[];
};

function formatDiffPath(path: Array<string | number>) {
  return path.map((segment) => String(segment)).join(".");
}

function filterRawDiffs(
  scenarioName: string,
  diffs: ReturnType<typeof diff>,
) {
  return diffs.filter((entry) => {
    const path = formatDiffPath(entry.path);
    return !RAW_DIFF_ALLOWLIST.some(
      (allowance) =>
        allowance.scenario.test(scenarioName) && allowance.path.test(path),
    );
  });
}

async function runScenario(
  label: string,
  baseURL: string,
  seed: string,
  scenario: (ctx: ScenarioServerContext) => Promise<unknown>,
): Promise<ScenarioRun> {
  await requireHealthy(baseURL, label);
  await resetServerState(baseURL);

  const traces: TraceEntry[] = [];
  const actors = new Map<
    string,
    {
      client: ReturnType<typeof createAuthClient>;
      fetch(input: string | URL | Request, init?: RequestInit): Promise<Response>;
    }
  >();
  const shortSeed = seed.replace(/-/g, "").slice(0, 12);

  const context: ScenarioServerContext = {
    baseURL,
    actor(name = "primary") {
      const existing = actors.get(name);
      if (existing) {
        return existing;
      }

      const fetchImpl = createTracingFetch(baseURL, name, traces);
      const actor = {
        client: createAuthClient({
          baseURL,
          fetchOptions: {
            customFetchImpl: fetchImpl,
          },
        }),
        fetch(input: string | URL | Request, init?: RequestInit) {
          return fetchImpl(input, init);
        },
      };
      actors.set(name, actor);
      return actor;
    },
    uniqueEmail(prefix) {
      return `${prefix}-${shortSeed}@test.com`;
    },
    uniqueToken(prefix) {
      return `${prefix}-${shortSeed}`;
    },
    snapshot(value) {
      return normalizeClientValue(value);
    },
    async rawRequest({
      actor = "primary",
      path,
      method = "GET",
      body,
      headers,
      json,
      redirect,
    }) {
      const requestHeaders = new Headers(headers);
      let requestBody = body;
      if (json !== undefined) {
        requestHeaders.set("content-type", "application/json");
        requestBody = JSON.stringify(json);
      }

      const response = await context.actor(actor).fetch(path, {
        method,
        headers: requestHeaders,
        body: requestBody,
        redirect,
      });
      const text = await response.text();
      let parsed: unknown = null;
      if (text) {
        try {
          parsed = JSON.parse(text);
        } catch {
          parsed = text;
        }
      }
      return {
        status: response.status,
        location: response.headers.get("location"),
        body: parsed,
      };
    },
    resetServerState() {
      return resetServerState(baseURL);
    },
    setResetPasswordMode(mode) {
      return setResetPasswordMode(baseURL, mode);
    },
    seedResetPasswordToken(args) {
      return seedResetPasswordToken(baseURL, args);
    },
    setOAuthRefreshMode(mode) {
      return setOAuthRefreshMode(baseURL, mode);
    },
    setSocialProfile(args) {
      return setSocialProfile(baseURL, args);
    },
    setGitHubProfile(args) {
      return setGitHubProfile(baseURL, args);
    },
    seedOAuthAccount(args) {
      return seedOAuthAccount(baseURL, args);
    },
    readVerificationEmail(args) {
      return readVerificationEmail(baseURL, args);
    },
    readTwoFactorOtp(args) {
      return readTwoFactorOtp(baseURL, args);
    },
    readChangeEmailConfirmation(args) {
      return readChangeEmailConfirmation(baseURL, args);
    },
    seedDeleteUserToken(args) {
      return seedDeleteUserToken(baseURL, args);
    },
    removeCredentialAccount(args) {
      return removeCredentialAccount(baseURL, args);
    },
    promoteAdmin(args) {
      return promoteAdmin(baseURL, args);
    },
  };

  return {
    observation: normalizeClientValue(await scenario(context)),
    traces,
  };
}

function formatDiffs(title: string, diffs: ReturnType<typeof diff>) {
  return [
    title,
    ...diffs.map((entry) => `- ${entry.type} ${formatDiffPath(entry.path)}`),
  ].join("\n");
}

export function compatScenario(
  scenarioName: string,
  scenario: (ctx: ScenarioServerContext) => Promise<unknown>,
) {
  test.serial(scenarioName, async () => {
    const seed = `${Date.now()}-${crypto.randomUUID()}`;
    const ts = await runScenario("TS", TS_BASE_URL, seed, scenario);
    const rust = await runScenario("Rust", RUST_BASE_URL, seed, scenario);

    const clientDiffs = diff(ts.observation, rust.observation, {
      cyclesFix: false,
    });
    if (clientDiffs.length > 0) {
      throw new Error(
        `${formatDiffs(`Client-visible drift in scenario: ${scenarioName}`, clientDiffs)}\n\nTS:\n${JSON.stringify(
          ts.observation,
          null,
          2,
        )}\n\nRust:\n${JSON.stringify(rust.observation, null, 2)}`,
      );
    }

    const rawDiffs = filterRawDiffs(
      scenarioName,
      diff(ts.traces, rust.traces, {
        cyclesFix: false,
      }),
    );

    if (rawDiffs.length > 0) {
      throw new Error(
        `${formatDiffs(`Raw trace drift in scenario: ${scenarioName}`, rawDiffs)}\n\nTS traces:\n${JSON.stringify(
          ts.traces,
          null,
          2,
        )}\n\nRust traces:\n${JSON.stringify(rust.traces, null, 2)}`,
      );
    }
  });
}
