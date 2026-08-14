import { compatScenario } from "../../support/scenario";

const DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("expected object response body");
  }
  return value as Record<string, unknown>;
}

function asString(value: unknown, key: string): string {
  if (typeof value !== "string") {
    throw new Error(`expected string for ${key}`);
  }
  return value;
}

function normalizeApprovedTokenResponse(response: {
  status: number;
  location: string | null;
  body: unknown;
}) {
  const snapshot = structuredClone(response) as {
    status: number;
    location: string | null;
    body: Record<string, unknown> | null;
  };

  if (snapshot.body && typeof snapshot.body.expires_in === "number") {
    const expiresIn = snapshot.body.expires_in;
    snapshot.body.expires_in =
      Math.abs(expiresIn - 604800) <= 5 ? "<week-session-ttl>" : expiresIn;
  }

  return snapshot;
}

compatScenario("device code request returns oauth device response fields", async (ctx) => {
  const code = await ctx.rawRequest({
    path: "/api/auth/device/code",
    method: "POST",
    json: {
      client_id: "compat-device-client",
      scope: "openid profile",
    },
  });
  const body = asRecord(code.body);
  const userCode = asString(body.user_code, "user_code");
  const verificationUri = asString(body.verification_uri, "verification_uri");
  const verificationUriComplete = asString(
    body.verification_uri_complete,
    "verification_uri_complete",
  );

  return {
    code: {
      status: code.status,
      hasDeviceCode: typeof body.device_code === "string" && body.device_code.length >= 40,
      userCodeFormat: /^[A-Z0-9]{8}$/.test(userCode),
      expiresIn: body.expires_in,
      interval: body.interval,
      verificationUriHasDevicePath: verificationUri.includes("/device"),
      verificationUriCompleteHasUserCode: verificationUriComplete.includes("user_code="),
    },
  };
});

compatScenario("device token returns authorization_pending while request is pending", async (ctx) => {
  const code = await ctx.rawRequest({
    path: "/api/auth/device/code",
    method: "POST",
    json: {
      client_id: "compat-device-client",
    },
  });
  const deviceCode = asString(asRecord(code.body).device_code, "device_code");

  const token = await ctx.rawRequest({
    path: "/api/auth/device/token",
    method: "POST",
    json: {
      grant_type: DEVICE_GRANT_TYPE,
      device_code: deviceCode,
      client_id: "compat-device-client",
    },
  });

  return {
    token: ctx.snapshot(token),
  };
});

compatScenario("device token returns invalid_grant for an unknown device code", async (ctx) => {
  const token = await ctx.rawRequest({
    path: "/api/auth/device/token",
    method: "POST",
    json: {
      grant_type: DEVICE_GRANT_TYPE,
      device_code: "unknown-device-code",
      client_id: "compat-device-client",
    },
  });

  return {
    token: ctx.snapshot(token),
  };
});

compatScenario("device verify accepts a hyphenated user code", async (ctx) => {
  const code = await ctx.rawRequest({
    path: "/api/auth/device/code",
    method: "POST",
    json: {
      client_id: "compat-device-client",
    },
  });
  const userCode = asString(asRecord(code.body).user_code, "user_code");
  const formattedUserCode = `${userCode.slice(0, 4)}-${userCode.slice(4)}`;

  const verify = await ctx.rawRequest({
    path: `/api/auth/device?user_code=${encodeURIComponent(formattedUserCode)}`,
  });
  const verifyBody = asRecord(verify.body);

  return {
    verify: {
      status: verify.status,
      location: verify.location,
      body: {
        status: verifyBody.status,
        echoedHyphenatedInput: verifyBody.user_code === formattedUserCode,
      },
    },
  };
});

compatScenario("device approve flow returns a bearer token", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase4-device-approve");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Device Approve User",
  });

  const code = await ctx.rawRequest({
    path: "/api/auth/device/code",
    method: "POST",
    json: {
      client_id: "compat-device-client",
      scope: "read write",
    },
  });
  const codeBody = asRecord(code.body);
  const deviceCode = asString(codeBody.device_code, "device_code");
  const userCode = asString(codeBody.user_code, "user_code");

  const approve = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/device/approve",
    method: "POST",
    json: {
      userCode,
    },
  });

  const token = await ctx.rawRequest({
    path: "/api/auth/device/token",
    method: "POST",
    json: {
      grant_type: DEVICE_GRANT_TYPE,
      device_code: deviceCode,
      client_id: "compat-device-client",
    },
  });

  return {
    signup: ctx.snapshot(signup),
    approve: ctx.snapshot(approve),
    token: normalizeApprovedTokenResponse(ctx.snapshot(token) as typeof token),
  };
});

compatScenario("device deny flow returns access_denied", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase4-device-deny");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Device Deny User",
  });

  const code = await ctx.rawRequest({
    path: "/api/auth/device/code",
    method: "POST",
    json: {
      client_id: "compat-device-client",
    },
  });
  const codeBody = asRecord(code.body);
  const deviceCode = asString(codeBody.device_code, "device_code");
  const userCode = asString(codeBody.user_code, "user_code");

  const deny = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/device/deny",
    method: "POST",
    json: {
      userCode,
    },
  });

  const token = await ctx.rawRequest({
    path: "/api/auth/device/token",
    method: "POST",
    json: {
      grant_type: DEVICE_GRANT_TYPE,
      device_code: deviceCode,
      client_id: "compat-device-client",
    },
  });

  return {
    signup: ctx.snapshot(signup),
    deny: ctx.snapshot(deny),
    token: ctx.snapshot(token),
  };
});

compatScenario("device approve blocks already-processed codes", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase4-device-double-approve");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Device Double Approve User",
  });

  const code = await ctx.rawRequest({
    path: "/api/auth/device/code",
    method: "POST",
    json: {
      client_id: "compat-device-client",
    },
  });
  const userCode = asString(asRecord(code.body).user_code, "user_code");

  const firstApprove = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/device/approve",
    method: "POST",
    json: {
      userCode,
    },
  });

  const secondApprove = await ctx.rawRequest({
    actor: "primary",
    path: "/api/auth/device/approve",
    method: "POST",
    json: {
      userCode,
    },
  });

  return {
    signup: ctx.snapshot(signup),
    firstApprove: ctx.snapshot(firstApprove),
    secondApprove: ctx.snapshot(secondApprove),
  };
});

compatScenario("device token rejects a mismatched client id", async (ctx) => {
  const code = await ctx.rawRequest({
    path: "/api/auth/device/code",
    method: "POST",
    json: {
      client_id: "compat-device-client-a",
    },
  });
  const deviceCode = asString(asRecord(code.body).device_code, "device_code");

  const token = await ctx.rawRequest({
    path: "/api/auth/device/token",
    method: "POST",
    json: {
      grant_type: DEVICE_GRANT_TYPE,
      device_code: deviceCode,
      client_id: "compat-device-client-b",
    },
  });

  return {
    token: ctx.snapshot(token),
  };
});
