import { compatScenario } from "../../support/scenario";
import { adminActor, signUpAndPromoteAdmin } from "../phase9/helpers";

function extractState(url: string | undefined) {
  if (!url) {
    throw new Error("missing OAuth URL");
  }
  const state = new URL(url).searchParams.get("state");
  if (!state) {
    throw new Error("missing OAuth state");
  }
  return state;
}

function summarizeLocation(location: string | null) {
  if (!location) {
    throw new Error("missing redirect location");
  }
  const url = new URL(location, "http://compat.local");
  return {
    pathname: url.pathname,
    params: Object.fromEntries(url.searchParams.entries()),
  };
}

compatScenario("admin ban, unban, and user-session routes match TS", async (ctx) => {
  const admin = await signUpAndPromoteAdmin(ctx, "admin", "phase10-admin-stateful", "Phase 10 Admin");
  const target = adminActor(ctx, "target");
  const targetEmail = ctx.uniqueEmail("phase10-target");
  const signUp = await target.client.signUp.email({
    email: targetEmail,
    password: "password123",
    name: "Phase 10 Target",
  });
  const targetId = signUp.data?.user.id ?? "";

  await target.client.signIn.email({
    email: targetEmail,
    password: "password123",
  });

  const listBeforeBan = await admin.adminClient.admin.listUserSessions({
    userId: targetId,
  });

  const banUser = await admin.adminClient.admin.banUser({
    userId: targetId,
    banReason: "phase10 ban",
    banExpiresIn: 60 * 60,
  });

  const listAfterBan = await admin.adminClient.admin.listUserSessions({
    userId: targetId,
  });

  const unbanUser = await admin.adminClient.admin.unbanUser({
    userId: targetId,
  });

  await target.client.signIn.email({
    email: targetEmail,
    password: "password123",
  });
  await target.client.signIn.email({
    email: targetEmail,
    password: "password123",
  });

  const listBeforeRevoke = await admin.adminClient.admin.listUserSessions({
    userId: targetId,
  });
  const revokeSingle = await admin.adminClient.admin.revokeUserSession({
    sessionToken: listBeforeRevoke.data?.sessions[0]?.token ?? "",
  });
  const listAfterSingle = await admin.adminClient.admin.listUserSessions({
    userId: targetId,
  });
  const listMissing = await admin.adminClient.admin.listUserSessions({
    userId: "missing-user",
  });
  const revokeMissing = await admin.adminClient.admin.revokeUserSessions({
    userId: "missing-user",
  });
  const revokeAll = await admin.adminClient.admin.revokeUserSessions({
    userId: targetId,
  });
  const listAfterAll = await admin.adminClient.admin.listUserSessions({
    userId: targetId,
  });

  return {
    listBeforeBan: ctx.snapshot(listBeforeBan),
    banUser: ctx.snapshot(banUser),
    listAfterBan: ctx.snapshot(listAfterBan),
    unbanUser: ctx.snapshot(unbanUser),
    listBeforeRevoke: ctx.snapshot(listBeforeRevoke),
    revokeSingle: ctx.snapshot(revokeSingle),
    listAfterSingle: ctx.snapshot(listAfterSingle),
    listMissing: ctx.snapshot(listMissing),
    revokeMissing: ctx.snapshot(revokeMissing),
    revokeAll: ctx.snapshot(revokeAll),
    listAfterAll: ctx.snapshot(listAfterAll),
  };
});

compatScenario("banned users are denied email and social session creation", async (ctx) => {
  const admin = await signUpAndPromoteAdmin(ctx, "admin", "phase10-banned", "Phase 10 Admin");
  const target = adminActor(ctx, "target");
  const targetEmail = ctx.uniqueEmail("phase10-banned-user");
  const targetPassword = "password123";
  const signUp = await target.client.signUp.email({
    email: targetEmail,
    password: targetPassword,
    name: "Banned User",
  });
  const targetId = signUp.data?.user.id ?? "";

  await admin.adminClient.admin.banUser({
    userId: targetId,
    banReason: "phase10 banned",
  });

  const emailSignIn = await target.client.signIn.email({
    email: targetEmail,
    password: targetPassword,
  });

  await ctx.setSocialProfile({
    email: targetEmail,
    sub: ctx.uniqueToken("phase10-banned-social"),
    name: "Banned Social User",
    emailVerified: true,
    idTokenValid: true,
  });

  const socialSignIn = await target.client.signIn.social({
    provider: "google",
    callbackURL: "/dashboard",
  });
  const state = extractState(socialSignIn.data?.url);
  const callback = await ctx.rawRequest({
    actor: "target",
    path: `/api/auth/callback/google?code=compat-code&state=${encodeURIComponent(state)}`,
    redirect: "manual",
  });
  const callbackLocation = summarizeLocation(callback.location);
  const session = await target.client.getSession();

  return {
    emailSignIn: ctx.snapshot(emailSignIn),
    socialSignIn: {
      redirect: socialSignIn.data?.redirect,
      hasState: Boolean(state),
    },
    callback: {
      status: callback.status,
      pathname: callbackLocation.pathname,
      params: callbackLocation.params,
    },
    session: ctx.snapshot(session),
  };
});

compatScenario("admin impersonation restores the original admin session and hides impersonated sessions", async (ctx) => {
  const admin = await signUpAndPromoteAdmin(ctx, "admin", "phase10-impersonate", "Phase 10 Admin");
  const target = adminActor(ctx, "target");
  const targetEmail = ctx.uniqueEmail("phase10-impersonated-user");
  const targetPassword = "password123";
  const signUp = await target.client.signUp.email({
    email: targetEmail,
    password: targetPassword,
    name: "Impersonated User",
  });
  const targetId = signUp.data?.user.id ?? "";

  const impersonate = await admin.adminClient.admin.impersonateUser({
    userId: targetId,
  });
  const impersonatedSession = await admin.client.getSession();

  const directSignIn = await target.client.signIn.email({
    email: targetEmail,
    password: targetPassword,
  });
  const listedSessions = await target.client.listSessions();

  const stopImpersonating = await admin.adminClient.admin.stopImpersonating({});
  const restoredSession = await admin.client.getSession();
  const adminListUsers = await admin.adminClient.admin.listUsers({
    query: {
      filterField: "role",
      filterOperator: "eq",
      filterValue: "admin",
    },
  });

  return {
    impersonate: {
      data: {
        hasImpersonatedBy: Boolean(impersonate.data?.session?.impersonatedBy),
        user: ctx.snapshot(impersonate.data?.user),
      },
      error: ctx.snapshot(impersonate.error),
    },
    impersonatedSession: {
      data: {
        hasImpersonatedBy: Boolean(impersonatedSession.data?.session?.impersonatedBy),
        user: ctx.snapshot(impersonatedSession.data?.user),
      },
      error: ctx.snapshot(impersonatedSession.error),
    },
    directSignIn: ctx.snapshot(directSignIn),
    listedSessions: ctx.snapshot(listedSessions),
    stopImpersonating: ctx.snapshot(stopImpersonating),
    restoredSession: ctx.snapshot(restoredSession),
    adminListUsers: ctx.snapshot(adminListUsers),
  };
});
