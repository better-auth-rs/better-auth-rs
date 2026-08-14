import { compatScenario } from "../../support/scenario";
import { adminActor, signUpAndPromoteAdmin } from "./helpers";

compatScenario("admin get-user and update-user match TS", async (ctx) => {
  const admin = await signUpAndPromoteAdmin(ctx, "admin", "phase9-admin-get", "Phase 9 Admin");
  const targetEmail = ctx.uniqueEmail("phase9-target");

  const createUser = await admin.adminClient.admin.createUser({
    email: targetEmail,
    password: "password123",
    name: "Phase 9 Target",
  });

  const targetId = createUser.data?.user.id ?? "";

  const getUser = await admin.adminClient.admin.getUser({
    query: {
      id: targetId,
    },
  });

  const updateUser = await admin.adminClient.admin.updateUser({
    userId: targetId,
    data: {
      name: "Updated Phase 9 Target",
      role: "admin",
    },
  });

  return {
    createUser: ctx.snapshot(createUser),
    getUser: ctx.snapshot(getUser),
    updateUser: ctx.snapshot(updateUser),
  };
});

compatScenario("admin create-user, set-role, set-user-password, and remove-user match TS", async (ctx) => {
  const admin = await signUpAndPromoteAdmin(ctx, "admin", "phase9-admin-crud", "Phase 9 Admin");
  const createdEmail = ctx.uniqueEmail("phase9-created");
  const passwordlessEmail = ctx.uniqueEmail("phase9-passwordless");

  const createUser = await admin.adminClient.admin.createUser({
    email: createdEmail,
    password: "password123",
    name: "Created User",
    role: ["user", "admin"],
  });

  const createPasswordlessUser = await admin.adminClient.admin.createUser({
    email: passwordlessEmail,
    name: "Passwordless User",
    role: "user",
  });

  const duplicateEmail = await admin.adminClient.admin.createUser({
    email: createdEmail,
    password: "password123",
    name: "Duplicate User",
  });

  const createdUserId = createUser.data?.user.id ?? "";
  const setRole = await admin.adminClient.admin.setRole({
    userId: createdUserId,
    role: ["admin", "user"],
  });

  const setUserPassword = await admin.adminClient.admin.setUserPassword({
    userId: createdUserId,
    newPassword: "newpassword123",
  });

  const signInWithNewPassword = await admin.client.signIn.email({
    email: createdEmail,
    password: "newpassword123",
  });

  const removeUser = await admin.adminClient.admin.removeUser({
    userId: createdUserId,
  });

  const passwordlessSignIn = await admin.client.signIn.email({
    email: passwordlessEmail,
    password: "anypassword123",
  });

  return {
    createUser: ctx.snapshot(createUser),
    createPasswordlessUser: ctx.snapshot(createPasswordlessUser),
    duplicateEmail: ctx.snapshot(duplicateEmail),
    setRole: ctx.snapshot(setRole),
    setUserPassword: ctx.snapshot(setUserPassword),
    signInWithNewPassword: {
      dataPresent: signInWithNewPassword.data !== null,
      error: ctx.snapshot(signInWithNewPassword.error),
    },
    removeUser: ctx.snapshot(removeUser),
    passwordlessSignIn: ctx.snapshot(passwordlessSignIn),
  };
});

compatScenario("admin list-users and has-permission match TS", async (ctx) => {
  const admin = await signUpAndPromoteAdmin(ctx, "admin", "phase9-admin-list", "Phase 9 Admin");
  const member = adminActor(ctx, "member");
  const memberEmail = ctx.uniqueEmail("phase9-member");
  await member.client.signUp.email({
    email: memberEmail,
    password: "password123",
    name: "Phase 9 Member",
  });

  await admin.adminClient.admin.createUser({
    email: ctx.uniqueEmail("phase9-list-user"),
    password: "password123",
    name: "Alpha User",
    role: "user",
  });

  const listUsers = await admin.adminClient.admin.listUsers({
    query: {
      limit: 2,
      offset: 0,
      searchField: "name",
      searchOperator: "contains",
      searchValue: "User",
      sortBy: "name",
      sortDirection: "asc",
      filterField: "role",
      filterOperator: "contains",
      filterValue: "user",
    },
  });

  const adminHasPermission = await admin.adminClient.admin.hasPermission({
    permissions: {
      user: ["create", "update"],
    },
  });

  const memberHasPermission = await member.adminClient.admin.hasPermission({
    permissions: {
      user: ["create"],
    },
  });

  return {
    listUsers: ctx.snapshot(listUsers),
    adminHasPermission: ctx.snapshot(adminHasPermission),
    memberHasPermission: ctx.snapshot(memberHasPermission),
  };
});
