import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { asArray, asRecord, signUpUser, type CompatContext } from "../../phase6/helpers";
import { requests } from "../organization-extended/helpers";

async function verifyEmail(ctx: CompatContext, actor: string, email: string) {
  const sent = await ctx.actor(actor).client.sendVerificationEmail({ email });
  expect(sent.error).toBeNull();
  const message = asRecord(await ctx.readVerificationEmail({ email }));
  const verified = await ctx.rawRequest({ actor, path: `/api/auth/verify-email?token=${encodeURIComponent(String(message.token))}` });
  expect(verified.status).toBe(200);
}

export function invitationOptions(requireVerified: boolean) {
  compatScenario("re-inviting cancels the previous invitation before capacity and team checks; resend preserves identity", async (ctx) => {
    await signUpUser(ctx, "owner", "replace-owner", "Owner");
    const { call, observations } = requests(ctx);
    const org = asRecord(await call("owner", "create", { name: "Invitation Options", slug: ctx.uniqueToken("replace") }));
    const input = { organizationId: org.id, email: ctx.uniqueEmail("recipient"), role: "member" };
    const first = asRecord(await call("owner", "invite-member", input));
    const replacement = asRecord(await call("owner", "invite-member", { ...input, role: "admin" }));
    expect(replacement.id).not.toBe(first.id);
    const resent = asRecord(await call("owner", "invite-member", { ...input, resend: true, teamId: "unknown-team" }));
    expect(resent.id).toBe(replacement.id);
    expect(resent.role).toBe("admin");
    const list = asArray(await call("owner", `list-invitations?organizationId=${org.id}`)).map(asRecord);
    expect(list).toHaveLength(2);
    expect(list.find((item) => item.id === first.id)?.status).toBe("canceled");
    expect(list.find((item) => item.id === replacement.id)?.status).toBe("pending");
    await call("owner", "invite-member", { ...input, teamId: "unknown-team" }, 400);
    const canceled = asArray(await call("owner", `list-invitations?organizationId=${org.id}`)).map(asRecord);
    expect(canceled).toHaveLength(2);
    expect(canceled.every((item) => item.status === "canceled")).toBe(true);
    const latest = asRecord(await call("owner", "invite-member", input));
    expect(latest.id).not.toBe(replacement.id);
    return observations;
  });

  compatScenario("invitation recipient, verification and pending-state guards apply to lookup, accept and reject", async (ctx) => {
    await signUpUser(ctx, "owner", "guard-owner", "Owner");
    const recipient = await signUpUser(ctx, "recipient", "guard-recipient", "Recipient");
    const rejector = await signUpUser(ctx, "rejector", "guard-rejector", "Rejector");
    const { call, observations } = requests(ctx);
    const org = asRecord(await call("owner", "create", { name: "Invitation Guards", slug: ctx.uniqueToken("guards") }));
    const invitation = asRecord(await call("owner", "invite-member", { organizationId: org.id, email: recipient.email, role: "member" }));
    const lookup = `get-invitation?id=${invitation.id}`;
    await call("anonymous", lookup, undefined, 401);
    await call("owner", lookup, undefined, 403);
    await call("recipient", "list-user-invitations", undefined, 403);
    await call("recipient", lookup, undefined, requireVerified ? 403 : 200);
    if (requireVerified) {
      await call("recipient", "accept-invitation", { invitationId: invitation.id }, 403);
      await call("recipient", "reject-invitation", { invitationId: invitation.id }, 403);
      await verifyEmail(ctx, "recipient", recipient.email);
      await call("recipient", lookup);
    }
    const accepted = asRecord(await call("recipient", "accept-invitation", { invitationId: invitation.id }));
    expect(asRecord(accepted.invitation).status).toBe("accepted");
    expect(asRecord(accepted.member).userId).toBe(recipient.signup.data!.user.id);
    await call("recipient", lookup, undefined, 400);
    await call("owner", lookup, undefined, 400);
    await call("recipient", "accept-invitation", { invitationId: invitation.id }, 400);
    await call("recipient", "reject-invitation", { invitationId: invitation.id }, 400);
    const toReject = asRecord(await call("owner", "invite-member", { organizationId: org.id, email: rejector.email, role: "member" }));
    if (requireVerified) await verifyEmail(ctx, "rejector", rejector.email);
    const rejected = asRecord(await call("rejector", "reject-invitation", { invitationId: toReject.id }));
    expect(asRecord(rejected.invitation).status).toBe("rejected");
    const memberId = asRecord(accepted.member).id;
    await call("owner", "update-member-role", { organizationId: org.id, memberId, role: "admin" });
    const departedInviter = asRecord(await call("recipient", "invite-member", { organizationId: org.id, email: rejector.email, role: "member" }));
    await call("owner", "remove-member", { organizationId: org.id, memberIdOrEmail: memberId });
    const unavailable = asRecord(await call("rejector", `get-invitation?id=${departedInviter.id}`, undefined, 400));
    expect(unavailable.code).toBe("INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION");
    const acceptedAfterDeparture = asRecord(await call("rejector", "accept-invitation", { invitationId: departedInviter.id }));
    expect(asRecord(acceptedAfterDeparture.invitation).status).toBe("accepted");
    await call("recipient", "get-invitation?id=missing", undefined, 400);
    await call("recipient", "accept-invitation", { invitationId: "missing" }, 400);
    await call("recipient", "reject-invitation", { invitationId: "missing" }, 400);
    return observations;
  });
}
