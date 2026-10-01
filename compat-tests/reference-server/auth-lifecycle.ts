import { APIError } from "better-auth/api";

export function createAuthLifecycleFixture(profile: string, database: any) {
  const enabled = profile.startsWith("auth-lifecycle");
  const confirmation = profile === "auth-lifecycle-confirmation";
  const zero = profile === "auth-lifecycle-zero";
  const events: unknown[] = [];
  let resetToken: string | null = null;
  let deleteToken: string | null = null;
  const record = (name: string, user: any, request?: Request) => {
    events.push({ name, email: user.email, userName: user.name, image: user.image ?? null,
      department: user.department, hasHidden: Object.hasOwn(user, "secretNote"),
      hasCreatedAt: !!user.createdAt, path: request ? new URL(request.url).pathname.replace(/^\/api\/auth/, "") : null,
      tag: request?.headers.get("x-lifecycle-tag") ?? null });
    if (request?.headers.get("x-lifecycle-fail") === name)
      throw new APIError("BAD_REQUEST", {code: "LIFECYCLE_REJECTED", message: "Lifecycle rejected"});
  };
  return {
    enabled,
    options: enabled ? {
      ...(zero ? {session: {freshAge: 0}} : {}),
      user: {additionalFields: {
        department: {type: "string" as const, required: false, defaultValue: "ops"},
        secretNote: {type: "string" as const, required: false, returned: false, defaultValue: "internal"},
      }},
    } : {},
    emailAndPassword: enabled ? {
      password: {hash: async (password:string)=>`fixture:${password}`, verify: async ({hash,password}:{hash:string,password:string})=>hash===`fixture:${password}`},
      ...(confirmation ? {resetPasswordTokenExpiresIn: 90} : zero ? {resetPasswordTokenExpiresIn: 0} : {}),
      revokeSessionsOnPasswordReset: true,
      async sendResetPassword(data: any, request?: Request) { resetToken=data.token; record("reset-send",data.user,request); },
      async onPasswordReset(data: any, request?: Request) { record("reset-complete",data.user,request); },
    } : {},
    deleteUser: enabled ? {
      enabled: true,
      ...(confirmation ? {async sendDeleteAccountVerification(data:any,request?:Request) { deleteToken=data.token; record("delete-send",data.user,request); }} : {}),
      async beforeDelete(user:any,request?:Request) { record("before-delete",user,request); },
      async afterDelete(user:any,request?:Request) { record("after-delete",user,request); },
    } : {},
    reset() { events.length=0; resetToken=null; deleteToken=null; },
    async route(request:Request, auth:any):Promise<Response|null> {
      if (!enabled || new URL(request.url).pathname !== "/__test/auth-lifecycle") return null;
      const body=await request.json(); const ctx=await auth.$context;
      if(body.action === "clear") events.length=0;
      if(body.action === "age") {
        const sessions=await ctx.adapter.findMany({model:"session",where:[{field:"userId",value:body.userId}]});
        for(const session of sessions) await ctx.adapter.update({model:"session",where:[{field:"id",value:session.id}],update:{createdAt:new Date(Date.now()-2*86400_000)}});
      }
      if(body.action === "add-account") {
        const account=await ctx.internalAdapter.createAccount({userId:body.userId,providerId:"lifecycle",accountId:"lifecycle-account"});
        return Response.json({accountId:account.id});
      }
      const user=body.userId ? await ctx.internalAdapter.findUserById(body.userId) : null;
      const accounts=body.userId ? await ctx.internalAdapter.findAccounts(body.userId) : [];
      const verification=resetToken ? await ctx.internalAdapter.findVerificationValue(`reset-password:${resetToken}`) : null;
      return Response.json({events,resetToken,deleteToken,userExists:!!user,accounts:accounts.length,
        resetLifetime:verification ? Math.round((verification.expiresAt.getTime()-verification.createdAt.getTime())/1000) : null});
    },
  };
}
