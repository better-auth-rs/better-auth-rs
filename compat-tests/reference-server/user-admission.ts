import { getCurrentAdapter } from "@better-auth/core/context";
import { emailOTP, phoneNumber, magicLink, anonymous } from "better-auth/plugins";
export function createUserAdmissionFixture(profile: string) {
  const enabled = profile.startsWith("user-admission");
  let mode = "allow";
  const events: any[] = [];
  let magicURL: string | null = null;
  const password = {hash: async (value: string) => `fixture:${value}`, verify: async ({hash,password}:any) => hash === `fixture:${password}`};
  return {
    enabled,
    emailAndPassword: enabled ? {password,autoSignIn:profile !== "user-admission-protected"} : {},
    user: enabled ? {async validateUserInfo(data: any, ctx: any) {
      const existing = data.user.email ? await ctx.context.internalAdapter.findUserByEmail(data.user.email) : null;
      events.push({source:data.source,email:data.user.email ?? null,name:data.user.name ?? null,
        emailVerified:data.user.emailVerified??null,hasId:data.user.id !== undefined,hasCreatedAt:data.user.createdAt instanceof Date,
        hasUpdatedAt:data.user.updatedAt instanceof Date,role:data.user.role ?? null,
        existing:!!existing,path:ctx.path ?? null,tag:ctx.request?.headers.get("x-admission-tag") ?? null,
        customBody:ctx.body?.customBody ?? null,sessionEmail:ctx.context.session?.user.email ?? null,
        username:data.user.username??null,bodyUsername:ctx.body?.username??null,bodyDisplayUsername:ctx.body?.displayUsername??null});
      if(mode === "rollback") await (await getCurrentAdapter(ctx.context.adapter)).create({model:"user",data:{email:"admission-audit@example.com",name:"Audit",emailVerified:false,createdAt:new Date(),updatedAt:new Date()}});
      if(mode === "throw") throw new Error("private admission failure");
      if(mode === "deny" || mode === "rollback") return {error:"application_denied",errorDescription:"Application denied user"};
      if(mode === "bare") return {error:"application_denied"};
      if(mode === "empty") return {error:""};
    }} : {},
    plugins: enabled ? [
      emailOTP({generateOTP:()=>"123456",sendVerificationOTP:async()=>{}}),
      phoneNumber({sendOTP:async()=>{},verifyOTP:async({code})=>code==="246810",signUpOnVerification:{getTempEmail:phone=>`${phone}@phone.example.com`}}),
      magicLink({sendMagicLink:async({url})=>{magicURL=url;}}),
      anonymous({generateName:()=>"Admission Guest"}),
    ] : [],
    reset(){mode="allow";events.length=0;magicURL=null;},
    async route(request:Request,auth:any):Promise<Response|null>{
      if(!enabled || new URL(request.url).pathname!=="/__test/user-admission" || request.method!=="POST")return null;
      const body=await request.json();
      if(body.mode)mode=body.mode;
      if(body.clear)events.length=0;
      const ctx=await auth.$context;
      const user=body.email ? (await ctx.internalAdapter.findUserByEmail(body.email))?.user : null;
      if(body.promote && user)await ctx.internalAdapter.updateUser(user.id,{role:"admin",emailVerified:true});
      const accounts=user ? await ctx.internalAdapter.findAccounts(user.id) : [];
      const audit=await ctx.internalAdapter.findUserByEmail("admission-audit@example.com");
      return Response.json({events,magicURL,exists:!!user,auditExists:!!audit,accounts:accounts.map((account:any)=>({providerId:account.providerId,accessToken:account.accessToken ?? null}))});
    },
  };
}
