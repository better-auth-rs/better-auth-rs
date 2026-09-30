import { emailOTP, phoneNumber } from "better-auth/plugins";
import { APIError } from "better-auth/api";
export function createOtpCallbacksFixture(profile: string) {
  const events: any[] = [];
  const event = (name: string, data: unknown, ctx: any) => events.push({
    name, data, path: ctx.path ?? null,
    requestPath: ctx.request ? new URL(ctx.request.url).pathname.replace(/^\/api\/auth/, "") : null,
    body: ctx.body, header: ctx.request?.headers.get("x-callback-tag") ?? null,
    basePath: ctx.context.options.basePath ?? "/api/auth",
    hasResponse: ctx.context.returned !== undefined,
    sessionEmail: ctx.context.session?.user.email ?? null,
  });
  const fail = (ctx: any, name: string) => {
    if (ctx.request?.headers.get("x-callback-fail") === name) throw new APIError("BAD_REQUEST", {code:"CALLBACK_REJECTED",message:"Callback rejected"});
  };
  return {
    plugins: [emailOTP({
      sendVerificationOnSignUp: true,
      overrideDefaultEmailVerification: profile === "otp-callbacks-override",
      changeEmail: {enabled: true},
      generateOTP(data, ctx) { event("email.generate",data,ctx); fail(ctx,"generate"); return "123456"; },
      async sendVerificationOTP(data, ctx) {
        const user=await ctx!.context.internalAdapter.findUserByEmail(data.email);
        event("email.send",{email:data.email,type:data.type,userExists:!!user},ctx);
        fail(ctx,"email-send");
      },
    }), phoneNumber({
      requireVerification:true,
      signUpOnVerification:{getTempEmail:phone=>`${phone}@phone.example.com`},
      async sendOTP(data, ctx) {
        const user=await ctx.context.adapter.findOne({model:"user",where:[{field:"phoneNumber",value:data.phoneNumber}]});
        event("phone.send",{phoneNumber:data.phoneNumber,userExists:!!user},ctx); fail(ctx,"phone-send");
      },
      async sendPasswordResetOTP(data, ctx) {
        const user=await ctx.context.adapter.findOne({model:"user",where:[{field:"phoneNumber",value:data.phoneNumber}]});
        event("phone.reset",{phoneNumber:data.phoneNumber,userExists:!!user},ctx); fail(ctx,"phone-reset");
      },
      async verifyOTP(data, ctx) { event("phone.verify",{phoneNumber:data.phoneNumber},ctx); fail(ctx,"phone-verify"); return data.code==="246810"; },
      async callbackOnVerification(data,ctx) {
        const user=await ctx.context.internalAdapter.findUserById(data.user.id);
        event("phone.verified",{phoneNumber:data.phoneNumber,persistedVerified:user?.phoneNumberVerified,name:data.user.name},ctx); fail(ctx,"verified");
      },
    })],
    reset(){events.length=0;},
    async handle(request:Request):Promise<Response|null>{
      if(new URL(request.url).pathname!=="/__test/otp-callbacks"||request.method!=="POST")return null;
      const body=await request.json(); if(body.action==="clear")events.length=0;
      return Response.json(events);
    },
  };
}
