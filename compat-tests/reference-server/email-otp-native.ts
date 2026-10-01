import { emailOTP } from "better-auth/plugins";
import { APIError } from "better-auth/api";
export function createEmailOtpNativeFixture(profile:string) {
 const enabled=profile.startsWith("email-otp-native");
 const state={generated:0,sent:0,encoded:0,decoded:0,fail:"",events:[] as any[]};
 const reject=()=>{throw new APIError("BAD_REQUEST",{code:"NATIVE_OTP_REJECTED",message:"Native OTP rejected"});};
 const storeOTP=profile.endsWith("custom-hash")?{hash:async(otp:string)=>{state.encoded++;if(state.fail==="encode")reject();return `hash:${otp}`;}}
   :profile.endsWith("custom-encrypted")?{encrypt:async(otp:string)=>{state.encoded++;if(state.fail==="encode")reject();return `sealed:${otp}`;},decrypt:async(stored:string)=>{state.decoded++;if(state.fail==="decode" || !stored.startsWith("sealed:"))reject();return stored.slice(7);}}
   :profile.endsWith("-hash")?"hashed":profile.endsWith("-encrypted")?"encrypted":"plain";
 return {
  enabled,
  plugins:enabled?[emailOTP({disableSignUp:true,resendStrategy:"reuse",storeOTP,
   generateOTP(data,ctx){state.generated++;state.events.push({data,body:ctx?.body??null,path:ctx?.path??null,hasRequest:!!ctx?.request});if(state.fail==="generate")reject();return `${String(state.generated).padStart(6,"0")}:tail`;},
   async sendVerificationOTP(){state.sent++;},
  })]:[],
  reset(){state.generated=0;state.sent=0;state.encoded=0;state.decoded=0;state.fail="";state.events.length=0;},
  async route(request:Request,auth:any):Promise<Response|null>{
   if(!enabled||new URL(request.url).pathname!=="/__test/email-otp-native"||request.method!=="POST")return null;
   const body=await request.json();if(body.fail!==undefined)state.fail=body.fail;
   const type=body.type??"sign-in",email=body.email??"Missing@Example.com";
   try {
    if(body.action==="create")return Response.json(await auth.api.createVerificationOTP({body:{email,type}}));
    if(body.action==="get")return Response.json(await auth.api.getVerificationOTP({query:{email,type}}));
    const ctx=await auth.$context;const identifier=`${type}-otp-${email.toLowerCase()}`;
    if(body.action==="expire")await ctx.internalAdapter.updateVerificationByIdentifier(identifier,{expiresAt:new Date(Date.now()-1000)});
    if(body.action==="tamper")await ctx.internalAdapter.updateVerificationByIdentifier(identifier,{value:"broken:0"});
    const record=await ctx.internalAdapter.findVerificationValue(identifier);
    return Response.json({...state,exists:!!record,expiresAt:record?.expiresAt?.toISOString()??null,attempts:record?Number(record.value.slice(record.value.lastIndexOf(":")+1)):null});
   }catch(error:any){if(error instanceof APIError)return Response.json(error.body,{status:error.statusCode});throw error;}
  },
 };
}
