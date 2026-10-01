import {test,expect} from "bun:test";
import {betterAuth} from "better-auth";
import {emailOTP} from "better-auth/plugins";
for(const custom of [false,true])test(`configured sender precedence ${custom}`,async()=>{
 const calls:string[]=[];
 const auth=betterAuth({baseURL:"http://localhost:3000",secret:"priority-contract-secret-longer-than-thirty-two",rateLimit:{enabled:false},
  emailAndPassword:{enabled:true,password:{hash:async()=>"fixture",verify:async()=>true}},
  emailVerification:{sendOnSignUp:true,...custom?{sendVerificationEmail:()=>{calls.push("configured");}}:{}},
  plugins:[emailOTP({overrideDefaultEmailVerification:true,sendVerificationOTP:()=>{calls.push("otp");}})]});
 await auth.api.signUpEmail({body:{name:"Owner",email:"owner@example.com",password:"fixture-password"}});
 await auth.api.sendVerificationEmail({body:{email:"owner@example.com"}});
 expect(calls).toEqual(Array(2).fill(custom?"configured":"otp"));
});
