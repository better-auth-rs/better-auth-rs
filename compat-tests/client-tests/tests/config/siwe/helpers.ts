import {expect} from "bun:test";
import {secp256k1} from "@noble/curves/secp256k1.js";
import {keccak_256} from "@noble/hashes/sha3.js";
import {bytesToHex,utf8ToBytes} from "@noble/hashes/utils.js";
import {post,type Context} from "../phone-number/helpers";
export {post,control,error} from "../phone-number/helpers";
const secret=new Uint8Array(32);secret[31]=1;
export const address=`0x${bytesToHex(keccak_256(secp256k1.getPublicKey(secret,false).slice(1)).slice(-20))}`;
export function sign(message:string,key=secret){const hash=keccak_256(utf8ToBytes(`\x19Ethereum Signed Message:\n${new TextEncoder().encode(message).length}${message}`));const signature=secp256k1.sign(hash,key,{prehash:false,format:"recovered"});return `0x${bytesToHex(new Uint8Array([...signature.slice(1),signature[0]+27]))}`;}
export async function signed(ctx:Context,options:{domain?:string;chainId?:number;extra?:string;alias?:boolean}={}){
 const result=await post(ctx,options.alias?"/siwe/get-nonce":"/siwe/nonce",{});expect(result.status).toBe(200);expect(result.body.nonce).toMatch(/^[a-zA-Z0-9]{8,250}$/);
 const message=`${options.domain??"wallet.example.com"} wants you to sign in with your Ethereum account:\n${address}\n\nSign in to the compatibility suite.\n\nURI: https://wallet.example.com\nVersion: 1\nChain ID: ${options.chainId??1}\nNonce: ${result.body.nonce}\nIssued At: 2026-09-30T00:00:00.000Z${options.extra??""}`;
 return {message,signature:sign(message)};
}
