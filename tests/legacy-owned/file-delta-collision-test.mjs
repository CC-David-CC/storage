import {createHash,webcrypto} from 'node:crypto';import assert from 'node:assert/strict';
import {deltaBlob} from '../active-system/gateway_service/vendor/js-sha256/verify-worker.mjs';
const block=65536,weak=787416541;let calls=0;
const original=globalThis.crypto;Object.defineProperty(globalThis,'crypto',{configurable:true,value:{subtle:{digest(...args){calls++;return webcrypto.subtle.digest(...args)}}}});
try{
 const data=new Uint8Array(1024*1024);for(let i=0;i<data.length;i++)data[i]=[101,98,101,100][i%4];
 const sig={version:'codi-file-delta/1',size:block,block,chunks:[[weak,'f'.repeat(64)]]};
 assert.equal(await deltaBlob(new Blob([data]),sig),null);assert.equal(calls,64,'failed strong hashes must be bounded');
 calls=0;let checks=0;await assert.rejects(deltaBlob(new Blob([data]),sig,()=>{if(++checks===2)throw Error('closed')}),/closed/);assert.equal(calls,1,'cancellation must stop after the awaited digest');
 const zeros=new Uint8Array(block);let a=1,b=0;for(let i=0;i<block;i++){a%=65521;b=(b+a)%65521}const weakZero=(b*65536+a)>>>0,strong=createHash('sha256').update(zeros).digest('hex');
 const full=new Blob(Array.from({length:2048},()=>zeros)),fullsig={version:'codi-file-delta/1',size:full.size,block,chunks:Array.from({length:2048},()=>[weakZero,strong])};calls=0;
 const result=await deltaBlob(full,fullsig);assert.ok(result instanceof Blob&&result.size<100000);assert.equal(calls,2048,'successful matches must not consume failed-match budget');
 console.log('PASS worker delta collision budget, cancellation and 128 MiB successful matching');
}finally{Object.defineProperty(globalThis,'crypto',{configurable:true,value:original})}
