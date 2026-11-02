import assert from 'node:assert/strict';import {createHash} from 'node:crypto';import {captureBlob} from '../active-system/gateway_service/vendor/js-sha256/verify-worker.mjs';
for(const n of [0,1,262143,262144,262145,4*1024*1024+7]){
 const data=new Uint8Array(n);for(let i=0;i<n;i++)data[i]=(i*53+7)&255;const expected=createHash('sha256').update(data).digest('hex');
 let max=0,reads=0;const old=Blob.prototype.arrayBuffer;Blob.prototype.arrayBuffer=function(){reads++;max=Math.max(max,this.size);return old.call(this)};
 try{const captured=await captureBlob(new Blob([data]));assert.equal(captured.blob.size,n);assert.equal(captured.sha256,expected);assert.ok(max<=262144);assert.equal(createHash('sha256').update(Buffer.from(await old.call(captured.blob))).digest('hex'),expected);if(n)assert.ok(reads>=2)}finally{Blob.prototype.arrayBuffer=old}
}
let checks=0;await assert.rejects(captureBlob(new Blob([new Uint8Array(1048576)]),()=>{if(++checks===2)throw Error('cancelled')}),/cancelled/);
class Changing extends Blob{constructor(){super([new Uint8Array(600000)]);this.calls=0}slice(a,b){this.calls++;const value=new Uint8Array(b-a);if(this.calls>3)value[0]=1;return new Blob([value])}}
await assert.rejects(captureBlob(new Changing()),/Source changed/);
console.log('PASS bounded two-pass capture, hashes, cancellation and changing source');
