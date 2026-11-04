import assert from 'node:assert/strict';
import {indexedDB,IDBKeyRange} from 'fake-indexeddb';
import {MirroredFiles} from '../active-system/storage/browser/mirror.mjs';
globalThis.indexedDB=indexedDB;globalThis.IDBKeyRange=IDBKeyRange;
const digest=async blob=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',await blob.arrayBuffer()))].map(x=>x.toString(16).padStart(2,'0')).join('');
let captures=0,fail=false;
const server={
 async list(){throw Error('offline')},
 async captureSnapshot(blob,{signal}){assert.equal(signal.aborted,false);captures++;if(fail)return {blob,sha256:'invalid'};return {blob,sha256:await digest(blob)}}
};
const mirror=new MirroredFiles({scope:'test:archive-worker',server,retryMs:0});
const zip=await mirror.write('/archive.zip',new Uint8Array([1,2,3]));
captures=0;
await mirror.importTree('/expanded',[
 {path:'/expanded/a.txt',directory:false,data:new TextEncoder().encode('hello')},
 {path:'/expanded/nested',directory:true},
 {path:'/expanded/nested/b.txt',directory:false,data:new Uint8Array([4,5])}
],'/archive.zip',zip.version);
assert.equal(captures,2);
assert.equal(new TextDecoder().decode((await mirror.read('/expanded/a.txt')).data),'hello');
fail=true;
await assert.rejects(()=>mirror.importTree('/failed',[{path:'/failed/no.txt',directory:false,data:new Uint8Array([7])}],'/archive.zip',zip.version),/Invalid file capture/);
assert.equal((await mirror.list('/')).entries.some(x=>x.path==='/failed'),false);
mirror.close();
console.log('PASS worker archive capture and all-or-nothing publication');
