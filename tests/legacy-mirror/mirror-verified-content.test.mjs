import assert from 'node:assert/strict';
import {indexedDB,IDBKeyRange} from 'fake-indexeddb';
import {MirroredFiles} from '../../active-system/storage/browser/mirror.mjs';
globalThis.indexedDB=indexedDB;globalThis.IDBKeyRange=IDBKeyRange;
Object.defineProperty(globalThis,'navigator',{value:{locks:{request:async(_name,_options,fn)=>fn()}},configurable:true});
const data=new Map();
const content={
 async capture(blob){const id=crypto.randomUUID(),hash=[...new Uint8Array(await crypto.subtle.digest('SHA-256',await blob.arrayBuffer()))].map(x=>x.toString(16).padStart(2,'0')).join('');const ref={kind:'codi-opfs-content/1',path:'/content-'+id,generation:crypto.randomUUID(),size:blob.size,sha256:hash};data.set(id,blob);return ref},
 async read(ref){return data.get(ref.path.slice('/content-'.length))},
 async acquire(ref){return {data:await this.read(ref),release(){}}}
};
const server={async list(){throw Error('offline')}};
const legacy=new MirroredFiles({scope:'migration',server,retryMs:0});
const old=await legacy.write('/old.txt','old content');const raced=await legacy.write('/race.txt','first');legacy.close();
const m=new MirroredFiles({scope:'migration',server,content,retryMs:0});
assert.equal(await m.migrateContent('/old.txt',old.version),true);
let row=await m.read('/old.txt');assert.equal(row.version,old.version);assert.equal(row.status,'pending');assert.equal(new TextDecoder().decode(row.data),'old content');
assert.equal(await m.migrateContent('/old.txt',old.version),false);
const current=await m.write('/old.txt','new content',old.version);
assert.equal(new TextDecoder().decode((await m.read('/old.txt')).data),'new content');
const copied=await m.copyFile('/old.txt','/copy.txt',current.version);
assert.equal(new TextDecoder().decode((await m.read('/copy.txt')).data),'new content');
await m.remove('/copy.txt',copied.version);
await assert.rejects(()=>m.migrateContent('/old.txt',old.version),/changed/);
// A local edit while OPFS capture is in flight wins over the migration.
let release,started;
const entered=new Promise(r=>started=r),gate=new Promise(r=>release=r);
const slow={...content,async capture(blob){started();await gate;return content.capture(blob)}};
const otherTab=new MirroredFiles({scope:'migration',server,content:slow,retryMs:0});
const migrating=otherTab.migrateContent('/race.txt',raced.version);await entered;
await m.write('/race.txt','second',raced.version);release();
await assert.rejects(()=>migrating,/changed/i);
assert.equal(new TextDecoder().decode((await m.read('/race.txt')).data),'second');
otherTab.close();
const ctrl=new AbortController();
await assert.rejects(()=>m.readBounded('/old.txt',100,{signal:AbortSignal.abort()}),e=>e.name==='AbortError');
let releaseRead,enteredRead;const readEntered=new Promise(r=>enteredRead=r),readGate=new Promise(r=>releaseRead=r);
const slowRead={...content,async read(ref){enteredRead();await readGate;return content.read(ref)}};
const waiting=new MirroredFiles({scope:'migration',server,content:slowRead,retryMs:0});
const read=waiting.readBounded('/old.txt',100,{signal:ctrl.signal});await readEntered;ctrl.abort();
await assert.rejects(()=>read,e=>e.name==='AbortError');releaseRead();waiting.close();
// An aborted native Blob read can continue; its lease must not be released
// until the underlying browser operation actually settles.
let releaseBytes,bytesStarted,released=0;
const byteGate=new Promise(r=>releaseBytes=r),byteEntered=new Promise(r=>bytesStarted=r);
const held={...content,async acquire(ref){const blob=await content.read(ref);blob.arrayBuffer=()=>{bytesStarted();return byteGate};return {data:blob,release(){released++}}}};
const heldMirror=new MirroredFiles({scope:'migration',server,content:held,retryMs:0}),abortBytes=new AbortController();
const pendingBytes=heldMirror.readBounded('/old.txt',100,{signal:abortBytes.signal});await byteEntered;abortBytes.abort();
await assert.rejects(()=>pendingBytes,e=>e.name==='AbortError');assert.equal(released,0);
releaseBytes(new Uint8Array([1]).buffer);await new Promise(r=>setTimeout(r,0));assert.equal(released,1);heldMirror.close();
m.close();
const reopened=new MirroredFiles({scope:'migration',server,content,retryMs:0});
assert.equal(await (await reopened.readBlob('/old.txt')).data.text(),'new content');
const other=new MirroredFiles({scope:'other',server,content,retryMs:0});
await assert.rejects(()=>other.read('/old.txt'),/not found/i);
other.close();reopened.close();
console.log('PASS opt-in content adapter migration, versions, reopen and account scope');
