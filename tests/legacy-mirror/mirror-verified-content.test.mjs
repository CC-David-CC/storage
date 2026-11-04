import assert from 'node:assert/strict';
import {indexedDB,IDBKeyRange} from 'fake-indexeddb';
import {MirroredFiles} from '../active-system/storage/browser/mirror.mjs';
globalThis.indexedDB=indexedDB;globalThis.IDBKeyRange=IDBKeyRange;
const data=new Map();
const content={
 async capture(blob){const id=crypto.randomUUID(),hash=[...new Uint8Array(await crypto.subtle.digest('SHA-256',await blob.arrayBuffer()))].map(x=>x.toString(16).padStart(2,'0')).join('');const ref={kind:'codi-opfs-content/1',path:'/content-'+id,generation:crypto.randomUUID(),size:blob.size,sha256:hash};data.set(id,blob);return ref},
 async read(ref){return data.get(ref.path.slice('/content-'.length))}
};
const server={async list(){throw Error('offline')}};
const legacy=new MirroredFiles({scope:'migration',server,retryMs:0});
const old=await legacy.write('/old.txt','old content');legacy.close();
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
const raceLegacy=new MirroredFiles({scope:'migration',server,retryMs:0});const raced=await raceLegacy.write('/race.txt','first');raceLegacy.close();let release,started;
const entered=new Promise(r=>started=r),gate=new Promise(r=>release=r);
const slow={...content,async capture(blob){started();await gate;return content.capture(blob)}};
const otherTab=new MirroredFiles({scope:'migration',server,content:slow,retryMs:0});
const migrating=otherTab.migrateContent('/race.txt',raced.version);await entered;
await m.write('/race.txt','second',raced.version);release();
await assert.rejects(()=>migrating,/changed/i);
assert.equal(new TextDecoder().decode((await m.read('/race.txt')).data),'second');
otherTab.close();
m.close();
const reopened=new MirroredFiles({scope:'migration',server,content,retryMs:0});
assert.equal(await (await reopened.readBlob('/old.txt')).data.text(),'new content');
const other=new MirroredFiles({scope:'other',server,content,retryMs:0});
await assert.rejects(()=>other.read('/old.txt'),/not found/i);
other.close();reopened.close();
console.log('PASS opt-in content adapter migration, versions, reopen and account scope');
