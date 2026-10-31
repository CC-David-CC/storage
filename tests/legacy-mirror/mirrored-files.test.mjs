import assert from 'node:assert/strict';
import {indexedDB,IDBKeyRange} from 'fake-indexeddb';
import {MirroredFiles,MirrorConflict,filePath} from '../active-system/storage/browser/mirror.mjs';
globalThis.indexedDB=indexedDB;globalThis.IDBKeyRange=IDBKeyRange;
const sha=async data=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',data))].map(b=>b.toString(16).padStart(2,'0')).join('');
class Server{
 constructor(){this.files=new Map();this.offline=false;this.drop=false;}
 check(){if(this.offline)throw Error('offline');}
 async list(path){this.check();const prefix=path?path+'/':'';return {entries:[...this.files].filter(([p])=>p.startsWith(prefix)&&!p.slice(prefix.length).includes('/')).map(([p,r])=>({name:p.slice(prefix.length),directory:r.directory,bytes:r.directory?null:r.data.length}))};}
 async read(path){this.check();const r=this.files.get(path);if(!r||r.directory)throw Object.assign(Error('missing'),{status:404});return {data:Uint8Array.from(r.data),sha256:await sha(r.data)};}
 async write(path,data,previous=null){this.check();const old=this.files.get(path),oldHash=old&&!old.directory?await sha(old.data):null;if(previous===null?!!old:!old||oldHash!==previous)throw Object.assign(Error('conflict'),{status:409});this.files.set(path,{directory:false,data:Uint8Array.from(data)});if(this.drop){this.drop=false;throw Error('lost reply');}return {sha256:await sha(data)};}
 async rename(source,destination,previous){this.check();const old=this.files.get(source);if(!old||old.directory||await sha(old.data)!==previous||this.files.has(destination))throw Object.assign(Error('conflict'),{status:409});this.files.set(destination,old);this.files.delete(source);if(this.drop){this.drop=false;throw Error('lost reply');}}
 async mkdir(path){this.check();if(this.files.has(path))throw Object.assign(Error('exists'),{status:409});this.files.set(path,{directory:true});}
 async remove(path,previous=null){this.check();const old=this.files.get(path);if(!old)throw Object.assign(Error('missing'),{status:404});if(!old.directory&&await sha(old.data)!==previous)throw Object.assign(Error('conflict'),{status:409});if(old.directory&&[...this.files.keys()].some(x=>x.startsWith(path+'/')))throw Error('not empty');this.files.delete(path);}
}
const pause=()=>new Promise(r=>setTimeout(r,0));
const server=new Server(),a=new MirroredFiles({scope:'issuer:user-a',server,retryMs:0}),b=new MirroredFiles({scope:'issuer:user-b',server:new Server(),retryMs:0});
assert.throws(()=>filePath('/../escape'));assert.throws(()=>filePath('/.secret'));
server.offline=true;const first=await a.write('/note.txt','offline');await pause();assert.equal((await a.read('/note.txt')).status,'pending');assert.deepEqual((await b.list('/')).entries,[]);
server.offline=false;await a.sync();assert.equal(new TextDecoder().decode((await server.read('note.txt')).data),'offline');assert.equal((await a.read('/note.txt')).status,'synced');
let local=await a.read('/note.txt');server.offline=true;await a.write('/note.txt','local edit',local.version);await pause();server.offline=false;server.files.set('note.txt',{directory:false,data:new TextEncoder().encode('other device')});await a.sync();local=await a.read('/note.txt');assert.equal(local.status,'conflict');assert.equal(new TextDecoder().decode(local.data),'local edit');assert.equal(new TextDecoder().decode((await server.read('note.txt')).data),'other device');
await a.resolve('/note.txt','local',local.version);await a.sync();assert.equal(new TextDecoder().decode((await server.read('note.txt')).data),'local edit');
server.files.set('note.txt',{directory:false,data:new TextEncoder().encode('remote refresh')});await a.sync();assert.equal(new TextDecoder().decode((await a.read('/note.txt')).data),'remote refresh');
server.offline=true;await a.mkdir('/folder');await pause();await a.write('/folder/one.txt','hello');await pause();server.offline=false;await a.sync();assert.equal(new TextDecoder().decode((await server.read('folder/one.txt')).data),'hello');
const item=await a.read('/folder/one.txt');await a.remove('/folder/one.txt',item.version);await a.sync();assert.equal(server.files.has('folder/one.txt'),false);
server.drop=true;await a.write('/lost.txt','saved once');await pause();await a.sync().catch(()=>{});await a.sync();assert.equal((await a.read('/lost.txt')).status,'synced');assert.equal(new TextDecoder().decode((await server.read('lost.txt')).data),'saved once');
// A move queues while offline, then atomically renames on the server.
await a.write('/moveme.txt','portable');await a.sync();const moved=await a.read('/moveme.txt');server.offline=true;await a.move('/moveme.txt','/folder/moveme.txt',moved.version);await pause();assert.equal((await a.read('/folder/moveme.txt')).status,'pending');const pendingMove=await a.read('/folder/moveme.txt');await assert.rejects(()=>a.write('/folder/moveme.txt','edit',pendingMove.version));
server.offline=false;server.drop=true;await a.sync().catch(()=>{});await a.sync();assert.equal(server.files.has('moveme.txt'),false);assert.equal(new TextDecoder().decode((await server.read('folder/moveme.txt')).data),'portable');assert.equal((await a.read('/folder/moveme.txt')).status,'synced');
// A server-side collision must leave both originals intact.
await a.write('/collision.txt','mine');await a.sync();const collision=await a.read('/collision.txt');server.offline=true;await a.move('/collision.txt','/folder/collision.txt',collision.version);await pause();server.files.set('folder/collision.txt',{directory:false,data:new TextEncoder().encode('theirs')});server.offline=false;await a.sync().catch(()=>{});assert.equal(new TextDecoder().decode((await a.read('/collision.txt')).data),'mine');assert.equal(new TextDecoder().decode((await server.read('folder/collision.txt')).data),'theirs');
// A remotely edited source must not be deleted by the queued move.
await a.write('/changed.txt','original');await a.sync();const changed=await a.read('/changed.txt');server.offline=true;await a.move('/changed.txt','/folder/changed.txt',changed.version);await pause();server.files.set('changed.txt',{directory:false,data:new TextEncoder().encode('remote change')});server.offline=false;await a.sync().catch(()=>{});assert.equal((await a.read('/changed.txt')).status,'conflict');assert.equal(new TextDecoder().decode((await a.read('/changed.txt')).data),'original');assert.equal(new TextDecoder().decode((await server.read('changed.txt')).data),'remote change');assert.equal(server.files.has('folder/changed.txt'),false);
// Atomic local operations: concurrent parent deletion and child creation must
// never leave an accessible child without its folder.
server.offline=true;await a.mkdir('/race');await pause();const folder=(await a.list('/')).entries.find(x=>x.path==='/race');
await Promise.allSettled([a.remove('/race',folder.version),a.write('/race/child.txt','x')]);
const root=await a.list('/');if(!root.entries.some(x=>x.path==='/race'))await assert.rejects(()=>a.list('/race'));else assert.equal((await a.list('/race')).entries.length,1);
// Different tabs sharing an account must not overwrite the same local version.
const tab=new MirroredFiles({scope:'issuer:user-a',server,retryMs:0});const before=await a.read('/note.txt');const attempts=await Promise.allSettled([a.write('/note.txt','one',before.version),tab.write('/note.txt','two',before.version)]);assert.equal(attempts.filter(x=>x.status==='fulfilled').length,1);tab.close();
// Previously saved ArrayBuffer records remain readable and synchronize after
// new writes switch to IndexedDB Blob storage.
const legacyBytes=new TextEncoder().encode('old local file'),legacyHash=await sha(legacyBytes);
await new Promise((resolve,reject)=>{const open=indexedDB.open('codi-mirrored-files-v1',1);open.onerror=()=>reject(open.error);open.onsuccess=()=>{const db=open.result,tx=db.transaction('files','readwrite');tx.objectStore('files').put({scope:'legacy-scope',path:'/legacy.txt',directory:false,data:legacyBytes.buffer,sha256:legacyHash,base:null,version:'legacy-version',dirty:true,deleted:false,conflict:false});tx.oncomplete=()=>{db.close();resolve();};tx.onerror=()=>reject(tx.error);};});
const legacy=new MirroredFiles({scope:'legacy-scope',server,retryMs:0});assert.equal(new TextDecoder().decode((await legacy.read('/legacy.txt')).data),'old local file');assert.equal((await legacy.list('/')).entries[0].bytes,legacyBytes.length);server.offline=false;await legacy.sync();assert.equal(new TextDecoder().decode((await server.read('legacy.txt')).data),'old local file');legacy.close();
// A retry timer must not perpetually restart a slow in-flight sync.
const slowServer=new Server();const realList=slowServer.list.bind(slowServer);slowServer.list=async path=>{await new Promise(r=>setTimeout(r,35));return realList(path);};
const slow=new MirroredFiles({scope:'slow-scope',server:slowServer,retryMs:5});await Promise.race([slow.sync(),new Promise((_,reject)=>setTimeout(()=>reject(Error('Slow sync never settled')),500))]);slow.close();
// Version-aware servers avoid retransferring unchanged data, but same-size
// external changes are still detected by their server-side content hash.
const versioned=new Server();let fullReads=0;const fullRead=versioned.read.bind(versioned);versioned.read=async path=>{fullReads++;return fullRead(path);};versioned.supportsVersion=async()=>true;versioned.version=async path=>{const r=versioned.files.get(path);if(!r||r.directory)throw Error('missing');return {bytes:r.data.length,sha256:await sha(r.data)};};
const efficient=new MirroredFiles({scope:'versioned-scope',server:versioned,retryMs:0});await efficient.write('/changed.bin','first');await efficient.sync();await efficient.sync();assert.equal(fullReads,0,'Unchanged sync must not download file bytes');versioned.files.set('changed.bin',{directory:false,data:new TextEncoder().encode('other')});await efficient.sync();assert.equal(fullReads,1,'Changed server content must be downloaded');assert.equal(new TextDecoder().decode((await efficient.read('/changed.bin')).data),'other');efficient.close();
// A limited service must not force a long scan to restart at its first file.
const limited=new Server();for(let i=0;i<12;i++)limited.files.set('file'+String(i).padStart(2,'0')+'.txt',{directory:false,data:new TextEncoder().encode('old '+i)});
limited.supportsVersion=async()=>true;let remaining=3,versionCalls=0;limited.version=async path=>{if(remaining--<=0)throw Object.assign(Error('slow down'),{status:429});versionCalls++;const r=limited.files.get(path);return {bytes:r.data.length,sha256:await sha(r.data)};};
const resuming=new MirroredFiles({scope:'limited-scope',server:limited,retryMs:0});let completed=false;
for(let i=0;i<6&&!completed;i++){remaining=3;try{await resuming.sync();completed=true;}catch(e){assert.equal(e.status,429);assert.equal((await resuming.status()).lastSynced,null);}}
assert.equal(completed,true,'A scan larger than one request window must make progress');assert.equal(versionCalls,12);assert.equal((await resuming.list('/')).entries.length,12);
limited.files.set('file00.txt',{directory:false,data:new TextEncoder().encode('new 0')});limited.files.set('file11.txt',{directory:false,data:new TextEncoder().encode('new 11')});completed=false;
for(let i=0;i<6&&!completed;i++){remaining=3;try{await resuming.sync();completed=true;}catch(e){assert.equal(e.status,429);}}
assert.equal(completed,true);assert.equal(new TextDecoder().decode((await resuming.read('/file00.txt')).data),'new 0');assert.equal(new TextDecoder().decode((await resuming.read('/file11.txt')).data),'new 11');
// Successful completion clears the temporary progress so later external edits are discovered.
limited.files.set('file00.txt',{directory:false,data:new TextEncoder().encode('newer')});completed=false;
for(let i=0;i<6&&!completed;i++){remaining=3;try{await resuming.sync();completed=true;}catch(e){assert.equal(e.status,429);}}
assert.equal(completed,true);assert.equal(new TextDecoder().decode((await resuming.read('/file00.txt')).data),'newer');
// An edit during an interrupted scan still takes priority over cached checks.
remaining=3;await assert.rejects(()=>resuming.sync(),e=>e.status===429);const edited=await resuming.read('/file00.txt');await resuming.write('/file00.txt','local during scan',edited.version);await pause();completed=false;
for(let i=0;i<8&&!completed;i++){remaining=3;try{await resuming.sync();completed=true;}catch(e){assert.equal(e.status,429);}}
assert.equal(completed,true);assert.equal(new TextDecoder().decode((await limited.read('file00.txt')).data),'local during scan');resuming.close();
a.close();b.close();console.log('PASS offline local saves, account isolation, signed-server conflict safety, remote refresh, folders, deletion and lost reply recovery');
