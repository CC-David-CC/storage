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
server.drop=true;await a.write('/lost.txt','saved once');await pause();await a.sync();assert.equal((await a.read('/lost.txt')).status,'synced');assert.equal(new TextDecoder().decode((await server.read('lost.txt')).data),'saved once');
// Atomic local operations: concurrent parent deletion and child creation must
// never leave an accessible child without its folder.
server.offline=true;await a.mkdir('/race');await pause();const folder=(await a.list('/')).entries.find(x=>x.path==='/race');
await Promise.allSettled([a.remove('/race',folder.version),a.write('/race/child.txt','x')]);
const root=await a.list('/');if(!root.entries.some(x=>x.path==='/race'))await assert.rejects(()=>a.list('/race'));else assert.equal((await a.list('/race')).entries.length,1);
// Different tabs sharing an account must not overwrite the same local version.
const tab=new MirroredFiles({scope:'issuer:user-a',server,retryMs:0});const before=await a.read('/note.txt');const attempts=await Promise.allSettled([a.write('/note.txt','one',before.version),tab.write('/note.txt','two',before.version)]);assert.equal(attempts.filter(x=>x.status==='fulfilled').length,1);tab.close();
a.close();b.close();console.log('PASS offline local saves, account isolation, signed-server conflict safety, remote refresh, folders, deletion and lost reply recovery');
