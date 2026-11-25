import assert from 'node:assert/strict';
import test from 'node:test';
import 'fake-indexeddb/auto';
import {createHash} from 'node:crypto';
import {MirroredFiles} from '../active-system/storage/browser/mirror.mjs';

const bytes = text => new TextEncoder().encode(text);
const entry = text => ({directory:false, data:bytes(text), sha256:createHash('sha256').update(text).digest('hex')});

function setup(t) {
  const entries = new Map([['report.txt',entry('initial')]]);
  let offline = false, mutations = 0;
  const check = () => { if (offline) throw Error('Offline'); };
  const server = {
    async list(path) {
      check();
      const start = path ? path + '/' : '';
      return {entries:[...entries].filter(([name]) => name.startsWith(start) && !name.slice(start.length).includes('/'))
        .map(([name,{directory}]) => ({name:name.slice(start.length),directory}))};
    },
    async read(path) {
      check();
      const row = entries.get(path);
      if (!row || row.directory) throw Object.assign(Error('File not found.'),{status:404});
      return row;
    },
    async mkdir(path) {
      check();
      const parent=path.slice(0,path.lastIndexOf('/'));
      if(parent&&!entries.get(parent)?.directory)throw Object.assign(Error('Parent folder unavailable.'),{status:409});
      mutations++; throw Error('Unexpected folder creation');
    },
    async write(path) {
      check();
      const parent=path.slice(0,path.lastIndexOf('/'));
      if(parent&&!entries.get(parent)?.directory)throw Object.assign(Error('Parent folder unavailable.'),{status:409});
      mutations++; throw Error('Unexpected write');
    },
    async remove(path, expected) {
      check();
      const current=entries.get(path);
      if(!current||(current.directory?expected!==null:current.sha256!==expected)||[...entries.keys()].some(name=>name.startsWith(path+'/'))) {
        throw Object.assign(Error('Deletion precondition changed.'),{status:409});
      }
      mutations++;
      entries.delete(path);
    }
  };
  const mirror = new MirroredFiles({scope:crypto.randomUUID(),server,retryMs:0});
  t.after(() => mirror.close());
  return {entries, mirror, server, setOffline:value => {offline=value;}, mutations:() => mutations};
}

async function waitUntilOffline(mirror) {
  for (let step=0; step<100; step++) {
    if ((await mirror.status()).error === 'Offline') return;
    await new Promise(resolve => setImmediate(resolve));
  }
  assert.fail('Offline write was not retained');
}

test('selecting the account version installs a replacement folder without changing it on the server',async t=>{
  const {entries,mirror,setOffline,mutations}=setup(t);
  await mirror.sync();
  const before=await mirror.stat('/report.txt');
  setOffline(true);
  await mirror.write('/report.txt',bytes('device edit'),before.version);
  await waitUntilOffline(mirror);
  entries.set('report.txt',{directory:true});
  entries.set('report.txt/child.txt',entry('account child'));
  setOffline(false);
  await mirror.sync();
  const conflict=await mirror.stat('/report.txt');
  assert.equal(conflict.status,'conflict');
  await assert.rejects(mirror.resolve('/report.txt','local',conflict.version),/has a folder/);
  await mirror.resolve('/report.txt','server',conflict.version);
  await mirror.sync();
  assert.deepEqual((await mirror.list('/report.txt')).entries.map(item=>item.name),['child.txt']);
  assert.equal(mutations(),0);
});

test('canceling a conflicted deletion restores the newer account file and honors the selected revision',async t=>{
  const {entries,mirror,setOffline,mutations}=setup(t);
  await mirror.sync();
  const before=await mirror.stat('/report.txt');
  setOffline(true);
  await mirror.remove('/report.txt',before.version);
  await waitUntilOffline(mirror);
  entries.set('report.txt',entry('newer account file'));
  setOffline(false);
  await mirror.sync();
  const [conflict]=(await mirror.list('/')).entries;
  assert.equal(conflict.deleted,true);
  assert.equal(conflict.status,'conflict');
  await assert.rejects(mirror.resolve('/report.txt','server',before.version),/changed/);
  await mirror.resolve('/report.txt','server',conflict.version);
  assert.equal(new TextDecoder().decode((await mirror.read('/report.txt')).data),'newer account file');
  assert.equal(mutations(),0);
});

test('restoring a deleted file retries a rolled-back Blob write as bytes',async t=>{
  const {entries,mirror,setOffline,mutations}=setup(t);
  await mirror.sync();
  const before=await mirror.stat('/report.txt');
  setOffline(true);
  await mirror.remove('/report.txt',before.version);
  await waitUntilOffline(mirror);
  entries.set('report.txt',entry('verified newer file'));
  setOffline(false);
  await mirror.sync();
  const [conflict]=(await mirror.list('/')).entries;
  const put=IDBObjectStore.prototype.put;
  let rejected=0, retried=0;
  IDBObjectStore.prototype.put=function(value,...args){
    if(value.path==='/report.txt'&&value.data instanceof Blob){
      rejected++;
      throw new DOMException('Error preparing Blob/File data to be stored in object store','UnknownError');
    }
    if(value.path==='/report.txt'&&value.data instanceof ArrayBuffer)retried++;
    return put.call(this,value,...args);
  };
  t.after(()=>{IDBObjectStore.prototype.put=put;});
  await mirror.resolve('/report.txt','server',conflict.version);
  assert.equal(rejected,1);
  assert.equal(retried,1);
  assert.equal(new TextDecoder().decode((await mirror.read('/report.txt')).data),'verified newer file');
  assert.equal(mutations(),0);
});

test('confirming a folder copy preserves local children until the exact account tree is verified',async t=>{
  const {entries,mirror,setOffline,mutations}=setup(t);
  await mirror.sync();
  setOffline(true);
  await mirror.mkdir('/Project');
  await mirror.mkdir('/Project/Empty');
  await mirror.write('/Project/note.txt',bytes('device note'));
  await waitUntilOffline(mirror);
  entries.set('Project',entry('account file at the original path'));
  setOffline(false);
  // Local writes may have queued a final failed scan before reconnect.
  try{await mirror.sync();}catch(error){if(error.message!=='Offline')throw error;}
  await mirror.sync();
  const root=(await mirror.list('/')).entries.find(item=>item.name==='Project');
  assert.equal(root.status,'conflict');
  const tree=await mirror.conflictTree('/Project',root.version);
  assert.deepEqual(tree.map(item=>item.path),['/Project','/Project/Empty','/Project/note.txt']);
  entries.set('Project-copy',{directory:true});
  entries.set('Project-copy/Empty',{directory:true});
  entries.set('Project-copy/note.txt',entry('wrong bytes'));
  await assert.rejects(mirror.resolveConflictTree('/Project','/Project-copy',root.version,tree),/folder copy changed/);
  assert.equal(new TextDecoder().decode((await mirror.read('/Project/note.txt')).data),'device note');

  entries.set('Project-copy/note.txt',entry('device note'));
  await mirror.write('/Project/late.txt',bytes('saved after selection'));
  await assert.rejects(mirror.resolveConflictTree('/Project','/Project-copy',root.version,tree),/device folder changed/i);
  const updated=await mirror.conflictTree('/Project',root.version);
  entries.set('Project-copy/late.txt',entry('saved after selection'));
  await mirror.resolveConflictTree('/Project','/Project-copy',root.version,updated);
  await mirror.sync();
  assert.equal(new TextDecoder().decode((await mirror.read('/Project')).data),'account file at the original path');
  assert.equal(new TextDecoder().decode((await mirror.read('/Project-copy/note.txt')).data),'device note');
  assert.equal((await mirror.list('/Project-copy/Empty')).entries.length,0);
  assert.equal(mutations(),0);
});

test('a pending folder deletion protects its account children until the device cancels it',async t=>{
  const {entries,mirror,setOffline,mutations}=setup(t);
  entries.set('Project',{directory:true});
  entries.set('Project/note.txt',entry('first account note'));
  entries.set('Project/other.txt',entry('other account note'));
  await mirror.sync();
  const initial=(await mirror.list('/')).entries.find(item=>item.name==='Project');
  setOffline(true);
  for(const item of (await mirror.list('/Project')).entries)await mirror.remove(item.path,item.version);
  await mirror.remove('/Project',initial.version);
  await waitUntilOffline(mirror);
  entries.set('Project/note.txt',entry('updated in another session'));
  entries.set('Project/new.txt',entry('added in another session'));
  setOffline(false);
  await mirror.sync();
  await mirror.sync(); // Background retries must keep every child intact.
  const conflict=(await mirror.list('/')).entries.find(item=>item.name==='Project');
  assert.equal(conflict.deleted,true);
  assert.equal(conflict.status,'conflict');
  assert.equal(mutations(),0);
  await assert.rejects(mirror.cancelFolderDeletion('/Project',initial.version),/changed/i);
  await mirror.cancelFolderDeletion('/Project',conflict.version);
  await mirror.sync();
  assert.deepEqual((await mirror.list('/Project')).entries.map(item=>item.name),['new.txt','note.txt','other.txt']);
  assert.equal(new TextDecoder().decode((await mirror.read('/Project/note.txt')).data),'updated in another session');
  assert.equal(mutations(),0);
});

test('an unchanged pending folder deletion can still finish after its selected children',async t=>{
  const {entries,mirror,setOffline,mutations}=setup(t);
  entries.set('Project',{directory:true});
  entries.set('Project/note.txt',entry('first account note'));
  await mirror.sync();
  const root=(await mirror.list('/')).entries.find(item=>item.name==='Project');
  const [note]=(await mirror.list('/Project')).entries;
  setOffline(true);
  await mirror.remove(note.path,note.version);
  await mirror.remove(root.path,root.version);
  await waitUntilOffline(mirror);
  setOffline(false);
  await mirror.sync();
  assert.equal(entries.has('Project'),false);
  assert.equal(entries.has('Project/note.txt'),false);
  assert.equal(mutations(),2);
});

test('canceling a pending folder deletion adopts an account file at that path',async t=>{
  const {entries,mirror,setOffline,mutations}=setup(t);
  entries.set('Project',{directory:true});
  await mirror.sync();
  const root=(await mirror.list('/')).entries.find(item=>item.name==='Project');
  setOffline(true);
  await mirror.remove(root.path,root.version);
  await waitUntilOffline(mirror);
  entries.set('Project',entry('replacement account file'));
  setOffline(false);
  await mirror.sync();
  const conflict=(await mirror.list('/')).entries.find(item=>item.name==='Project');
  assert.equal(conflict.status,'conflict');
  await mirror.cancelFolderDeletion(conflict.path,conflict.version);
  assert.equal(new TextDecoder().decode((await mirror.read('/Project')).data),'replacement account file');
  assert.equal(mutations(),0);
});

test('saving to a new account-only folder confirms the parent and preserves the original caller bytes',async t=>{
  const {entries,mirror,setOffline}=setup(t);
  await mirror.sync();
  entries.set('Project',{directory:true});
  entries.set('Project/Nested',{directory:true});
  const puts=[];
  const put=IDBObjectStore.prototype.put;
  IDBObjectStore.prototype.put=function(value,...args){
    puts.push([value.path,value.data?.constructor.name]);
    if(value.path==='/Project/Nested/draft.txt'&&value.data instanceof Blob){
      throw new DOMException('Error preparing Blob/File data to be stored in object store','UnknownError');
    }
    return put.call(this,value,...args);
  };
  t.after(()=>{IDBObjectStore.prototype.put=put;});
  const original=bytes('captured before lookup');
  const saving=mirror.write('/Project/Nested/draft.txt',original);
  original.fill(0);
  const saved=await saving;
  assert.equal(saved.status,'pending');
  assert.deepEqual(puts.slice(0,4),[
    ['/Project/Nested/draft.txt','Blob'],
    ['/Project/Nested/draft.txt','ArrayBuffer'],
    ['/Project',undefined],
    ['/Project/Nested',undefined]
  ]);
  assert.equal(new TextDecoder().decode((await mirror.read('/Project/Nested/draft.txt')).data),'captured before lookup');
  assert.equal((await mirror.list('/Project')).entries[0].status,'synced');
  setOffline(true);
  assert.equal((await mirror.write('/Project/Nested/offline.txt',bytes('can save offline'))).status,'pending');
});

test('a nested folder can be created inside a new account folder and absent or deleted parents stay unavailable',async t=>{
  const {entries,mirror,setOffline}=setup(t);
  await mirror.sync();
  entries.set('Project',{directory:true});
  const created=await mirror.mkdir('/Project/New');
  assert.equal(created.status,'pending');
  assert.equal((await mirror.list('/Project')).entries[0].name,'New');
  await assert.rejects(mirror.write('/Missing/draft.txt',bytes('not written')),/Create the parent folder first/);
  await assert.rejects(mirror.mkdir('/report.txt/folder'),/Create the parent folder first/);

  entries.set('Deleting',{directory:true});
  await mirror.mkdir('/Deleting/Temporary');
  setOffline(true);
  const [child]=(await mirror.list('/Deleting')).entries;
  const folder=(await mirror.list('/')).entries.find(item=>item.name==='Deleting');
  await mirror.remove(child.path,child.version);
  await mirror.remove(folder.path,folder.version);
  await waitUntilOffline(mirror);
  await assert.rejects(mirror.write('/Deleting/draft.txt',bytes('not written')),/Create the parent folder first/);
  assert.equal((await mirror.list('/')).entries.some(item=>item.name==='Deleting'),false);
});

test('cached account folders accept verified draft data without loading a worker',async t=>{
  const {entries,mirror,server,setOffline}=setup(t);
  entries.set('Project',{directory:true});
  await mirror.sync();
  const prior=Object.getOwnPropertyDescriptor(navigator,'onLine');
  Object.defineProperty(navigator,'onLine',{configurable:true,value:false});
  t.after(()=>{
    if(prior)Object.defineProperty(navigator,'onLine',prior);
    else delete navigator.onLine;
  });
  let workerCalls=0;
  server.captureSnapshot=()=>{
    workerCalls++;
    throw Error('File verification worker failed');
  };
  setOffline(true);
  const bytesPath='/Project/offline.txt';
  const bytesResult=await mirror.write(bytesPath,bytes('retained draft'));
  assert.equal(bytesResult.sha256,entry('retained draft').sha256);
  assert.equal(new TextDecoder().decode((await mirror.read(bytesPath)).data),'retained draft');

  const bundle='Ω'.repeat(131073);
  const blobPath='/Project/archive.txt';
  const blobResult=await mirror.write(blobPath,new Blob([bundle]));
  assert.equal(blobResult.sha256,entry(bundle).sha256);
  assert.equal(new TextDecoder().decode((await mirror.read(blobPath)).data),bundle);
  assert.equal(workerCalls,0);

  const changing=new Blob(['prior']);
  let reads=0;
  changing.slice=()=>new Blob([++reads===1?'prior':'later']);
  await assert.rejects(mirror.write('/Project/changing.txt',changing),/changed during capture/);
  await assert.rejects(mirror.read('/Project/changing.txt'),/not found/);
});
