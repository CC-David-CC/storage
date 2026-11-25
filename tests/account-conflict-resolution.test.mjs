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
    async remove() {check(); mutations++; throw Error('Unexpected deletion');}
  };
  const mirror = new MirroredFiles({scope:crypto.randomUUID(),server,retryMs:0});
  t.after(() => mirror.close());
  return {entries, mirror, setOffline:value => {offline=value;}, mutations:() => mutations};
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
