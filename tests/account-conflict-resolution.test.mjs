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
    async write() {check(); mutations++; throw Error('Unexpected write');},
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
