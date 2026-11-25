import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import test from 'node:test';
import {indexedDB, IDBObjectStore} from 'fake-indexeddb';
import {MirroredFiles, MirrorConflict} from '../../active-system/storage/browser/mirror.mjs';

globalThis.indexedDB = indexedDB;
const encode = value => new TextEncoder().encode(value);
const decode = value => new TextDecoder().decode(value);
const digest = value => createHash('sha256').update(value).digest('hex');
const preparationError = new DOMException('Error preparing Blob/File data to be stored in object store', 'UnknownError');

function connected(files = {}) {
  const values = new Map(Object.entries(files).map(([name, value]) => [name, encode(value)]));
  const writes = [];
  return {
    writes, values,
    async list() {
      return {entries: Array.from(values, ([name, data]) => ({name, directory:false, bytes:data.byteLength}))};
    },
    async supportsVersion() { return true; },
    async version(path) {
      const data = values.get(path);
      if (!data) throw Object.assign(Error('missing'), {status:404});
      return {sha256:digest(data)};
    },
    async read(path) {
      const version = await this.version(path);
      return {...version, data:values.get(path).slice()};
    },
    async write(path, data, previous) {
      assert.equal(previous, values.has(path) ? digest(values.get(path)) : null);
      assert.ok(data instanceof Uint8Array);
      values.set(path, data.slice());
      writes.push(path);
    },
  };
}

function row(scope, path, expected, {stored = expected, dirty = false, base = null} = {}) {
  assert.equal(encode(expected).byteLength, encode(stored).byteLength);
  return {scope, path, data:new Blob([stored]), sha256:digest(encode(expected)),
    version:crypto.randomUUID(), dirty, directory:false, deleted:false, conflict:false, base};
}

async function storeOperation(mode, operation) {
  const db = await new Promise((resolve, reject) => {
    const request = indexedDB.open('codi-mirrored-files-v1', 1);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction('files', mode);
      const request = operation(tx.objectStore('files'));
      tx.oncomplete = () => resolve(request.result);
      tx.onabort = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

async function put(record) { await storeOperation('readwrite', store => store.put(record)); }
async function stored(record) { return storeOperation('readonly', store => store.get([record.scope, record.path])); }

function makeUnreadable(testContext, match) {
  const read = Blob.prototype.arrayBuffer;
  testContext.mock.method(Blob.prototype, 'arrayBuffer', async function() {
    const data = await read.call(this);
    if (decode(data) === match) throw new DOMException('The object can not be found here.', 'NotFoundError');
    return data;
  });
}

test('a missing cached Blob preserves its pending row while unrelated files sync', async t => {
  const server = connected({'incoming.txt':'from account'});
  const failed = row('keep-pending','/a.csv','device only',{dirty:true});
  const healthy = row(failed.scope,'/longer-valid.csv','usable',{dirty:true});
  const mirror = new MirroredFiles({scope:failed.scope,server,retryMs:0});
  t.after(() => mirror.close());
  await mirror.ready();
  await put(failed);
  await put(healthy);
  makeUnreadable(t,'device only');

  await assert.rejects(mirror.sync(), /Could not sync \/a.csv: The local file cannot be read/);
  assert.deepEqual(server.writes, ['longer-valid.csv']);
  assert.equal(decode((await mirror.read('/incoming.txt')).data),'from account');
  assert.equal(decode((await mirror.read('/longer-valid.csv')).data),'usable');
  const retained = await stored(failed);
  assert.equal(retained.version, failed.version);
  assert.equal(retained.sha256, failed.sha256);
  assert.equal(retained.dirty, true);
  assert.equal(retained.attempted, undefined);
  assert.equal((await mirror.status()).pending, 1);
});

test('an identical account copy repairs a cached Blob without uploading again', async t => {
  const server = connected({'notes.csv':'good bytes'});
  const record = row('confirmed-copy','/notes.csv','good bytes',{stored:'lost bytes',dirty:true});
  record.attempted = {base:null,sha256:record.sha256};
  const mirror = new MirroredFiles({scope:record.scope,server,retryMs:0});
  t.after(() => mirror.close());
  await mirror.ready();
  await put(record);
  makeUnreadable(t,'lost bytes');

  await mirror.sync();
  const repaired = await mirror.read(record.path);
  assert.equal(decode(repaired.data),'good bytes');
  assert.equal(repaired.version,record.version);
  assert.equal(repaired.status,'synced');
  assert.deepEqual(server.writes,[]);
  assert.ok((await stored(record)).data instanceof ArrayBuffer);
});

test('a direct read verifies account bytes and preserves a newer device edit', async t => {
  const server = connected({'notes.txt':'real data'});
  const record = row('direct-repair','/notes.txt','real data',{stored:'lost data'});
  const mirror = new MirroredFiles({scope:record.scope,server,retryMs:0});
  t.after(() => mirror.close());
  await mirror.ready();
  await put(record);
  makeUnreadable(t,'lost data');

  const read = server.read.bind(server);
  server.read = async () => ({data:encode('fake data'),sha256:record.sha256});
  await assert.rejects(mirror.read(record.path), /identical account copy could not be verified/);
  assert.ok((await stored(record)).data instanceof Blob);

  let release, started;
  const paused = new Promise(resolve => { started = resolve; });
  server.read = async path => {
    await new Promise(resolve => { release = resolve; started(); });
    return read(path);
  };
  const repair = mirror.read(record.path);
  await paused;
  const newer = {...record, version:'newer-version', sha256:digest(encode('new device edit')),
    data:encode('new device edit').buffer, dirty:true};
  await put(newer);
  release();
  await assert.rejects(repair, MirrorConflict);
  assert.equal(decode((await mirror.read(record.path)).data),'new device edit');
});

test('sync uses a full verified download when a clean delta base is unreadable', async t => {
  const server = connected({'notes.csv':'new server'});
  let attemptedDelta = false;
  server.readChunked = async () => { attemptedDelta = true; throw Error('Unreadable delta base is not usable'); };
  const record = row('changed-server','/notes.csv','old server',{base:digest(encode('old server'))});
  const mirror = new MirroredFiles({scope:record.scope,server,retryMs:0});
  t.after(() => mirror.close());
  await mirror.ready();
  await put(record);
  makeUnreadable(t,'old server');
  await mirror.sync();
  assert.equal(attemptedDelta,false);
  assert.equal(decode((await mirror.read(record.path)).data),'new server');
});

test('a readable small legacy Blob becomes owned bytes before its upload journal changes', async t => {
  const server = connected();
  const record = row('legacy-publish','/notes.txt','legacy bytes',{dirty:true});
  const mirror = new MirroredFiles({scope:record.scope,server,retryMs:0});
  t.after(() => mirror.close());
  await mirror.ready();
  await put(record);
  const original = IDBObjectStore.prototype.put;
  t.mock.method(IDBObjectStore.prototype, 'put', function(next) {
    if(next.attempted && next.data instanceof Blob) throw preparationError;
    return original.call(this,next);
  });
  await mirror.sync();
  assert.equal(decode(server.values.get('notes.txt')),'legacy bytes');
  assert.ok((await stored(record)).data instanceof ArrayBuffer);
});
