import assert from 'node:assert/strict';
import test from 'node:test';
import {indexedDB, IDBObjectStore} from 'fake-indexeddb';
import {MirroredFiles, MirrorCommitUncertain} from '../../active-system/storage/browser/mirror.mjs';

globalThis.indexedDB = indexedDB;
const unavailable = new DOMException('Error preparing Blob/File data to be stored in object store', 'UnknownError');
const offline = {async list() { throw Error('offline'); }};
const encode = value => new TextEncoder().encode(value);
const decode = value => new TextDecoder().decode(value);

test('unsupported Blob writes retain exact bytes and recheck the file version', async () => {
  const mirror = new MirroredFiles({scope:'private-profile', server:offline, retryMs:0});
  const originalPut = IDBObjectStore.prototype.put;
  let rejectedBlobs = 0;
  try {
    IDBObjectStore.prototype.put = function(record) {
      if (record.data instanceof Blob) {
        rejectedBlobs++;
        throw unavailable;
      }
      return originalPut.call(this, record);
    };
    const saved = await mirror.write('/source.zip', new Blob([encode('café')]));
    const attempts = await Promise.allSettled([
      mirror.write('/source.zip', 'v2', saved.version),
      mirror.write('/source.zip', 'v3', saved.version),
    ]);
    assert.equal(attempts.filter(result => result.status === 'fulfilled').length, 1);
    assert.equal(attempts.find(result => result.status === 'rejected').reason.name, 'MirrorConflict');

    const file = await mirror.read('/source.zip');
    const entry = {path:'/Extract/nested.txt', directory:false, data:encode('π\0')};
    await mirror.importTree('/Extract', [entry], '/source.zip', file.version);
    assert.equal(decode((await mirror.read('/Extract/nested.txt')).data), 'π\0');
    assert.equal(rejectedBlobs, 1);
  } finally {
    IDBObjectStore.prototype.put = originalPut;
    mirror.close();
  }
});

test('an unrelated transaction error never switches the record format', async () => {
  const mirror = new MirroredFiles({scope:'unrelated-error', server:offline, retryMs:0});
  const originalPut = IDBObjectStore.prototype.put;
  const quota = new DOMException('Quota reached', 'QuotaExceededError');
  let attempts = 0;
  try {
    IDBObjectStore.prototype.put = function() {
      attempts++;
      throw quota;
    };
    await assert.rejects(mirror.write('/draft.txt', 'data'), error => error === quota);
    assert.equal(attempts, 1);
    assert.deepEqual((await mirror.list()).entries, []);
  } finally {
    IDBObjectStore.prototype.put = originalPut;
    mirror.close();
  }
});

test('a committed write with a lost account binding is never replayed', async () => {
  let valid = true;
  const mirror = new MirroredFiles({scope:'uncertain-private-profile', server:offline,
    valid:()=>valid, retryMs:0});
  const originalPut = IDBObjectStore.prototype.put;
  let attempts = 0;
  try {
    IDBObjectStore.prototype.put = function(record) {
      attempts++;
      const request = originalPut.call(this, record);
      valid = false;
      return request;
    };
    await assert.rejects(mirror.write('/draft.txt', 'committed'), MirrorCommitUncertain);
    assert.equal(attempts, 1);
  } finally {
    IDBObjectStore.prototype.put = originalPut;
    mirror.close();
  }
  const reopened = new MirroredFiles({scope:'uncertain-private-profile', server:offline, retryMs:0});
  try {
    assert.equal(decode((await reopened.read('/draft.txt')).data), 'committed');
  } finally {
    reopened.close();
  }
});

test('small generated files keep owned bytes across mirror metadata writes', async () => {
  const dataByPath = new Map();
  const originalPut = IDBObjectStore.prototype.put;
  const mirror = new MirroredFiles({scope:'inline-generated', server:offline, retryMs:0});
  try {
    IDBObjectStore.prototype.put = function(record) {
      dataByPath.set(record.path, record.data);
      return originalPut.call(this, record);
    };
    const example = 'voltage_v,current_ma\n1,1\n';
    const saved = await mirror.write('/example.csv', example);
    assert.ok(dataByPath.get('/example.csv') instanceof ArrayBuffer);
    assert.equal(decode((await mirror.read('/example.csv')).data), example);

    const edited = encode('π');
    const write = mirror.write('/example.csv', edited, saved.version);
    edited.fill(0);
    await write;
    assert.ok(dataByPath.get('/example.csv') instanceof ArrayBuffer);
    assert.equal(decode((await mirror.read('/example.csv')).data), 'π');

    await mirror.write('/large.csv', new Uint8Array(64 * 1024 + 1));
    assert.ok(dataByPath.get('/large.csv') instanceof Blob);
    await mirror.write('/upload.csv', new Blob([example]));
    assert.ok(dataByPath.get('/upload.csv') instanceof Blob);
  } finally {
    IDBObjectStore.prototype.put = originalPut;
    mirror.close();
  }
});
