import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createTemporaryFiles} from '../active-system/storage/browser/temporary-files.mjs';

test('a guest home belongs to one live session and enforces exact file revisions', async () => {
  let active = true;
  const guest = createTemporaryFiles(() => active);
  const other = createTemporaryFiles(() => true);
  const path = 'Documents/example.txt';
  const {files} = guest;
  const first = await files.write(path, new Uint8Array([1]));
  assert.equal((await other.files.list('Documents')).entries.length, 0);
  const races = await Promise.allSettled([2,3].map(value => files.write(path,new Uint8Array([value]),first.sha256)));
  assert.equal(races.filter(result=>result.status==='fulfilled').length,1);
  assert.equal(races.find(result=>result.status==='rejected').reason.status,409);
  const saved = await files.read(path);
  saved.data.fill(0);
  assert.notEqual((await files.read(path)).data[0],0);
  const thaw = guest.freeze();
  await assert.rejects(files.remove(path,saved.sha256),{status:409});
  assert.equal((await files.read(path)).sha256,saved.sha256);
  thaw();
  await assert.rejects(files.rename(path,'../name',saved.sha256));
  await files.rename(path,'Documents/renamed.txt',saved.sha256);
  await assert.rejects(files.remove('Documents'),{status:409});
  active=false;
  await assert.rejects(files.list('Documents'),{name:'AbortError'});
});
