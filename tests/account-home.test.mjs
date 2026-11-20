import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAccountHome } from '../active-system/storage/browser/account-home.mjs';

const revision = 'b'.repeat(64);

test('guest paths and conditional mutations use the signed Files client', async () => {
  const calls = [];
  const changes = [];
  const files = {
    list: async path => { calls.push(['list', path]); return { entries: [] }; },
    write: async (path, data, expected, { signal }) => {
      calls.push(['write', path, data, expected]);
      assert.equal(signal.aborted, false);
      return { sha256: revision };
    },
  };
  const home = createAccountHome({ files, valid: () => true, onChange: paths => changes.push(paths) });
  assert.deepEqual(await home.list('/'), { entries: [] });
  const bytes = new Uint8Array([1]);
  assert.deepEqual(await home.write('/Documents/probe', bytes, null), { sha256: revision });
  await home.write('/Documents/probe', bytes, revision);
  await assert.rejects(home.write('/Documents/probe', bytes, undefined), /exact saved file revision/);
  await assert.rejects(home.write('/../another-account', bytes, null), /Invalid file path/);
  await assert.rejects(home.write('/.private', bytes, null), /Invalid file path/);
  assert.deepEqual(calls, [
    ['list', ''],
    ['write', 'Documents/probe', bytes, null],
    ['write', 'Documents/probe', bytes, revision],
  ]);
  assert.deepEqual(changes, [['/Documents/probe'], ['/Documents/probe']]);
});

test('conflict and account transition never report a confirmed change', async () => {
  let valid = true;
  let finishRead;
  const changes = [];
  const conflict = Object.assign(new Error('File changed'), { status: 409 });
  const files = {
    read: () => new Promise(resolve => { finishRead = resolve; }),
    write: async () => { throw conflict; },
  };
  const home = createAccountHome({ files, valid: () => valid, onChange: paths => changes.push(paths) });
  await assert.rejects(home.write('/file', new Uint8Array(), revision), error => error === conflict);
  const pending = home.read('/file');
  valid = false;
  finishRead({ data: new Uint8Array([1]), sha256: revision });
  await assert.rejects(pending, { name: 'AbortError' });
  valid = true;
  home.close();
  await assert.rejects(home.read('/file'), { name: 'AbortError' });
  assert.deepEqual(changes, []);
});
