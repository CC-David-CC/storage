import {filePath, MirrorConflict} from './mirror.mjs';

const homeFolders = ['Documents', 'Digital-Projects', '3D-Objects', 'Games', 'Pictures', 'Audio', 'Video'];
const maxFile = 128 * 1024 * 1024;
const maxTotal = 256 * 1024 * 1024;
function fail(message, status) { throw Object.assign(new Error(message), {status}); }
function canonical(path) {
  if (typeof path !== 'string' || !path || filePath('/' + path) !== '/' + path) throw new TypeError('A relative file path is required.');
  return path;
}
const parent = path => path.substring(0, path.lastIndexOf('/'));
const versionOf = entry => ({bytes:entry.data.byteLength, sha256:entry.sha256});

// This file tree lives exclusively in the owning guest session. Its public
// operations match the account file client, including conditional writes.
export function createTemporaryFiles(valid) {
  const entries = new Map(['', ...homeFolders].map(path => [path, {directory:true}]));
  const changes = new EventTarget();
  const changed = () => changes.dispatchEvent(new Event('change'));
  let total = 0, frozen = false;
  function check() {
    if (!valid()) throw new DOMException('This guest session has ended.', 'AbortError');
  }
  function writable() {
    check();
    if (frozen) fail('Temporary files are being transferred.', 409);
  }
  function get(path) {
    const entry = entries.get(path);
    if (!entry) fail('File or folder not found.', 404);
    return entry;
  }
  function folder(path) {
    if (!get(path).directory) fail('A folder is required.', 409);
  }
  function file(path) {
    const entry = get(canonical(path));
    if (entry.directory) fail('Choose a file.', 409);
    return entry;
  }
  function vacant(path) {
    if (entries.has(path)) fail('The destination already exists.', 409);
    folder(parent(path));
    if (entries.size >= 16384) fail('This temporary workspace is full.', 507);
  }
  function matches(entry, expected) {
    if (entry.directory ? expected !== null : entry.sha256 !== expected) fail('The file changed. Refresh before continuing.', 409);
  }
  function listRows(path, format) {
    check(); if (path) canonical(path); folder(path);
    const rows = [];
    for (const [key, entry] of entries) {
      if (!key || parent(key) !== path) continue;
      const name = key.slice(path ? path.length + 1 : 0);
      rows.push(format({name, directory:!!entry.directory, bytes:entry.data?.byteLength ?? 0}, key, entry));
    }
    return {entries:rows.sort((a,b) => Number(b.directory)-Number(a.directory) || a.name.localeCompare(b.name))};
  }
  const files = Object.freeze({
    temporary: true, acceptsBlobWrites: true, check,
    async list(path = '') { return listRows(path, row => row); },
    async mkdir(path) { writable(); canonical(path); vacant(path); entries.set(path, {directory:true}); changed(); return {path}; },
    async version(path) { check(); return versionOf(file(path)); },
    async read(path) { check(); const entry = file(path); return {...versionOf(entry), data:entry.data.slice()}; },
    async write(path, value, expected = null, {signal} = {}) {
      writable(); signal?.throwIfAborted(); canonical(path);
      const blob = value instanceof Blob ? value : new Blob([value]);
      if (blob.size > maxFile) fail('Files are limited to 128 MiB.', 413);
      const data = new Uint8Array(await blob.arrayBuffer());
      const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
      const entry = {data, sha256:Array.from(hash,b=>b.toString(16).padStart(2,'0')).join('')};
      writable(); signal?.throwIfAborted();
      const old = entries.get(path);
      if (expected === null) vacant(path);
      else { if (!old || old.directory) fail('The file changed.',409); matches(old,expected); }
      const next = total - (old?.data.byteLength ?? 0) + data.byteLength;
      if (next > maxTotal) fail('This temporary workspace is full.', 507);
      entries.set(path,entry); total=next; changed();
      return versionOf(entry);
    },
    async rename(path,destination,expected) {
      writable(); const entry=file(path); canonical(destination); vacant(destination); matches(entry,expected);
      entries.set(destination,entry); entries.delete(path); changed(); return versionOf(entry);
    },
    async remove(path,expected=null) {
      writable(); const entry=get(canonical(path)); matches(entry,expected);
      if (entry.directory && [...entries.keys()].some(key=>key.startsWith(path+'/'))) fail('The folder is not empty.',409);
      entries.delete(path); total -= entry.data?.byteLength ?? 0; changed(); return {path};
    },
  });
  // Both interfaces use these exact entries, so edits from Files, Linux, or a
  // legacy editor participate in the same conditional writes and promotion.
  function mirrorFile(path, signal) {
    check(); signal?.throwIfAborted();
    const entry = entries.get(filePath(path).slice(1));
    if (!entry || entry.directory) fail('File not found.', 404);
    return entry;
  }
  const metadata = entry => ({...versionOf(entry), version:entry.sha256, status:'synced'});
  function snapshot(path, {expected = null, signal} = {}) {
    const entry = mirrorFile(path,signal);
    if (expected !== null && expected !== entry.sha256) throw new MirrorConflict();
    // Blob captures immutable bytes. Later edits need no lease on the Map.
    return {...metadata(entry), data:new Blob([entry.data]), deleted:false};
  }
  function readBounded(path, maximumBytes, {signal} = {}) {
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 0 || maximumBytes > maxFile) throw Error('Invalid read size limit.');
    const entry = mirrorFile(path,signal);
    if (entry.data.byteLength > maximumBytes) throw Error('This file exceeds the allowed size.');
    return {...metadata(entry), data:entry.data.slice(), deleted:false};
  }
  const mirror = Object.freeze({
    temporary:true,
    async stat(path,{signal} = {}) { return metadata(mirrorFile(path,signal)); },
    async read(path) { return readBounded(path,maxFile); },
    async readBounded(path,limit,options) { return readBounded(path,limit,options); },
    async readBlob(path,options) { return snapshot(path,options); },
    async acquireSnapshot(path,options) { return {...snapshot(path,options), release(){}}; },
    async list(path = '/') {
      return listRows(filePath(path).slice(1), (row,key,entry) => ({
        ...row, path:'/'+key, version:entry.sha256 ?? null, bytes:row.directory ? null : row.bytes,
        deleted:false, status:'synced', canMove:!row.directory, canReceiveMove:row.directory
      }));
    },
    async write(path,value,expected = null,options) {
      try {
        const result = await files.write(filePath(path).slice(1),value,expected,options);
        check(); return {...result, version:result.sha256, status:'synced'};
      } catch (error) {
        if (error.status === 409) throw new MirrorConflict(error.message);
        throw error;
      }
    },
    async mkdir(path) {
      await files.mkdir(filePath(path).slice(1));
      check(); return {path, version:null, status:'synced'};
    },
    async remove(path,expected = null) {
      await files.remove(filePath(path).slice(1),expected);
      check(); return {path, status:'synced'};
    },
    subscribe(listener) {
      check();
      if (typeof listener !== 'function') throw TypeError('Listener required.');
      changes.addEventListener('change',listener);
      return () => changes.removeEventListener('change',listener);
    },
    async status() {
      check(); return {pending:0, conflicts:0, error:null, lastSynced:null, verification:null, temporary:true};
    },
    async sync() { check(); }
  });
  return {files, mirror, freeze() { writable(); frozen=true; return () => { frozen=false; }; }};
}
