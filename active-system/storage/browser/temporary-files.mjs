import {filePath} from './mirror.mjs';

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
  const files = Object.freeze({
    temporary: true, acceptsBlobWrites: true, check,
    async list(path = '') {
      check(); if (path) canonical(path); folder(path);
      const rows = [];
      for (const [key, entry] of entries) {
        if (key && parent(key) === path) rows.push({name:key.slice(path ? path.length+1 : 0), directory:!!entry.directory, bytes:entry.directory ? 0 : entry.data.byteLength});
      }
      rows.sort((a,b) => Number(b.directory)-Number(a.directory) || a.name.localeCompare(b.name));
      return {entries:rows};
    },
    async mkdir(path) { writable(); canonical(path); vacant(path); entries.set(path, {directory:true}); return {path}; },
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
      entries.set(path,entry); total=next;
      return versionOf(entry);
    },
    async rename(path,destination,expected) {
      writable(); const entry=file(path); canonical(destination); vacant(destination); matches(entry,expected);
      entries.set(destination,entry); entries.delete(path); return versionOf(entry);
    },
    async remove(path,expected=null) {
      writable(); const entry=get(canonical(path)); matches(entry,expected);
      if (entry.directory && [...entries.keys()].some(key=>key.startsWith(path+'/'))) fail('The folder is not empty.',409);
      entries.delete(path); total -= entry.data?.byteLength ?? 0; return {path};
    },
  });
  return {files, freeze() { writable(); frozen=true; return () => { frozen=false; }; }};
}
