import {readFile} from 'node:fs/promises';import {createHash,webcrypto} from 'node:crypto';import assert from 'node:assert/strict';
const src=await readFile(new URL('../active-system/gateway_service/client.mjs',import.meta.url),'utf8');
const core=src.slice(src.indexOf('let chunkGear;'),src.indexOf('export class UserFiles'));
const code='const hexDigest=async b=>[...new Uint8Array(await crypto.subtle.digest("SHA-256",b))].map(x=>x.toString(16).padStart(2,"0")).join("");'+core+';return chunksForBlob;';
const split=Function('crypto',code)(webcrypto);const vectors=JSON.parse(await readFile(new URL('fixtures/chunk-sync/v1.json',import.meta.url),'utf8')).vectors;
for(const v of vectors){const parts=[];for(let i=0;i<Math.ceil(v.length/32);i++){const n=Buffer.alloc(4);n.writeUInt32BE(i);parts.push(createHash('sha256').update(n).digest())}const data=Buffer.concat(parts).subarray(0,v.length);const chunks=await split(new Blob([data]));assert.deepEqual(chunks.map(x=>[x.offset,x.length,x.sha256]),v.manifest.chunks)}
console.log('PASS browser chunk boundaries match frozen server vectors');
