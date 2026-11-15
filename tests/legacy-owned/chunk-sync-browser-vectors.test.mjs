import {readFile} from 'node:fs/promises';import {createHash,webcrypto} from 'node:crypto';import assert from 'node:assert/strict';
import {chunkBlob} from '../active-system/gateway_service/vendor/js-sha256/verify-worker.mjs';
const vectors=JSON.parse(await readFile(new URL('fixtures/chunk-sync/v1.json',import.meta.url),'utf8')).vectors;
for(const v of vectors){const parts=[];for(let i=0;i<Math.ceil(v.length/32);i++){const n=Buffer.alloc(4);n.writeUInt32BE(i);parts.push(createHash('sha256').update(n).digest())}const data=Buffer.concat(parts).subarray(0,v.length);const chunks=await chunkBlob(new Blob([data]));assert.deepEqual(chunks,v.manifest.chunks)}
console.log('PASS browser chunk boundaries match frozen server vectors');
