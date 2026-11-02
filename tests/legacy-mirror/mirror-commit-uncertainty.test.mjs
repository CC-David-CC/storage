import assert from 'node:assert/strict';
import {indexedDB,IDBObjectStore} from 'fake-indexeddb';
import {MirroredFiles,MirrorCommitUncertain} from '../active-system/storage/browser/mirror.mjs';
globalThis.indexedDB=indexedDB;
let valid=true;const originalPut=IDBObjectStore.prototype.put;
const server={list:async()=>{throw Error('offline')}};
const first=new MirroredFiles({scope:'uncertain-account-a',server,valid:()=>valid,retryMs:0});
try{
  IDBObjectStore.prototype.put=function(...args){const request=originalPut.apply(this,args);valid=false;return request};
  await assert.rejects(first.write('/note.txt','committed'),error=>error instanceof MirrorCommitUncertain&&!error.message.includes('note.txt'));
}finally{IDBObjectStore.prototype.put=originalPut;first.close()}
valid=true;
const originalAccount=new MirroredFiles({scope:'uncertain-account-a',server,retryMs:0});
const otherAccount=new MirroredFiles({scope:'uncertain-account-b',server,retryMs:0});
try{
  assert.equal(new TextDecoder().decode((await originalAccount.read('/note.txt')).data),'committed');
  await assert.rejects(otherAccount.read('/note.txt'),/not found/i);
}finally{originalAccount.close();otherAccount.close()}
console.log('PASS committed write reports uncertainty on invalidation and remains scoped');
