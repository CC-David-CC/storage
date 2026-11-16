import test from 'node:test';
import assert from 'node:assert/strict';
import {UserFiles} from '../src/webos_storage/client.mjs';
globalThis.location=new URL('http://127.0.0.1:18000/');
const authority=check=>({check,basePath:'/gateway',publicKey:{},authorize:async()=> 'synthetic-test-authority'});
const deferred=()=>{let resolve;const promise=new Promise(yes=>{resolve=yes;});return {promise,resolve};};
test('restored views share bounded transfers and capture queued resource names',async()=>{
 const before=globalThis.fetch,gate=deferred(),entered=deferred();let active=0,maximum=0;const seen=[];
 globalThis.fetch=async(url,options)=>{
  const value=JSON.parse(options.body);
  if(url.endsWith('/challenge'))return Response.json({nonce:'a'.repeat(43),request_sha256:value.request_sha256});
  active++;maximum=Math.max(active,maximum);seen.push(value.path);if(seen.length===4)entered.resolve();await gate.promise;active--;return Response.json({entries:[]});
 };
 try{
  const client=new UserFiles(authority(()=>{}),{workerUrl:'/verify-worker.mjs'});
  const tasks=['first','second','third','fourth'].map(p=>client.list(p));await entered.promise;
  const mutable={path:'captured'};tasks.push(client.request('list',mutable),client.list('sixth'));mutable.path='changed';
  await Promise.resolve();assert.equal(seen.length,4);gate.resolve();await Promise.all(tasks);
  assert.equal(maximum,4);assert.deepEqual(seen.slice(4).sort(),['captured','sixth']);
 }finally{globalThis.fetch=before;gate.resolve();}
});
test('a session change prevents queued work from obtaining a new grant or dispatching',async()=>{
 const before=globalThis.fetch,gate=deferred(),entered=deferred();let valid=true,uses=0,grants=0;
 globalThis.fetch=async(url,options)=>{
  const value=JSON.parse(options.body);
  if(url.endsWith('/challenge')){grants++;return Response.json({nonce:'a'.repeat(43),request_sha256:value.request_sha256});}
  uses++;if(uses===4)entered.resolve();await gate.promise;return Response.json({entries:[]});
 };
 try{
  const client=new UserFiles(authority(()=>{if(!valid)throw new DOMException('Account changed','AbortError');}),{workerUrl:'/verify-worker.mjs'});
  const tasks=['one','two','three','four'].map(p=>client.list(p));tasks.forEach(p=>p.catch(()=>{}));await entered.promise;
  const queued=client.list('queued');queued.catch(()=>{});valid=false;gate.resolve();
  await Promise.all([...tasks,queued].map(p=>assert.rejects(p,{name:'AbortError'})));assert.equal(uses,4);assert.equal(grants,4);
 }finally{globalThis.fetch=before;gate.resolve();}
});
