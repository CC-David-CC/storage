/** Account files over same-origin HTTPS. Never sends credentials to another URL. */
import {hash,signJws,inspectJws,verifyJws,sameKey,validateTimes,nowSeconds,requireThat} from '../network/crypto.mjs';
import {verifyIdentity,PROOF_TYPE} from '../network/identity.mjs';

const MAX_FILE=128*1024*1024,MAX_RESPONSE=192*1024*1024;
export class FileRequestError extends Error{
  constructor(message,status){super(message);this.name='FileRequestError';this.status=status;}
}
// Keep temporary binary strings small; a 128 MiB file must not create a
// second 128 MiB JavaScript string merely to call atob/btoa.
function encode(bytes){
  const chunks=[],step=24*1024; // divisible by three, so only the last chunk has padding
  for(let offset=0;offset<bytes.length;offset+=step){
    const part=bytes.subarray(offset,offset+step);let binary='';
    for(let i=0;i<part.length;i+=8192)binary+=String.fromCharCode(...part.subarray(i,i+8192));
    chunks.push(btoa(binary));
  }
  return chunks.join('');
}
function decode(text){
  requireThat(typeof text==='string'&&text.length<=Math.ceil(MAX_FILE/3)*4&&text.length%4===0,'Invalid file response');
  const padding=text.endsWith('==')?2:text.endsWith('=')?1:0;
  const size=text.length/4*3-padding;requireThat(size>=0&&size<=MAX_FILE,'File response too large');
  const out=new Uint8Array(size),step=32*1024;let offset=0;
  for(let start=0;start<text.length;start+=step){
    const part=text.slice(start,start+step),raw=atob(part);
    requireThat(btoa(raw)===part,'Noncanonical file response');
    for(let i=0;i<raw.length;i++)out[offset++]=raw.charCodeAt(i);
  }
  requireThat(offset===size,'Invalid file response');return out;
}
// Rolling checksums locate shifted 64 KiB blocks; SHA-256 confirms each match.
// Checksums are hints only: the gateway verifies the whole reconstructed file.
const DELTA_BLOCK=64*1024, DELTA_MOD=65521, DELTA_MAX_OPS=8192, DELTA_MAX_FAILED_HASHES=64;
const hexDigest=async bytes=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(b=>b.toString(16).padStart(2,'0')).join('');
// Each file operation owns its worker. Session changes and aborts terminate it.
async function runFileWorker(operation,blob,check=()=>{},signal=null,extra={}){
  check();if(signal?.aborted)throw new DOMException('Cancelled','AbortError');
  const worker=new Worker(new URL('./hash/verify-worker.mjs',import.meta.url),{type:'module',name:'codi-file-verify'});
  try{return await new Promise((resolve,reject)=>{
    let settled=false;const finish=(error,value)=>{if(settled)return;settled=true;clearInterval(timer);signal?.removeEventListener('abort',abort);error?reject(error):resolve(value);};
    const abort=()=>finish(new DOMException('Cancelled','AbortError'));
    const timer=setInterval(()=>{try{check()}catch(error){finish(error)}},50);
    try{
      signal?.addEventListener('abort',abort,{once:true});
      worker.onerror=()=>finish(Error('File verification worker failed'));worker.onmessageerror=()=>finish(Error('Invalid verification worker message'));
      worker.onmessage=event=>{try{check();const data=event.data;if(!data||data.operation!==operation||data.error)throw Error('File verification worker failed');finish(null,data.value)}catch(error){finish(error)}};
      check();if(signal?.aborted)abort();else worker.postMessage({...extra,operation,blob});
    }catch(error){finish(error)}
  })}finally{worker.terminate()}
}
export class UserFiles{
  constructor(config,session,{sessionValid=()=>true}={}){
    const api=config?.identity?.apiBase,base=config?.gateway?.basePath;
    requireThat(config?.identity?.mode==='server'&&config.identity.issuer===location.origin,'Same-origin issuer required');
    requireThat(typeof api==='string'&&/^\/(?:[A-Za-z0-9_-]+\/)*api\/v1$/.test(api),'Canonical issuer API required');
    requireThat(config.gateway.version==='codi-user-files/1'&&base===api.slice(0,-7)+'/gateway','Same-origin file gateway required');
    this.config=config;this.session=session;this.valid=sessionValid;this.base=base;this.api=api;
  }
  check(){requireThat(this.valid()&&this.session.public.kind==='registered','Sign in to access your server files');}
  get acceptsBlobWrites(){return true;}
  async post(path,body,{token=null,headers={},timeout=15000}={}){
    this.check();
    const response=await fetch(path,{method:'POST',mode:'same-origin',credentials:'same-origin',redirect:'error',cache:'no-store',referrerPolicy:'no-referrer',
      headers:{'Content-Type':'application/json',...(token?{Authorization:'Codi '+token}:{}),...headers},body,signal:AbortSignal.timeout(timeout)});
    const reader=response.body.getReader(),chunks=[];let size=0;
    try{
      while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>MAX_RESPONSE)throw Error('File response too large');chunks.push(value);}
    }catch(error){await reader.cancel().catch(()=>{});throw error;}
    const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
    let value;try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{throw Error('Invalid file service response');}
    this.check();if(!response.ok)throw new FileRequestError(value.error||'File request failed',response.status);return value;
  }
  async postBinary(path,body,headers){
    this.check();const response=await fetch(path,{method:'POST',mode:'same-origin',credentials:'same-origin',redirect:'error',cache:'no-store',referrerPolicy:'no-referrer',headers:{'Content-Type':'application/json',...headers},body,signal:AbortSignal.timeout(910000)});
    if(!response.ok){let value;try{value=await response.json()}catch{value={}}throw new FileRequestError(value.error||'File request failed',response.status);}
    const lengthText=response.headers.get('Content-Length'),sha256=response.headers.get('X-Codi-File-SHA256');
    requireThat(response.headers.get('Content-Type')==='application/octet-stream'&&typeof lengthText==='string'&&/^(0|[1-9][0-9]*)$/.test(lengthText)&&typeof sha256==='string'&&/^[0-9a-f]{64}$/.test(sha256),'Invalid binary file response');
    const size=Number(lengthText);requireThat(Number.isSafeInteger(size)&&size<=MAX_FILE,'Invalid binary file size');
    const data=new Uint8Array(size),reader=response.body.getReader();let offset=0;
    try{while(true){const {done,value}=await reader.read();if(done)break;requireThat(value.length<=size-offset,'Binary file exceeds declared size');data.set(value,offset);offset+=value.length;}}
    catch(error){await reader.cancel().catch(()=>{});throw error;}
    this.check();requireThat(offset===size&&await hexDigest(data)===sha256,'Binary file integrity check failed');this.check();return {data,sha256};
  }
  async request(operation,fields={},binary=null,binaryResponse=false){
    this.check();const session=this.session,sid=session.public.sid,publicKey=session.public.key,key=session.privateKey;
    await verifyIdentity(session.public,this.config.identity);this.check();
    const raw=JSON.stringify({resource:'my-files',operation,...fields});requireThat(new TextEncoder().encode(raw).length<=MAX_RESPONSE,'File request too large');
    const requestSha=await hash(raw);
    const challenge=await this.post(this.base+'/challenge',JSON.stringify({key:publicKey,request_sha256:requestSha}));
    requireThat(typeof challenge.nonce==='string'&&/^[A-Za-z0-9_-]{43}$/.test(challenge.nonce)&&challenge.request_sha256===requestSha,'Invalid gateway challenge');
    const authorize=this.api+'/gateway/authorize';
    const issuerNonce=await this.post(this.api+'/gateway/challenge',JSON.stringify({key:publicKey,path:authorize}),{token:session.token});
    const signedRequest=JSON.stringify({nonce:challenge.nonce,request_sha256:requestSha}),now=nowSeconds();
    const issuerProof=await signJws({v:1,nonce:issuerNonce.nonce,iss:sid,aud:this.config.identity.issuer,method:'POST',path:authorize,iat:now,exp:now+60,request_sha256:await hash(signedRequest)},key,PROOF_TYPE);
    const result=await this.post(authorize,JSON.stringify({request:signedRequest,proof:issuerProof}),{token:session.token});
    const inspected=inspectJws(result.confirmation,'codi-gateway-identity+jwt',8192);
    const authority=this.config.identity.authorityKeys.find(k=>k.kid===inspected.header.kid);requireThat(authority,'Unknown file authorization authority');
    const c=await verifyJws(result.confirmation,authority.jwk,'codi-gateway-identity+jwt',8192);validateTimes(c,30);
    const audience=location.origin+this.base;
    requireThat(c.v===1&&c.iss===this.config.identity.issuer&&c.aud===audience&&c.sid===sid&&c.sub===session.public.sub&&c.kind==='registered'&&sameKey(c.cnf?.jwk,publicKey)&&c.nonce===challenge.nonce&&c.request_sha256===requestSha,'File authorization context changed');
    this.check();requireThat(session.public.sid===sid,'File session changed');
    // The verified issuer time also works when the device clock is slightly
    // ahead; the proof still cannot outlive this exact short-lived grant.
    const proof=await signJws({v:1,iss:sid,aud:audience,nonce:challenge.nonce,grant_sha256:await hash(result.confirmation),request_sha256:requestSha,method:'POST',path:this.base+'/use',iat:c.iat,exp:c.exp},key,'codi-gateway-use+jws');
    const authorization='Codi-File '+result.confirmation+' '+proof;
    if(binary!==null){
      requireThat((binary instanceof Uint8Array&&binary.length<=MAX_FILE)||(binary instanceof Blob&&binary.size<=MAX_FILE),'Invalid binary upload');
      const metadata=new TextEncoder().encode(raw);requireThat(metadata.length<=8192,'Upload metadata too large');
      const prefix=new Uint8Array(4);new DataView(prefix.buffer).setUint32(0,metadata.length,false);
      const body=new Blob([prefix,metadata,binary],{type:'application/octet-stream'});
      return this.post(this.base+'/upload',body,{headers:{'Content-Type':'application/octet-stream',Authorization:authorization},timeout:910000});
    }
    if(binaryResponse)return this.postBinary(this.base+'/use',raw,{Authorization:authorization});
    return this.post(this.base+'/use',raw,{headers:{Authorization:authorization},timeout:910000});
  }
  wordCount(path,previousSHA256){return this.request('word-count',{path,previousSHA256});}
  list(path=''){return this.request('list',{path});}
  mkdir(path){return this.request('mkdir',{path});}
  async supportsInventoryVersions(){
    this.check();const response=await fetch(this.base+'/inventory-versions-capabilities',{method:'GET',mode:'same-origin',credentials:'same-origin',redirect:'error',cache:'no-store',referrerPolicy:'no-referrer',signal:AbortSignal.timeout(10000)});this.check();if(response.status===404)return false;if(!response.ok)throw new FileRequestError('File inventory capabilities unavailable',response.status);
    const text=await response.text();requireThat(text.length<=1024,'Invalid file inventory capabilities');let value;try{value=JSON.parse(text)}catch{throw Error('Invalid file inventory capabilities')};return !!(value&&Object.keys(value).length===5&&value.version==='codi-file-inventory-versions/1'&&value.maxDirectories===128&&value.maxEntries===2048&&value.maxHashedFiles===64&&value.maxHashBytes===32*1024*1024);
  }
  async inventoryVersions(){
    const result=await this.request('inventory-versions');requireThat(result&&Object.keys(result).length===2&&typeof result.complete==='boolean'&&Array.isArray(result.entries)&&result.entries.length<=2048&&(result.complete||result.entries.length===0),'Invalid file inventory');let hashed=0,bytes=0;
    for(const item of result.entries){requireThat(item&&typeof item.path==='string'&&item.path.length>0&&typeof item.directory==='boolean','Invalid file inventory entry');const keys=Object.keys(item).sort().join(',');if(keys==='directory,path')continue;requireThat(!item.directory&&keys==='bytes,directory,path,sha256'&&Number.isSafeInteger(item.bytes)&&item.bytes>=0&&item.bytes<=MAX_FILE&&typeof item.sha256==='string'&&/^[0-9a-f]{64}$/.test(item.sha256),'Invalid file inventory version');hashed++;bytes+=item.bytes;}
    requireThat(hashed<=64&&bytes<=32*1024*1024,'File inventory version limit exceeded');return result;
  }
  async supportsInventory(){
    this.check();const response=await fetch(this.base+'/inventory-capabilities',{method:'GET',mode:'same-origin',credentials:'same-origin',redirect:'error',cache:'no-store',referrerPolicy:'no-referrer',signal:AbortSignal.timeout(10000)});this.check();if(response.status===404)return false;if(!response.ok)throw new FileRequestError('File inventory capabilities unavailable',response.status);
    const text=await response.text();requireThat(text.length<=1024,'Invalid file inventory capabilities');let value;try{value=JSON.parse(text)}catch{throw Error('Invalid file inventory capabilities')};return !!(value&&Object.keys(value).length===3&&value.version==='codi-file-inventory/1'&&value.maxDirectories===128&&value.maxEntries===2048);
  }
  async inventory(){const result=await this.request('inventory');requireThat(result&&Object.keys(result).length===2&&typeof result.complete==='boolean'&&Array.isArray(result.entries)&&result.entries.length<=2048&&(!result.complete?result.entries.length===0:true),'Invalid file inventory');for(const item of result.entries)requireThat(item&&Object.keys(item).length===2&&typeof item.path==='string'&&item.path.length>0&&typeof item.directory==='boolean','Invalid file inventory entry');return result;}

  async supportsVersion(){
    this.check();
    const response=await fetch(this.base+'/capabilities',{method:'GET',mode:'same-origin',credentials:'same-origin',redirect:'error',cache:'no-store',referrerPolicy:'no-referrer',signal:AbortSignal.timeout(10000)});
    this.check();if(response.status===404)return false;
    if(!response.ok)throw new FileRequestError('File capabilities unavailable',response.status);
    const reader=response.body.getReader(),chunks=[];let length=0;
    try{while(true){const {done,value}=await reader.read();if(done)break;length+=value.length;if(length>1024)throw Error('File capabilities response too large');chunks.push(value);}}
    catch(error){await reader.cancel().catch(()=>{});throw error;}
    const raw=new Uint8Array(length);let offset=0;for(const chunk of chunks){raw.set(chunk,offset);offset+=chunk.length;}
    let result;try{result=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));}catch{throw Error('Invalid file capabilities');}
    this.check();return !!(result&&Object.keys(result).length===2&&result.version==='codi-file-capabilities/1'&&result.fileVersion===true);
  }
  async version(path){
    const result=await this.request('version',{path});
    requireThat(result&&Object.keys(result).length===2&&Number.isSafeInteger(result.bytes)&&result.bytes>=0&&result.bytes<=MAX_FILE&&typeof result.sha256==='string'&&/^[0-9a-f]{64}$/.test(result.sha256),'Invalid file version response');
    return {bytes:result.bytes,sha256:result.sha256};
  }
  async supportsVersionBatch(){
    this.check();const response=await fetch(this.base+'/version-batch-capabilities',{method:'GET',mode:'same-origin',credentials:'same-origin',redirect:'error',cache:'no-store',referrerPolicy:'no-referrer',signal:AbortSignal.timeout(10000)});
    this.check();if(response.status===404)return false;
    if(!response.ok)throw new FileRequestError('File version capabilities unavailable',response.status);
    const text=await response.text();requireThat(text.length<=1024,'Invalid file version capabilities');let value;try{value=JSON.parse(text);}catch{throw Error('Invalid file version capabilities');}
    return !!(value&&Object.keys(value).length===2&&value.version==='codi-file-version-batch/1'&&value.maxPaths===16);
  }
  async versions(paths){
    requireThat(Array.isArray(paths)&&paths.length>0&&paths.length<=16&&paths.every(p=>typeof p==='string')&&new Set(paths).size===paths.length,'Invalid file version batch');
    const result=await this.request('versions',{paths});requireThat(result&&Object.keys(result).length===1&&Array.isArray(result.entries)&&result.entries.length===paths.length,'Invalid file version batch response');
    return result.entries.map((entry,i)=>{requireThat(entry&&entry.path===paths[i],'Invalid file version batch path');if(entry.deferred===true){requireThat(Object.keys(entry).length===2,'Invalid deferred file version');return null;}requireThat(Object.keys(entry).length===3&&Number.isSafeInteger(entry.bytes)&&entry.bytes>=0&&entry.bytes<=MAX_FILE&&typeof entry.sha256==='string'&&/^[0-9a-f]{64}$/.test(entry.sha256),'Invalid file version batch item');return {bytes:entry.bytes,sha256:entry.sha256};});
  }
  async readChunked(path,expected,previous,{signal=null}={}){
    const check=()=>{this.check();if(signal?.aborted)throw new DOMException('Cancelled','AbortError')};check();requireThat(previous instanceof Blob&&previous.size<=MAX_FILE&&typeof expected==='string'&&/^[0-9a-f]{64}$/.test(expected),'Invalid chunk read');
    const cap=await fetch(this.base+'/chunk-capabilities',{method:'GET',mode:'same-origin',credentials:'same-origin',redirect:'error',cache:'no-store',referrerPolicy:'no-referrer',signal:AbortSignal.timeout(10000)});check();if(cap.status===404)return this.read(path);if(!cap.ok)throw new FileRequestError('Chunk capability unavailable',cap.status);
    const capText=await cap.text();check();requireThat(capText.length<=1024,'Invalid chunk capability');let supported;try{supported=JSON.parse(capText)}catch{throw Error('Invalid chunk capability')}requireThat(supported?.version==='codi-file-chunks/1'&&supported.maxBytes===MAX_FILE,'Invalid chunk capability');
    const m=await this.request('chunk-manifest-v1',{path,previousSHA256:expected});check();
    requireThat(m?.version==='codi-file-chunks/1'&&m.sha256===expected&&Number.isSafeInteger(m.size)&&m.size>=0&&m.size<=MAX_FILE&&Array.isArray(m.chunks)&&m.chunks.length<=8193,'Invalid chunk manifest');
    const local=await runFileWorker('chunks',previous,check,signal);check();requireThat(Array.isArray(local)&&local.length<=8193,'Invalid local chunk list');let localOffset=0;const lookup=new Map();for(const c of local){requireThat(Array.isArray(c)&&c.length===3&&c[0]===localOffset&&Number.isSafeInteger(c[1])&&c[1]>0&&c[1]<=262144&&typeof c[2]==='string'&&/^[0-9a-f]{64}$/.test(c[2])&&c[0]+c[1]<=previous.size,'Invalid local chunk');lookup.set(c[2]+':'+c[1],previous.slice(c[0],c[0]+c[1]));localOffset+=c[1]}requireThat(localOffset===previous.size,'Incomplete local chunks');let position=0;const parts=[];
    for(const entry of m.chunks){requireThat(Array.isArray(entry)&&entry.length===3&&entry[0]===position&&Number.isSafeInteger(entry[1])&&entry[1]>0&&entry[1]<=262144&&typeof entry[2]==='string'&&/^[0-9a-f]{64}$/.test(entry[2])&&position+entry[1]<=m.size,'Invalid chunk entry');
      const [offset,length,sha]=entry;let data=lookup.get(sha+':'+length);
      if(!data){const result=await this.request('chunk-read-v1',{path,previousSHA256:expected,offset,length,chunkSHA256:sha});check();requireThat(result?.offset===offset&&result.length===length&&result.sha256===sha&&typeof result.data==='string'&&result.data.length===Math.ceil(length/3)*4,'Invalid chunk response');const bytes=decode(result.data);requireThat(bytes.length===length&&await hexDigest(bytes)===sha,'Chunk integrity check failed');check();data=new Blob([bytes]);}
      parts.push(data);position+=length;
    }
    requireThat(position===m.size,'Incomplete chunk manifest');const blob=new Blob(parts),actual=await runFileWorker('hash',blob,check,signal);check();requireThat(actual===expected,'File integrity check failed');return {data:blob,sha256:actual};
  }
  async read(path){
    this.check();const capability=await fetch(this.base+'/binary-read-capabilities',{method:'GET',mode:'same-origin',credentials:'same-origin',redirect:'error',cache:'no-store',referrerPolicy:'no-referrer',signal:AbortSignal.timeout(10000)});this.check();
    if(capability.status!==404){
      if(!capability.ok)throw new FileRequestError('File read capabilities unavailable',capability.status);
      const text=await capability.text();requireThat(text.length<=1024,'Invalid binary read capabilities');let value;try{value=JSON.parse(text)}catch{throw Error('Invalid binary read capabilities')}
      if(value&&Object.keys(value).length===2&&value.version==='codi-binary-read/1'&&value.maxBytes===MAX_FILE)return this.request('read-binary',{path},null,true);
    }
    const result=await this.request('read',{path}),data=decode(result.data);
    const actual=[...new Uint8Array(await crypto.subtle.digest('SHA-256',data))].map(b=>b.toString(16).padStart(2,'0')).join('');
    requireThat(result.bytes===data.length&&result.sha256===actual,'File integrity check failed');return {data,sha256:actual};
  }
  async supportsStreamingUpload(){
    this.check();
    const response=await fetch(this.base+'/upload-capabilities',{method:'GET',mode:'same-origin',credentials:'same-origin',redirect:'error',cache:'no-store',referrerPolicy:'no-referrer',signal:AbortSignal.timeout(10000)});
    this.check();if(response.status===404)return false;
    if(!response.ok)throw new FileRequestError('File upload capabilities unavailable',response.status);
    const body=await response.text();requireThat(body.length<=1024,'Invalid upload capabilities');
    let result;try{result=JSON.parse(body);}catch{throw Error('Invalid upload capabilities');}
    return !!(result&&Object.keys(result).length===2&&result.version==='codi-binary-upload/1'&&result.maxBytes===MAX_FILE);
  }
  async supportsDelta(){
    this.check();const response=await fetch(this.base+'/delta-capabilities',{method:'GET',mode:'same-origin',credentials:'same-origin',redirect:'error',cache:'no-store',referrerPolicy:'no-referrer',signal:AbortSignal.timeout(10000)});this.check();
    if(response.status===404)return false;if(!response.ok)throw new FileRequestError('File delta capabilities unavailable',response.status);
    const text=await response.text();requireThat(text.length<=1024,'Invalid delta capabilities');let result;try{result=JSON.parse(text)}catch{throw Error('Invalid delta capabilities')}
    return !!(result&&Object.keys(result).length===4&&result.version==='codi-file-delta/1'&&result.block===DELTA_BLOCK&&result.maxBytes===MAX_FILE&&result.maxOps===DELTA_MAX_OPS);
  }
  async write(path,data,previousSHA256=null,{signal=null}={}){
    const check=()=>{this.check();if(signal?.aborted)throw new DOMException('Cancelled','AbortError')};check();
    if(typeof data==='string')data=new TextEncoder().encode(data);
    requireThat(data instanceof Uint8Array||(data instanceof Blob&&Object.prototype.toString.call(data)==='[object Blob]'),'File bytes or captured Blob required');
    // Mutable byte arrays are captured synchronously before the first await.
    // Mirror-owned Blobs are already immutable snapshots and can be reused.
    const snapshot=data instanceof Blob?data:new Blob([data]),size=snapshot.size;requireThat(size<=MAX_FILE,'Files are limited to 128 MiB');
    const operation=previousSHA256===null?'create':'replace';let sha256=null;
    if(previousSHA256!==null&&size>=2*DELTA_BLOCK&&await this.supportsDelta()){
      const signatures=await this.request('delta-signatures',{path,previousSHA256});check();
      requireThat(signatures?.sha256===previousSHA256,'Delta base version changed');
      const result=await runFileWorker('delta',snapshot,check,signal,{signature:signatures});check();
      requireThat(result&&typeof result.sha256==='string'&&/^[0-9a-f]{64}$/.test(result.sha256)&&(result.patch===null||(result.patch instanceof Blob&&result.patch.size<size&&typeof result.patchSHA256==='string'&&/^[0-9a-f]{64}$/.test(result.patchSHA256))),'Invalid delta worker result');
      sha256=result.sha256;
      if(result.patch!==null)return this.request('replace-delta',{path,format:'codi-file-delta/1',size:size,sha256,previousSHA256,patchSize:result.patch.size,patchSHA256:result.patchSHA256},result.patch);
    }
    if(await this.supportsStreamingUpload()){
      if(sha256===null)sha256=await runFileWorker('hash',snapshot,check,signal);check();requireThat(typeof sha256==='string'&&/^[0-9a-f]{64}$/.test(sha256),'Invalid file digest');
      return this.request(operation,{path,format:'codi-binary-upload/1',size:size,sha256,...(previousSHA256===null?{}:{previousSHA256})},snapshot);
    }
    // Legacy JSON fallback still encodes on the main thread; not release-ready
    // for the all-heavy-processing-off-thread goal.
    const legacy=new Uint8Array(await snapshot.arrayBuffer());check();return this.request(operation,{path,data:encode(legacy),...(previousSHA256===null?{}:{previousSHA256})});
  }
  remove(path,previousSHA256=null){return this.request('delete',{path,previousSHA256});}
  rename(path,destination,previousSHA256){return this.request('rename',{path,destination,previousSHA256});}
}
