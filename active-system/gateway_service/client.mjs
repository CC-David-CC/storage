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
export class UserFiles{
  constructor(config,session,{sessionValid=()=>true}={}){
    const api=config?.identity?.apiBase,base=config?.gateway?.basePath;
    requireThat(config?.identity?.mode==='server'&&config.identity.issuer===location.origin,'Same-origin issuer required');
    requireThat(typeof api==='string'&&/^\/(?:[A-Za-z0-9_-]+\/)*api\/v1$/.test(api),'Canonical issuer API required');
    requireThat(config.gateway.version==='codi-user-files/1'&&base===api.slice(0,-7)+'/gateway','Same-origin file gateway required');
    this.config=config;this.session=session;this.valid=sessionValid;this.base=base;this.api=api;
  }
  check(){requireThat(this.valid()&&this.session.public.kind==='registered','Sign in to access your server files');}
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
  async request(operation,fields={},binary=null){
    this.check();const session=this.session,sid=session.public.sid,publicKey=session.public.key,key=session.privateKey;
    await verifyIdentity(session.public,this.config.identity);this.check();
    const raw=JSON.stringify({resource:'my-files',operation,...fields});requireThat(new TextEncoder().encode(raw).length<=MAX_RESPONSE,'File request too large');
    const requestSha=await hash(raw);
    const challenge=await this.post(this.base+'/challenge',JSON.stringify({key:publicKey,request_sha256:requestSha}));
    requireThat(typeof challenge.nonce==='string'&&/^[A-Za-z0-9_-]{43}$/.test(challenge.nonce)&&challenge.request_sha256===requestSha,'Invalid gateway challenge');
    const authorize=this.api+'/gateway/authorize';
    const issuerNonce=await this.post(this.api+'/gateway/challenge',JSON.stringify({key:publicKey,path:authorize}));
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
      requireThat(binary instanceof Uint8Array&&binary.length<=MAX_FILE,'Invalid binary upload');
      const metadata=new TextEncoder().encode(raw);requireThat(metadata.length<=8192,'Upload metadata too large');
      const prefix=new Uint8Array(4);new DataView(prefix.buffer).setUint32(0,metadata.length,false);
      const body=new Blob([prefix,metadata,binary],{type:'application/octet-stream'});
      return this.post(this.base+'/upload',body,{headers:{'Content-Type':'application/octet-stream',Authorization:authorization},timeout:910000});
    }
    return this.post(this.base+'/use',raw,{headers:{Authorization:authorization},timeout:910000});
  }
  wordCount(path,previousSHA256){return this.request('word-count',{path,previousSHA256});}
  list(path=''){return this.request('list',{path});}
  mkdir(path){return this.request('mkdir',{path});}
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
  async read(path){
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
  async write(path,data,previousSHA256=null){
    if(typeof data==='string')data=new TextEncoder().encode(data);
    requireThat(data instanceof Uint8Array&&data.length<=MAX_FILE,'Files are limited to 128 MiB');
    const operation=previousSHA256===null?'create':'replace';
    if(await this.supportsStreamingUpload()){
      const sha256=[...new Uint8Array(await crypto.subtle.digest('SHA-256',data))].map(b=>b.toString(16).padStart(2,'0')).join('');
      return this.request(operation,{path,format:'codi-binary-upload/1',size:data.length,sha256,...(previousSHA256===null?{}:{previousSHA256})},data);
    }
    return this.request(operation,{path,data:encode(data),...(previousSHA256===null?{}:{previousSHA256})});
  }
  remove(path,previousSHA256=null){return this.request('delete',{path,previousSHA256});}
  rename(path,destination,previousSHA256){return this.request('rename',{path,destination,previousSHA256});}
}
