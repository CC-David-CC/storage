// CodiServer-authored worker. The adjacent core/shared files are js-sha256.
import {sha256} from './core.mjs';
const MAX=128*1024*1024;
const hex=async data=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',data))].map(x=>x.toString(16).padStart(2,'0')).join('');
export async function hashBlob(blob,check=()=>{}){
  if(!(blob instanceof Blob)||blob.size>MAX)throw Error('Invalid input');const hash=sha256.create();
  for(let offset=0;offset<blob.size;offset+=262144){const bytes=new Uint8Array(await blob.slice(offset,offset+262144).arrayBuffer());check();hash.update(bytes);}
  check();return hash.hex();
}
export async function chunkBlob(blob,check=()=>{}){
  if(!(blob instanceof Blob)||blob.size>MAX)throw Error('Invalid input');const gear=[],prefix=new TextEncoder().encode('codi-chunk-v1:');
  for(let i=0;i<256;i++){const input=new Uint8Array(prefix.length+1);input.set(prefix);input[prefix.length]=i;const bytes=new Uint8Array(await crypto.subtle.digest('SHA-256',input));check();gear.push((bytes[6]<<8)|bytes[7]);}
  const chunks=[];let rolling=0,start=0,length=0;
  for(let offset=0;offset<blob.size;offset+=65536){const part=new Uint8Array(await blob.slice(offset,offset+65536).arrayBuffer());check();
    for(let i=0;i<part.length;i++){rolling=((rolling<<1)+gear[part[i]])&65535;length++;if(length>=262144||(length>=16384&&rolling===0)){const sum=await hex(await blob.slice(start,start+length).arrayBuffer());check();chunks.push([start,length,sum]);start+=length;length=0;rolling=0;}}
  }
  if(length){const sum=await hex(await blob.slice(start,start+length).arrayBuffer());check();chunks.push([start,length,sum]);}
  return chunks;
}
// Construct the existing copy/literal delta format from a bounded rolling
// window. Literal Blob slices reference the snapshot without reading it whole.
const BLOCK=65536,MOD=65521,MAX_OPS=8192,MAX_FAILED=64;
export async function deltaBlob(blob,signature,check=()=>{}){
  if(!(blob instanceof Blob)||blob.size>MAX||signature?.version!=='codi-file-delta/1'||signature.block!==BLOCK||!Number.isSafeInteger(signature.size)||signature.size<0||signature.size>MAX||!Array.isArray(signature.chunks)||signature.chunks.length!==Math.floor(signature.size/BLOCK))throw Error('Invalid delta signature');
  const lookup=new Map();for(let i=0;i<signature.chunks.length;i++){const e=signature.chunks[i];if(!Array.isArray(e)||e.length!==2||!Number.isSafeInteger(e[0])||e[0]<0||e[0]>0xffffffff||typeof e[1]!=='string'||!/^[0-9a-f]{64}$/.test(e[1]))throw Error('Invalid delta block');let v=lookup.get(e[0]);if(!v){v=new Map();lookup.set(e[0],v)}if(!v.has(e[1]))v.set(e[1],i*BLOCK)}
  const ops=[];let pos=0,literal=0,a=0,b=0,ring=null,head=0,next=null,nextStart=-1,failures=0;
  const copy=offset=>{const last=ops.at(-1);if(last?.type==='copy'&&last.offset+last.length===offset)last.length+=BLOCK;else ops.push({type:'copy',offset,length:BLOCK})};
  const insert=(start,end)=>{if(end>start)ops.push({type:'insert',start,end})};
  while(pos+BLOCK<=blob.size){
    if(!ring){ring=new Uint8Array(await blob.slice(pos,pos+BLOCK).arrayBuffer());check();if(ring.length!==BLOCK)throw Error('Input changed');head=0;a=1;b=0;for(const byte of ring){a=(a+byte)%MOD;b=(b+a)%MOD}}
    const candidates=lookup.get((b*65536+a)>>>0);let source;
    if(candidates){let view=ring;if(head){view=new Uint8Array(BLOCK);view.set(ring.subarray(head));view.set(ring.subarray(0,head),BLOCK-head)}const digest=await hex(view);check();source=candidates.get(digest);if(source===undefined&&++failures>=MAX_FAILED)return null}
    if(source!==undefined){insert(literal,pos);copy(source);pos+=BLOCK;literal=pos;ring=null;if(ops.length>MAX_OPS)return null;continue}
    const index=pos+BLOCK;if(index===blob.size)break;
    if(!next||index<nextStart||index>=nextStart+next.length){nextStart=index;next=new Uint8Array(await blob.slice(index,index+BLOCK).arrayBuffer());check();if(!next.length)throw Error('Input changed')}
    const outgoing=ring[head],incoming=next[index-nextStart];ring[head]=incoming;head=(head+1)%BLOCK;
    a=(a-outgoing+incoming+MOD)%MOD;b=(b-BLOCK*outgoing+a-1)%MOD;if(b<0)b+=MOD;pos++;
  }
  insert(literal,blob.size);if(ops.length>MAX_OPS)return null;
  const total=ops.reduce((n,o)=>n+(o.type==='copy'?9:5+o.end-o.start),0);if(total>=blob.size||total>MAX)return null;
  const parts=[];for(const op of ops){if(op.type==='copy'){const h=new Uint8Array(9);h[0]=67;const v=new DataView(h.buffer);v.setUint32(1,op.offset);v.setUint32(5,op.length);parts.push(h)}else{const h=new Uint8Array(5);h[0]=73;new DataView(h.buffer).setUint32(1,op.end-op.start);parts.push(h,blob.slice(op.start,op.end))}}
  return new Blob(parts,{type:'application/octet-stream'});
}

if(typeof self!=='undefined'&&typeof self.postMessage==='function')self.onmessage=async event=>{
  try{const {operation,blob,signature}=event.data||{};let value;
    if(operation==='hash')value=await hashBlob(blob);
    else if(operation==='chunks')value=await chunkBlob(blob);
    else if(operation==='delta'){const patch=await deltaBlob(blob,signature);value={patch,sha256:await hashBlob(blob),patchSHA256:patch?await hashBlob(patch):null};}
    else throw Error('Unsupported operation');
    self.postMessage({operation,value});
  }catch{self.postMessage({error:'File verification failed'});}
};
