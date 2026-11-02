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
if(typeof self!=='undefined'&&typeof self.postMessage==='function')self.onmessage=async event=>{
  try{const {operation,blob}=event.data||{};if(operation!=='hash'&&operation!=='chunks')throw Error('Unsupported operation');const value=operation==='hash'?await hashBlob(blob):await chunkBlob(blob);self.postMessage({operation,value});}
  catch{self.postMessage({error:'File verification failed'});}
};
