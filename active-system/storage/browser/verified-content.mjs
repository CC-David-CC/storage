import {OPFSStore,StorageUnavailable} from './opfs/store.mjs';

// An immutable content address is independent of the user's path. Each save
// gets a new OPFS record; the mirror row is the only authority for its use.
// Published OPFS records are deliberately retained until safe GC is designed.
export class VerifiedContent {
  #store;#scope;#lockWaitMs;#closed=false;#abort=new AbortController();
  constructor(scope,options={}) { this.#scope=scope;this.#lockWaitMs=options.lockWaitMs??30000;this.#store=new OPFSStore(scope,options); }
  async capture(blob) {
    if (!['[object Blob]','[object File]'].includes(Object.prototype.toString.call(blob))) throw Error('A file snapshot is required.');
    blob=new Blob([blob]);
    const path='/content-'+crypto.randomUUID();
    const saved=await this.#store.save(path,blob,null,{owner:'codi-mirror-content/1'});
    return {kind:'codi-opfs-content/1',path,generation:saved.generation,size:saved.size,sha256:saved.sha256};
  }
  async verifyLegacy(blob,expected,{signal=null}={}) { return this.#store.verifyBlob(blob,expected,{signal}); }
  async acquire(ref,{signal=null}={}) {
    if(!isContentRef(ref))throw Error('Invalid content reference.');
    if(this.#closed||signal?.aborted)throw new DOMException('Cancelled','AbortError');
    if(!navigator.locks)throw Error('Browser file locks are unavailable.');
    const hash=[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(this.#scope)))].map(x=>x.toString(16).padStart(2,'0')).join('');
    if(this.#closed||signal?.aborted)throw new DOMException('Cancelled','AbortError');
    const deadline=AbortSignal.timeout(this.#lockWaitMs),lockSignal=AbortSignal.any([...(signal?[signal]:[]),this.#abort.signal,deadline]);
    let released=false,releaseLock;
    const held=new Promise(resolve=>releaseLock=resolve);
    const release=()=>{if(!released){released=true;releaseLock()}};
    return new Promise((resolve,reject)=>{
      let offered=false,acquired=false;
      navigator.locks.request('codi-content:'+hash+':'+ref.generation,{mode:'shared',signal:lockSignal},async()=>{
        acquired=true;try{
          const result=await this.#store.read(ref.path,{signal});
          if(result.generation!==ref.generation||result.size!==ref.size||result.sha256!==ref.sha256)throw Error('Saved content did not pass verification.');
          if(this.#closed||signal?.aborted)throw new DOMException('Cancelled','AbortError');
          offered=true;resolve({data:new Blob([result.file]),release});
          // Once handed to the caller, only explicit release (or tab death)
          // releases the lock; closing the account cannot revoke a returned Blob.
          await held;
        }catch(e){if(!offered)reject(e);else throw e}
      }).catch(e=>{if(!offered)reject(!acquired&&deadline.aborted&&!signal?.aborted&&!this.#abort.signal.aborted?new StorageUnavailable('lock-timeout'):e)});
    });
  }
  async collectionPage(status,after,limit){return this.#store.collectionPage(status,after,limit);}
  async tryRetire(item,recheck){
    if(this.#closed)throw new DOMException('Cancelled','AbortError');
    const hash=[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(this.#scope)))].map(x=>x.toString(16).padStart(2,'0')).join('');
    return navigator.locks.request('codi-content:'+hash+':'+item.generation,{mode:'exclusive',ifAvailable:true},async lock=>{
      if(!lock)return 'leased';
      if(!await recheck(item))return 'referenced';
      await this.#store.retireCandidate(item);return 'removed';
    });
  }
  async read(ref,{signal=null}={}) {
    const lease=await this.acquire(ref,{signal});
    try{
      const copy=await this.#store.readCopy(ref.path,{signal});
      if(copy.generation!==ref.generation||copy.sha256!==ref.sha256||copy.size!==ref.size)throw Error('Saved content did not pass verification.');
      return copy.blob;
    }finally{lease.release();}
  }
  close(){if(this.#closed)return;this.#closed=true;this.#abort.abort();this.#store.close();}
}
export function isContentRef(value){
 return value?.kind==='codi-opfs-content/1'&&typeof value.path==='string'&&/^\/content-[0-9a-f-]{36}$/.test(value.path)&&typeof value.generation==='string'&&Number.isSafeInteger(value.size)&&value.size>=0&&value.size<=128*1024*1024&&typeof value.sha256==='string'&&/^[0-9a-f]{64}$/.test(value.sha256);
}
