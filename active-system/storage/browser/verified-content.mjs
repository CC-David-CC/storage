import {OPFSStore} from './opfs/store.mjs';

// An immutable content address is independent of the user's path. Each save
// gets a new OPFS record; the mirror row is the only authority for its use.
// Published OPFS records are deliberately retained until safe GC is designed.
export class VerifiedContent {
  #store;
  constructor(scope,options={}) { this.#store=new OPFSStore(scope,options); }
  async capture(blob) {
    if (!(blob instanceof Blob)) throw Error('A file snapshot is required.');
    const path='/content-'+crypto.randomUUID();
    const saved=await this.#store.save(path,blob);
    return {kind:'codi-opfs-content/1',path,generation:saved.generation,size:saved.size,sha256:saved.sha256};
  }
  async read(ref,{signal=null}={}) {
    if (!isContentRef(ref)) throw Error('Invalid content reference.');
    const result=await this.#store.read(ref.path,{signal});
    if(result.generation!==ref.generation||result.size!==ref.size||result.sha256!==ref.sha256)throw Error('Saved content did not pass verification.');
    return new Blob([result.file]);
  }
  close(){this.#store.close();}
}
export function isContentRef(value){
 return value?.kind==='codi-opfs-content/1'&&typeof value.path==='string'&&/^\/content-[0-9a-f-]{36}$/.test(value.path)&&typeof value.generation==='string'&&Number.isSafeInteger(value.size)&&value.size>=0&&value.size<=128*1024*1024&&typeof value.sha256==='string'&&/^[0-9a-f]{64}$/.test(value.sha256);
}
