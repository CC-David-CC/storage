import {MirroredFiles} from './mirror.mjs';
import {VerifiedContent} from './verified-content.mjs';

// A release selects the backend for the entire origin. This is deliberately
// not a per-app or per-user preference: OPFS references raise the shared IDB
// database floor and older clients must stop writing on that origin.
export function createAccountFileMirror({issuer,owner,server,valid,storage=null}){
  if(typeof issuer!=='string'||!issuer||typeof owner!=='string'||!owner||typeof valid!=='function'||!valid()){
    throw Error('Account changed. Reopen your files.');
  }
  const scope=JSON.stringify(['codi-file-mirror/1',issuer,owner]);
  let content=null;
  if(storage!==null&&storage!==undefined){
    if(storage.version!=='codi-browser-file-content/1'||storage.backend!=='opfs'||storage.databaseVersion!==2){
      throw Error('This desktop does not support the configured file storage version.');
    }
    if(typeof globalThis.navigator?.storage?.getDirectory!=='function'||!globalThis.navigator?.locks){
      throw Error('This browser cannot open the configured file storage. Use Chromium with browser storage enabled.');
    }
    content=new VerifiedContent(scope,{valid});
  }
  try{return new MirroredFiles({scope,server,valid,content});}
  catch(error){content?.close();throw error;}
}


// A release without an explicit migration still needs to read clients that
// already use OPFS. Probe the version floor without writing any account rows.
export async function openAccountFileMirror(options) {
  async function open(storage) {
    const mirror = createAccountFileMirror({...options, storage});
    try {
      await mirror.ready();
      return mirror;
    } catch (error) {
      mirror.close();
      throw error;
    }
  }
  try {
    return await open(options.storage);
  } catch (error) {
    if (options.storage != null || error.name !== 'VersionError') throw error;
    // IndexedDB rejects version 1 before starting a transaction on a v2 store.
    // The explicit v2 open also rejects databases from a newer release.
    return open({version:'codi-browser-file-content/1', backend:'opfs', databaseVersion:2});
  }
}
