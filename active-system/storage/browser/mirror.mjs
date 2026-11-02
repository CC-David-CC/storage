/** Account-scoped local-first file mirror. The server client performs signed,
 * authorized operations; this module never sends a file to another origin. */
const MAX_FILE=128*1024*1024, MAX_ENTRIES=4096;
const need=(value,message)=>{if(!value)throw Error(message);};
export function filePath(value){
  need(typeof value==='string'&&new TextEncoder().encode(value).length<=2048&&value.startsWith('/'),'Use an absolute file path.');
  if(value==='/')return value;
  const parts=value.slice(1).split('/');
  need(parts.length<=16&&parts.every(p=>p&&p!=='.'&&p!=='..'&&!p.startsWith('.')&&new TextEncoder().encode(p).length<=255&&!/[\\%?#\x00-\x1f\x7f]/.test(p)),'Invalid file path.');
  return '/'+parts.join('/');
}
export function fileName(value){const name=String(value).trim();need(name&&!name.includes('/')&&filePath('/'+name)==='/'+name,'Enter a valid file name.');return name;}
const parent=path=>path.slice(0,path.lastIndexOf('/'))||'/';
const name=path=>path.slice(path.lastIndexOf('/')+1);
// ArrayBuffer.isView works across iframe realms. Copy synchronously before the
// first await: callers may mutate their input while the digest is pending.
const byteArray=value=>ArrayBuffer.isView(value)&&Object.prototype.toString.call(value)==='[object Uint8Array]';
const rawBuffer=value=>Object.prototype.toString.call(value)==='[object ArrayBuffer]';
const bytes=value=>typeof value==='string'?new TextEncoder().encode(value):byteArray(value)?new Uint8Array(value):rawBuffer(value)?new Uint8Array(ArrayBuffer.prototype.slice.call(value,0)):null;
const localQueues=new Map();
function serializeLocal(key,operation){const previous=localQueues.get(key)??Promise.resolve(),current=previous.catch(()=>{}).then(operation);localQueues.set(key,current);current.finally(()=>{if(localQueues.get(key)===current)localQueues.delete(key);}).catch(()=>{});return current;}
// Blob values are kept out of IndexedDB's serialized-record size limit. Older
// records contain ArrayBuffers; retain read/sync compatibility with them.
const storedSize=value=>value instanceof Blob?value.size:value.byteLength;
const storedBytes=async value=>new Uint8Array(value instanceof Blob?await value.arrayBuffer():value.slice(0));
async function digest(value){return [...new Uint8Array(await crypto.subtle.digest('SHA-256',value))].map(b=>b.toString(16).padStart(2,'0')).join('');}
export class MirrorConflict extends Error{constructor(message='This file changed on another device. Choose which copy to keep.'){super(message);this.name='MirrorConflict';}}
export class MirroredFiles{
  #scope;#server;#valid;#db;#opening;#running;#closed=false;#listeners=new Set();#timer;#retryMs;#rateFailures=0;#online;#visibility;#hasPending=true;#again=false;#lastError=null;#lastSynced=null;#checked=new Map();
  constructor({scope,server,valid=()=>true,onChange=()=>{},retryMs=15000}={}){
    need(typeof scope==='string'&&scope.length>0&&scope.length<=512&&server&&typeof valid==='function'&&typeof onChange==='function','Authenticated file mirror required.');
    need(typeof retryMs==='number'&&Number.isFinite(retryMs)&&retryMs>=0,'Invalid sync retry interval.');
    this.#scope=scope;this.#server=server;this.#valid=valid;this.#retryMs=retryMs;this.#listeners.add(onChange);
    this.#online=()=>{if(!this.#running)this.#queueSync();};globalThis.addEventListener?.('online',this.#online);
    this.#visibility=()=>{if(this.#closed||!this.#retryMs)return;if(globalThis.document?.visibilityState==='visible'&&this.#lastSynced!==null&&Date.now()-this.#lastSynced>=this.#retryMs*2&&!this.#running&&globalThis.navigator?.onLine!==false)this.#queueSync();else this.#schedule();};globalThis.document?.addEventListener?.('visibilitychange',this.#visibility);
    this.#schedule();
  }
  // Spread retries after rate limits. Successful idle mirrors poll less often,
  // especially in background tabs; a manual sync or local write is immediate.
  #schedule(){
    clearTimeout(this.#timer);if(this.#closed||!this.#retryMs)return;
    const idle=!this.#hasPending&&!this.#lastError,scale=idle?(globalThis.document?.visibilityState==='hidden'?16:4):1;
    const retry=Math.min(120000,this.#retryMs*2**Math.min(this.#rateFailures,8)),base=Math.min(240000,retry*scale);
    const delay=Math.max(1,Math.round(base*(0.8+0.4*Math.random())));
    this.#timer=setTimeout(()=>{this.#timer=null;if(this.#closed)return;if(!this.#running&&globalThis.navigator?.onLine!==false)this.sync().catch(()=>{});else this.#schedule();},delay);
  }
  #queueSync(){if(this.#closed)return;if(this.#running){this.sync().catch(()=>{});return;}if(this.#rateFailures&&this.#retryMs){if(!this.#timer)this.#schedule();return;}this.sync().catch(()=>{});}
  #check(){need(!this.#closed&&this.#valid(),'Account changed. Reopen your files.');}
  #changed(){for(const fn of this.#listeners)try{fn();}catch(e){console.error('File view update failed',e);}}
  subscribe(fn){this.#check();need(typeof fn==='function','Listener required.');this.#listeners.add(fn);return ()=>this.#listeners.delete(fn);}
  async #open(){
    this.#check();if(this.#db)return this.#db;
    this.#opening??=new Promise((resolve,reject)=>{const request=indexedDB.open('codi-mirrored-files-v1',1);
      request.onupgradeneeded=()=>{const store=request.result.createObjectStore('files',{keyPath:['scope','path']});store.createIndex('scope','scope');};
      request.onerror=()=>reject(request.error);request.onblocked=()=>reject(Error('Browser file storage is blocked.'));request.onsuccess=()=>resolve(request.result);
    }).then(db=>{if(this.#closed||!this.#valid()){db.close();throw Error('Account changed. Reopen your files.');}db.onversionchange=()=>{db.close();this.#db=null;};return this.#db=db;}).finally(()=>{this.#opening=null;});
    return this.#opening;
  }
  async #tx(mode,action){
    const db=await this.#open();this.#check();return new Promise((resolve,reject)=>{const tx=db.transaction('files',mode),store=tx.objectStore('files');let result,problem;
      const fail=e=>{problem=e;try{tx.abort();}catch{}};
      tx.oncomplete=()=>{try{this.#check();resolve(result);}catch(e){reject(e);}};tx.onabort=tx.onerror=()=>reject(problem||tx.error||Error('Browser file storage failed.'));
      try{action(store,value=>{result=value;},fail);}catch(e){fail(e);}
    });
  }
  async #all(){return this.#tx('readonly',(store,done,fail)=>{const request=store.index('scope').getAll(this.#scope);request.onsuccess=()=>done(request.result);request.onerror=()=>fail(request.error);});}
  async #get(path){return this.#tx('readonly',(store,done,fail)=>{const request=store.get([this.#scope,path]);request.onsuccess=()=>done(request.result||null);request.onerror=()=>fail(request.error);});}
  async #update(path,fn){return this.#tx('readwrite',(store,done,fail)=>{const request=store.get([this.#scope,path]);request.onsuccess=()=>{try{this.#check();const [next,result]=fn(request.result||null);if(next===null)store.delete([this.#scope,path]);else if(next!==undefined)store.put(next);done(result);}catch(e){fail(e);}};request.onerror=()=>fail(request.error);});}
  // Validate hierarchy and write within one IndexedDB transaction across tabs.
  async #mutate(path,fn){return this.#tx('readwrite',(store,done,fail)=>{const request=store.index('scope').getAll(this.#scope);request.onsuccess=()=>{try{this.#check();const all=request.result,old=all.find(r=>r.path===path)||null;const [next,result]=fn(old,all);if(next===null)store.delete([this.#scope,path]);else if(next!==undefined)store.put(next);done(result);}catch(e){fail(e);}};request.onerror=()=>fail(request.error);});}
  async list(path='/'){
    path=filePath(path);const all=await this.#all();if(path!=='/'){const dir=all.find(r=>r.path===path&&!r.deleted);need(dir?.directory,'Folder not found.');}
    return {entries:all.filter(r=>(!r.deleted||r.conflict)&&parent(r.path)===path).sort((a,b)=>a.path.localeCompare(b.path)).map(r=>({path:r.path,name:name(r.path),directory:r.directory,bytes:r.directory?null:storedSize(r.data),version:r.version,deleted:r.deleted,status:r.conflict?'conflict':r.dirty?'pending':'synced',canMove:!r.directory&&!r.deleted&&!r.conflict&&!r.moving&&((!r.dirty&&typeof r.base==='string')||(r.dirty&&r.base===null)),canReceiveMove:r.directory&&!r.deleted&&!r.conflict&&!r.moving&&((!r.dirty&&r.base==='dir')||(r.dirty&&r.base===null))}))};
  }
  async status(){const all=await this.#all();return {pending:all.filter(r=>r.dirty&&!r.conflict).length,conflicts:all.filter(r=>r.conflict).length,error:this.#lastError,lastSynced:this.#lastSynced};}
  async stat(path){path=filePath(path);const r=await this.#get(path);need(r&&!r.deleted&&!r.directory,'File not found.');this.#check();return {bytes:storedSize(r.data),sha256:r.sha256,version:r.version,status:r.conflict?'conflict':r.dirty?'pending':'synced'};}
  async read(path){path=filePath(path);const r=await this.#get(path);need(r&&!r.deleted&&!r.directory,'File not found.');const data=await storedBytes(r.data);this.#check();return {data,sha256:r.sha256,version:r.version,deleted:r.deleted,status:r.conflict?'conflict':r.dirty?'pending':'synced'};}
  async write(path,data,expected=null){
    path=filePath(path);need(path!=='/','Enter a filename.');const incoming=data instanceof Blob?data:null;
    // Reject oversize byte inputs before allocating a snapshot of them.
    const hint=incoming?incoming.size:byteArray(data)||rawBuffer(data)?data.byteLength:null;
    if(hint!==null)need(Number.isSafeInteger(hint)&&hint<=MAX_FILE,'Files are limited to 128 MiB.');
    const copy=incoming?null:bytes(data),size=incoming?incoming.size:copy?.length;need(Number.isSafeInteger(size)&&size<=MAX_FILE,'Files are limited to 128 MiB.');
    // A File from an upload picker can still reference the source on disk even
    // after IndexedDB stores it. Snapshot it before the picker source vanishes.
    // The same bytes are needed for the digest; do not read the input twice.
    const snapshot=incoming?await incoming.arrayBuffer():copy,sha256=await digest(snapshot),stored=new Blob([snapshot]);this.#check();
    const result=await this.#mutate(path,(old,all)=>{if(parent(path)!=='/'){const p=all.find(r=>r.path===parent(path));need(p&&!p.deleted&&p.directory,'Create the parent folder first.');}need(all.length<MAX_ENTRIES||old,'Browser file limit reached.');if(old?.moving)throw Error('Wait for this move to finish syncing.');if(expected===null?!!old:!old||old.deleted||old.directory||old.version!==expected)throw new MirrorConflict('This file changed; reload it before saving.');
      const row={scope:this.#scope,path,directory:false,data:stored,sha256,base:old?.base??null,version:crypto.randomUUID(),dirty:true,deleted:false,conflict:!!old?.conflict};return [row,{path,version:row.version,sha256,status:row.conflict?'conflict':'pending'}];});
    this.#hasPending=true;this.#changed();this.#queueSync();return result;
  }
  async mkdir(path){path=filePath(path);need(path!=='/','Root already exists.');const result=await this.#mutate(path,(old,all)=>{if(parent(path)!=='/'){const p=all.find(r=>r.path===parent(path));need(p&&!p.deleted&&p.directory,'Create the parent folder first.');}need(all.length<MAX_ENTRIES,'Browser file limit reached.');if(old)throw new MirrorConflict('An item with that name already exists.');const row={scope:this.#scope,path,directory:true,data:null,sha256:null,base:null,version:crypto.randomUUID(),dirty:true,deleted:false,conflict:false};return [row,{path,version:row.version,status:'pending'}];});this.#hasPending=true;this.#changed();this.#queueSync();return result;}
  // The source version and new destination are checked in the same browser
  // transaction. This is a local snapshot, not a server-side copy operation.
  async copyFile(source,destination,expected){
    source=filePath(source);destination=filePath(destination);
    need(source!=='/'&&destination!=='/'&&source!==destination&&typeof expected==='string','Choose a different destination for the copy.');
    const result=await this.#mutate(destination,(old,all)=>{
      const original=all.find(row=>row.path===source);
      if(!original||original.deleted||original.directory||original.version!==expected)throw new MirrorConflict('The source file changed; reload before copying.');
      need(!original.conflict&&!original.moving,'Resolve conflicts and finish moves before copying.');
      need(!old,'An item with that name already exists.');need(all.length<MAX_ENTRIES,'Browser file limit reached.');
      if(parent(destination)!=='/'){const dir=all.find(row=>row.path===parent(destination));need(dir&&!dir.deleted&&dir.directory&&!dir.conflict&&!dir.moving,'Choose an available destination folder.');}
      const row={scope:this.#scope,path:destination,directory:false,data:original.data,sha256:original.sha256,base:null,version:crypto.randomUUID(),dirty:true,deleted:false,conflict:false};
      return [row,{path:destination,version:row.version,sha256:row.sha256,status:'pending'}];
    });
    this.#hasPending=true;this.#changed();this.#queueSync();return result;
  }
  // Copy a consistent local snapshot in one transaction. The usual mirror
  // queue then synchronizes its entries; server synchronization is not atomic.
  async copyTree(source,destination,expected){
    source=filePath(source);destination=filePath(destination);
    need(source!=='/'&&destination!=='/'&&typeof expected==='string','Choose a folder to copy.');
    need(destination!==source&&!destination.startsWith(source+'/'),'Choose a destination outside the folder being copied.');
    const result=await this.#tx('readwrite',(store,done,fail)=>{const req=store.index('scope').getAll(this.#scope);req.onsuccess=()=>{try{
      this.#check();const all=req.result,root=all.find(r=>r.path===source);
      if(!root||root.deleted||!root.directory||root.version!==expected)throw new MirrorConflict('This folder changed; reload before copying.');
      const tree=all.filter(r=>r.path===source||r.path.startsWith(source+'/'));
      need(!tree.some(r=>r.conflict||r.moving),'Resolve conflicts and finish moves in this folder before copying.');
      const present=tree.filter(r=>!r.deleted);need(all.length+present.length<=MAX_ENTRIES,'Browser file limit reached.');
      const existing=new Set(all.map(r=>r.path));
      if(parent(destination)!=='/'){const dir=all.find(r=>r.path===parent(destination));need(dir&&!dir.deleted&&dir.directory&&!dir.conflict&&!dir.moving,'Choose an available destination folder.');}
      const copies=present.map(r=>{const path=filePath(destination+r.path.slice(source.length));need(!existing.has(path),'An item with that name already exists.');return {scope:this.#scope,path,directory:r.directory,data:r.data,sha256:r.sha256,base:null,version:crypto.randomUUID(),dirty:true,deleted:false,conflict:false};});
      for(const row of copies)store.put(row);done({path:destination,entries:copies.length});
    }catch(e){fail(e);}};req.onerror=()=>fail(req.error);});
    this.#hasPending=true;this.#changed();this.#queueSync();return result;
  }
  // Import a prevalidated archive as one browser-storage transaction. Server
  // synchronization remains per-entry and can be interrupted or conflict.
  async importTree(root,entries,source,expected){
    root=filePath(root);source=filePath(source);
    need(root!=='/'&&source!=='/'&&typeof expected==='string'&&Array.isArray(entries)&&entries.length<MAX_ENTRIES,'Invalid archive import.');
    const rows=[{path:root,directory:true,data:null,sha256:null}],seen=new Set([root]);let total=0;
    for(const entry of entries){
      need(entry&&typeof entry==='object'&&typeof entry.directory==='boolean','Invalid archive entry.');
      const path=filePath(entry.path);need(path.startsWith(root+'/')&&!seen.has(path),'Duplicate or invalid archive path.');seen.add(path);
      if(entry.directory)rows.push({path,directory:true,data:null,sha256:null});
      else{const data=bytes(entry.data);need(data&&data.length<=MAX_FILE&&(total+=data.length)<=MAX_FILE,'Archive data exceeds 128 MiB.');const hash=await digest(data);this.#check();rows.push({path,directory:false,data:new Blob([data]),sha256:hash});}
    }
    const directories=new Set(rows.filter(r=>r.directory).map(r=>r.path));
    for(const row of rows.slice(1))need(directories.has(parent(row.path)),'Archive is missing a parent folder.');
    const result=await this.#tx('readwrite',(store,done,fail)=>{const req=store.index('scope').getAll(this.#scope);req.onsuccess=()=>{try{
      this.#check();const all=req.result,original=all.find(r=>r.path===source);
      if(!original||original.deleted||original.directory||original.version!==expected||original.conflict||original.moving)throw new MirrorConflict('The ZIP changed. Reload and try again.');
      need(all.length+rows.length<=MAX_ENTRIES,'Browser file limit reached.');
      const existing=new Set(all.map(r=>r.path));for(const row of rows)need(!existing.has(row.path),'An item with that name already exists.');
      if(parent(root)!=='/'){const dir=all.find(r=>r.path===parent(root));need(dir&&!dir.deleted&&dir.directory&&!dir.conflict&&!dir.moving,'Choose an available destination folder.');}
      for(const row of rows)store.put({scope:this.#scope,...row,base:null,version:crypto.randomUUID(),dirty:true,deleted:false,conflict:false});
      done({path:root,entries:rows.length});
    }catch(e){fail(e);}};req.onerror=()=>fail(req.error);});
    this.#hasPending=true;this.#changed();this.#queueSync();return result;
  }
  async remove(path,expected){path=filePath(path);need(path!=='/'&&typeof expected==='string','A saved version is required.');await this.#mutate(path,(old,all)=>{need(!all.some(r=>!r.deleted&&parent(r.path)===path),'Folder must be empty before deleting.');if(old?.moving)throw Error('Wait for this move to finish syncing.');if(!old||old.deleted||old.version!==expected)throw new MirrorConflict('This item changed; reload before deleting.');return [{...old,version:crypto.randomUUID(),dirty:true,deleted:true,conflict:!!old.conflict},true];});this.#hasPending=true;this.#changed();this.#queueSync();}
  // A new local-only file can change paths in one local transaction. A saved
  // file keeps a two-path journal so the server rename is version checked.
  async move(source,destination,expected){
    source=filePath(source);destination=filePath(destination);need(source!=='/'&&destination!=='/'&&source!==destination&&typeof expected==='string','Choose a different destination.');
    await this.#exclusive(()=>this.#tx('readwrite',(store,done,fail)=>{const req=store.index('scope').getAll(this.#scope);req.onsuccess=()=>{try{this.#check();const all=req.result,old=all.find(r=>r.path===source);if(!old||old.deleted||old.directory||old.version!==expected)throw new MirrorConflict('This file changed; reload before moving.');const neverSynced=old.dirty&&old.base===null;need(!old.conflict&&!old.moving&&(neverSynced||(!old.dirty&&typeof old.base==='string')),'Save this file before moving it.');need(!all.some(r=>r.path===destination),'An item with that name already exists.');if(parent(destination)!=='/'){const dir=all.find(r=>r.path===parent(destination));need(dir&&!dir.deleted&&dir.directory&&!dir.moving&&!dir.conflict&&(!dir.dirty||dir.base===null),'Choose an available folder.');}
      if(neverSynced){store.delete([this.#scope,source]);store.put({...old,path:destination,base:null,version:crypto.randomUUID(),dirty:true,deleted:false,moving:false});done(true);}
      else{store.put({...old,path:destination,base:null,version:crypto.randomUUID(),dirty:true,deleted:false,moving:true,moveFrom:source});store.put({...old,version:crypto.randomUUID(),dirty:true,deleted:true,moving:true,moveTo:destination});done(true);}
    }catch(e){fail(e);}};req.onerror=()=>fail(req.error);}));this.#hasPending=true;this.#changed();this.#queueSync();
  }
  async #finishMove(source,destination,{restore=false,conflict=false}={}){
    return this.#tx('readwrite',(store,done,fail)=>{const req=store.index('scope').getAll(this.#scope);req.onsuccess=()=>{try{const all=req.result,a=all.find(r=>r.path===source.path),b=all.find(r=>r.path===destination.path);if(!a||!b||a.version!==source.version||b.version!==destination.version||a.moveTo!==b.path||b.moveFrom!==a.path)throw new MirrorConflict('Move changed in another tab.');if(restore){const {moving,moveTo,...prior}=a;store.put({...prior,deleted:false,dirty:conflict,conflict,version:crypto.randomUUID()});store.delete([this.#scope,b.path]);}else{const {moving,moveFrom,...next}=b;store.put({...next,base:source.base,dirty:false,conflict:false,version:crypto.randomUUID()});store.delete([this.#scope,a.path]);}done(true);}catch(e){fail(e);}};req.onerror=()=>fail(req.error);});
  }
  async #remoteInventory(){
    const inventory=new Map();
    if(typeof this.#server.supportsInventoryVersions==='function'&&typeof this.#server.inventoryVersions==='function'&&await this.#server.supportsInventoryVersions()){
      this.#check();const snapshot=await this.#server.inventoryVersions();this.#check();need(snapshot&&typeof snapshot.complete==='boolean'&&Array.isArray(snapshot.entries)&&snapshot.entries.length<=2048,'Invalid server inventory.');
      if(snapshot.complete){let hashed=0,bytes=0;for(const item of snapshot.entries){need(item&&typeof item.path==='string'&&!item.path.startsWith('/')&&typeof item.directory==='boolean','Invalid server inventory entry.');const keys=Object.keys(item).sort().join(',');need(keys==='directory,path'||(!item.directory&&keys==='bytes,directory,path,sha256'&&Number.isSafeInteger(item.bytes)&&item.bytes>=0&&item.bytes<=MAX_FILE&&typeof item.sha256==='string'&&/^[0-9a-f]{64}$/.test(item.sha256)),'Invalid server inventory version.');if(item.sha256){hashed++;bytes+=item.bytes;}const path=filePath('/'+item.path);need(!inventory.has(path),'Duplicate server inventory entry.');inventory.set(path,item.sha256?{directory:false,bytes:item.bytes,sha256:item.sha256}:{directory:item.directory});}need(hashed<=64&&bytes<=32*1024*1024,'Server inventory version limit exceeded.');for(const [path] of inventory){const dir=parent(path);need(dir==='/'||inventory.get(dir)?.directory===true,'Invalid server inventory hierarchy.');}return inventory;}
      need(snapshot.entries.length===0,'Incomplete server inventory.');
    }
    if(typeof this.#server.supportsInventory==='function'&&typeof this.#server.inventory==='function'&&await this.#server.supportsInventory()){
      this.#check();const snapshot=await this.#server.inventory();this.#check();need(snapshot&&typeof snapshot.complete==='boolean'&&Array.isArray(snapshot.entries)&&snapshot.entries.length<=2048,'Invalid server inventory.');
      if(snapshot.complete){for(const item of snapshot.entries){need(item&&typeof item.path==='string'&&!item.path.startsWith('/')&&typeof item.directory==='boolean','Invalid server inventory entry.');const path=filePath('/'+item.path);need(!inventory.has(path),'Duplicate server inventory entry.');inventory.set(path,{directory:item.directory});}for(const [path] of inventory){const dir=parent(path);need(dir==='/'||inventory.get(dir)?.directory===true,'Invalid server inventory hierarchy.');}return inventory;}
      need(snapshot.entries.length===0,'Incomplete server inventory.');
    }
    const queue=['/'];while(queue.length){this.#check();const dir=queue.shift(),result=await this.#server.list(dir==='/'?'':dir.slice(1));this.#check();need(Array.isArray(result.entries),'Invalid server folder listing.');
      for(const item of result.entries){need(item&&typeof item.name==='string'&&typeof item.directory==='boolean','Invalid server file listing.');const path=filePath((dir==='/'?'':dir)+'/'+item.name);need(!inventory.has(path)&&inventory.size<MAX_ENTRIES,'Server file list exceeds the browser limit.');inventory.set(path,{directory:item.directory});if(item.directory)queue.push(path);}
    }return inventory;
  }
  async #ack(row,base,{remove=false}={}){await this.#update(row.path,current=>{if(!current)return [undefined,false];if(current.version===row.version)return [remove?null:{...current,base,dirty:false,conflict:false},true];if(current.base===row.base)return [{...current,base},false];return [undefined,false];});}
  async #conflict(row){await this.#update(row.path,current=>current?.version===row.version?[{...current,conflict:true},true]:[undefined,false]);}
  async #install(row,remote){await this.#update(row.path,current=>{if(row.version===null?!!current:!current||current.version!==row.version||current.dirty)return [undefined,false];return [{scope:this.#scope,path:row.path,directory:remote.directory,data:remote.data??null,sha256:remote.sha256??null,base:remote.directory?'dir':remote.sha256,version:crypto.randomUUID(),dirty:false,deleted:false,conflict:false},true];});}
  async #pass(){
    this.#check();const canVersion=typeof this.#server.supportsVersion==='function'&&typeof this.#server.version==='function'&&await this.#server.supportsVersion();
    const canBatch=canVersion&&typeof this.#server.supportsVersionBatch==='function'&&typeof this.#server.versions==='function'&&await this.#server.supportsVersionBatch(),batchCache=new Map();
    const version=async(path,item)=>item?.sha256?item:batchCache.get(path)??(canVersion?await this.#server.version(path):await this.#server.read(path));
    let remote=await this.#remoteInventory(),rows=await this.#all();this.#check();
    // Recover an interrupted rename by checking both server paths and hashes.
    for(const source of rows.filter(r=>r.moving&&r.moveTo)){
      const destination=rows.find(r=>r.path===source.moveTo&&r.moving&&r.moveFrom===source.path);
      need(destination,'Move journal is incomplete.');const from=remote.get(source.path),to=remote.get(destination.path);
      const original=from&&!from.directory?await version(source.path.slice(1),from):null;
      const target=to&&!to.directory?await version(destination.path.slice(1),to):null;
      if(!from&&target?.sha256===source.base){await this.#finishMove(source,destination);continue;}
      if(from&&!from.directory&&original?.sha256===source.base&&!to){await this.#server.rename(source.path.slice(1),destination.path.slice(1),source.base);await this.#finishMove(source,destination);continue;}
      const changed=!from||from.directory||original?.sha256!==source.base;
      await this.#finishMove(source,destination,{restore:true,conflict:changed});
      throw Error(changed?'The file changed on the server; resolve the conflict before moving.':'The destination already exists on the server.');
    }
    if(rows.some(r=>r.moving)){remote=await this.#remoteInventory();rows=await this.#all();}
    // Create parents before children; remove children before parents.
    const dirty=rows.filter(r=>r.dirty&&!r.conflict&&!r.moving).sort((a,b)=>(a.deleted?1:0)-(b.deleted?1:0)||(a.deleted?b.path.length-a.path.length:a.path.length-b.path.length));
    for(let index=0;index<dirty.length;index++){const row=dirty[index];this.#check();const existing=remote.get(row.path),target=row.path.slice(1);
      // Updating existing files needs their server versions. Fetch a bounded
      // group together; the eventual write/delete still enforces its base hash.
      if(canBatch&&!row.directory&&existing&&!existing.directory&&!existing.sha256&&!batchCache.has(target)){
        const paths=[];let length=0;for(let i=index;i<dirty.length&&paths.length<16;i++){const candidate=dirty[i],entry=remote.get(candidate.path),relative=candidate.path.slice(1),size=new TextEncoder().encode(relative).length;if(candidate.directory||!entry||entry.directory||entry.sha256||batchCache.has(relative))continue;if(length+size>8192)break;paths.push(relative);length+=size;}
        if(paths.length){const values=await this.#server.versions(paths);this.#check();need(Array.isArray(values)&&values.length===paths.length,'Invalid batch file versions.');for(let i=0;i<paths.length;i++)batchCache.set(paths[i],values[i]);}
      }
      if(row.directory){
        if(row.deleted){if(existing){if(!existing.directory||[...remote.keys()].some(p=>parent(p)===row.path)){await this.#conflict(row);continue;}await this.#server.remove(target,null);remote.delete(row.path);}await this.#ack(row,null,{remove:true});}
        else if(existing&&!existing.directory)await this.#conflict(row);
        else{if(!existing){await this.#server.mkdir(target);remote.set(row.path,{directory:true});}await this.#ack(row,'dir');}
      }else{
        if(existing?.directory){await this.#conflict(row);continue;}
        const current=existing?await version(target,existing):null;this.#check();
        if(row.deleted){if(!current){await this.#ack(row,null,{remove:true});continue;}if(current.sha256!==row.base){await this.#conflict(row);continue;}await this.#server.remove(target,row.base);remote.delete(row.path);await this.#ack(row,null,{remove:true});}
        else if(current?.sha256===row.sha256)await this.#ack(row,row.sha256);
        else if((current?.sha256??null)!==row.base)await this.#conflict(row);
        else{await this.#server.write(target,await storedBytes(row.data),row.base);remote.set(row.path,{directory:false,sha256:row.sha256});await this.#ack(row,row.sha256);}
      }
    }
    // Re-read current local rows: an edit can arrive while the server is slow.
    const fresh=await this.#all(),local=new Map(fresh.map(r=>[r.path,r])),issues=[];
    const entries=[...remote];
    for(let index=0;index<entries.length;index++){const [path,item]=entries[index];this.#check();const row=local.get(path);if(row?.dirty)continue;
      if(item.directory){if(!row)await this.#install({path,version:null},{directory:true});else if(!row.directory)await this.#conflict({...row,dirty:true});continue;}
      if(row?.directory){await this.#conflict({...row,dirty:true});continue;}
      // Keep verified progress only while a scan is incomplete. A local edit
      // changes the row version and invalidates the entry. The next complete
      // scan starts fresh, so external edits are still eventually discovered.
      if(row&&this.#checked.get(path)===row.version)continue;
      let value;try{if(canBatch&&!item.sha256&&!batchCache.has(path.slice(1))){const paths=[];let bytes=0;for(let i=index;i<entries.length&&paths.length<16;i++){const [other,record]=entries[i],r=local.get(other),relative=other.slice(1),length=new TextEncoder().encode(relative).length;if(record.directory||record.sha256||r?.dirty||(r&&this.#checked.get(other)===r.version)||batchCache.has(relative))continue;if(bytes+length>8192)break;paths.push(relative);bytes+=length;}if(paths.length){const values=await this.#server.versions(paths);this.#check();need(Array.isArray(values)&&values.length===paths.length,'Invalid batch file versions.');for(let i=0;i<paths.length;i++)batchCache.set(paths[i],values[i]);}}value=await version(path.slice(1),item);if(!row||row.sha256!==value.sha256){if(!('data' in value))value=row?.data instanceof Blob&&typeof this.#server.readChunked==='function'?await this.#server.readChunked(path.slice(1),value.sha256,row.data):await this.#server.read(path.slice(1));this.#check();await this.#install({path,version:row?.version??null},{directory:false,data:new Blob([value.data]),sha256:value.sha256});}const current=await this.#get(path);if(current&&!current.dirty&&!current.directory&&current.sha256===value.sha256)this.#checked.set(path,current.version);}catch(error){if(error?.status===429)throw error;issues.push('Could not sync '+path+': '+(error.message||'server file unavailable'));continue;}
    }
    for(const row of fresh){if(row.dirty||remote.has(row.path))continue;if(row.directory&&fresh.some(child=>child.dirty&&child.path.startsWith(row.path+'/')))continue;await this.#update(row.path,current=>current&&!current.dirty&&current.version===row.version?[null,true]:[undefined,false]);}
    this.#changed();if(issues.length)throw Error(issues[0]+(issues.length>1?' (and '+(issues.length-1)+' other files)':''));this.#checked.clear();const remaining=await this.#all();this.#hasPending=remaining.some(r=>r.dirty&&!r.conflict);return {pending:remaining.filter(r=>r.dirty).length};
  }
  #exclusive(operation){return serializeLocal(this.#scope,()=>{const locks=globalThis.navigator?.locks;return locks?.request?locks.request('codi-mirror:'+this.#scope,{mode:'exclusive'},operation):operation();});}
  sync(){this.#check();if(this.#running){this.#again=true;return this.#running;}const run=async()=>{let result;do{this.#again=false;result=await this.#pass();}while(this.#again&&!this.#closed&&this.#valid());return result;};const task=this.#exclusive(run).then(result=>{this.#rateFailures=0;this.#lastError=null;this.#lastSynced=Date.now();this.#changed();return result;},error=>{if(!this.#closed){if(error?.status===429)this.#rateFailures=Math.min(this.#rateFailures+1,8);else this.#rateFailures=0;this.#lastError=error.message||'Server sync unavailable.';this.#changed();}throw error;}).finally(()=>{const repeat=this.#again;this.#again=false;if(this.#running===task)this.#running=null;this.#schedule();if(repeat&&!this.#rateFailures&&!this.#closed&&this.#valid())this.sync().catch(()=>{});});this.#running=task;return task;}
  async resolve(path,choice,expected){path=filePath(path);need(['local','server'].includes(choice),'Choose which copy to keep.');const row=await this.#get(path);if(!row||!row.conflict||row.version!==expected)throw new MirrorConflict('This item changed; reload before resolving.');need(!row.directory,'Folder conflicts require manual resolution.');
    const inventory=await this.#remoteInventory(),entry=inventory.get(path);need(!entry?.directory,'The server has a folder at this path.');const remote=entry?await this.#server.read(path.slice(1)):null;this.#check();
    if(choice==='local'){await this.#update(path,current=>{if(!current||current.version!==expected)throw new MirrorConflict();return [{...current,base:remote?.sha256??null,conflict:false,dirty:true},true];});}
    else{await this.#update(path,current=>{if(!current||current.version!==expected)throw new MirrorConflict();if(!remote)return [null,true];return [{scope:this.#scope,path,directory:false,data:new Blob([remote.data]),sha256:remote.sha256,base:remote.sha256,version:crypto.randomUUID(),dirty:false,deleted:false,conflict:false},true];});}
    this.#changed();if(choice==='local'){this.#hasPending=true;this.#queueSync();}
  }
  async persistence(){return {supported:typeof navigator.storage?.persist==='function'&&typeof navigator.storage?.persisted==='function',persistent:typeof navigator.storage?.persisted==='function'&&await navigator.storage.persisted()===true};}
  async requestPersistence(){need(navigator.userActivation?.isActive,'Use the storage protection button.');need(typeof navigator.storage?.persist==='function','Storage protection is unavailable.');await navigator.storage.persist();return this.persistence();}
  close(){if(this.#closed)return;this.#closed=true;clearTimeout(this.#timer);globalThis.removeEventListener?.('online',this.#online);globalThis.document?.removeEventListener?.('visibilitychange',this.#visibility);this.#listeners.clear();this.#checked.clear();this.#db?.close();this.#db=null;}
}
