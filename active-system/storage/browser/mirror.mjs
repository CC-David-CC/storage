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
const bytes=value=>typeof value==='string'?new TextEncoder().encode(value):value instanceof Uint8Array?Uint8Array.from(value):value instanceof ArrayBuffer?new Uint8Array(value.slice(0)):null;
// Blob values are kept out of IndexedDB's serialized-record size limit. Older
// records contain ArrayBuffers; retain read/sync compatibility with them.
const storedSize=value=>value instanceof Blob?value.size:value.byteLength;
const storedBytes=async value=>new Uint8Array(value instanceof Blob?await value.arrayBuffer():value.slice(0));
async function digest(value){return [...new Uint8Array(await crypto.subtle.digest('SHA-256',value))].map(b=>b.toString(16).padStart(2,'0')).join('');}
export class MirrorConflict extends Error{constructor(message='This file changed on another device. Choose which copy to keep.'){super(message);this.name='MirrorConflict';}}
export class MirroredFiles{
  #scope;#server;#valid;#db;#opening;#running;#closed=false;#listeners=new Set();#timer;#online;#again=false;#lastError=null;#lastSynced=null;
  constructor({scope,server,valid=()=>true,onChange=()=>{},retryMs=15000}={}){
    need(typeof scope==='string'&&scope.length>0&&scope.length<=512&&server&&typeof valid==='function'&&typeof onChange==='function','Authenticated file mirror required.');
    this.#scope=scope;this.#server=server;this.#valid=valid;this.#listeners.add(onChange);
    this.#online=()=>{if(!this.#running)this.sync().catch(()=>{});};globalThis.addEventListener?.('online',this.#online);
    // A slow transfer can exceed the retry period. Periodic retries must not
    // keep requesting another full pass and prevent an explicit sync settling.
    if(retryMs>0)this.#timer=setInterval(()=>{if(!this.#running&&globalThis.navigator?.onLine!==false)this.sync().catch(()=>{});},retryMs);
  }
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
    return {entries:all.filter(r=>(!r.deleted||r.conflict)&&parent(r.path)===path).sort((a,b)=>a.path.localeCompare(b.path)).map(r=>({path:r.path,name:name(r.path),directory:r.directory,bytes:r.directory?null:storedSize(r.data),version:r.version,deleted:r.deleted,status:r.conflict?'conflict':r.dirty?'pending':'synced'}))};
  }
  async status(){const all=await this.#all();return {pending:all.filter(r=>r.dirty&&!r.conflict).length,conflicts:all.filter(r=>r.conflict).length,error:this.#lastError,lastSynced:this.#lastSynced};}
  async read(path){path=filePath(path);const r=await this.#get(path);need(r&&!r.deleted&&!r.directory,'File not found.');const data=await storedBytes(r.data);this.#check();return {data,sha256:r.sha256,version:r.version,deleted:r.deleted,status:r.conflict?'conflict':r.dirty?'pending':'synced'};}
  async write(path,data,expected=null){
    path=filePath(path);need(path!=='/','Enter a filename.');const copy=bytes(data);need(copy&&copy.length<=MAX_FILE,'Files are limited to 128 MiB.');const sha256=await digest(copy);this.#check();
    const result=await this.#mutate(path,(old,all)=>{if(parent(path)!=='/'){const p=all.find(r=>r.path===parent(path));need(p&&!p.deleted&&p.directory,'Create the parent folder first.');}need(all.length<MAX_ENTRIES||old,'Browser file limit reached.');if(old?.moving)throw Error('Wait for this move to finish syncing.');if(expected===null?!!old:!old||old.deleted||old.directory||old.version!==expected)throw new MirrorConflict('This file changed; reload it before saving.');
      const row={scope:this.#scope,path,directory:false,data:new Blob([copy]),sha256,base:old?.base??null,version:crypto.randomUUID(),dirty:true,deleted:false,conflict:!!old?.conflict};return [row,{path,version:row.version,sha256,status:row.conflict?'conflict':'pending'}];});
    this.#changed();this.sync().catch(()=>{});return result;
  }
  async mkdir(path){path=filePath(path);need(path!=='/','Root already exists.');const result=await this.#mutate(path,(old,all)=>{if(parent(path)!=='/'){const p=all.find(r=>r.path===parent(path));need(p&&!p.deleted&&p.directory,'Create the parent folder first.');}need(all.length<MAX_ENTRIES,'Browser file limit reached.');if(old)throw new MirrorConflict('An item with that name already exists.');const row={scope:this.#scope,path,directory:true,data:null,sha256:null,base:null,version:crypto.randomUUID(),dirty:true,deleted:false,conflict:false};return [row,{path,version:row.version,status:'pending'}];});this.#changed();this.sync().catch(()=>{});return result;}
  async remove(path,expected){path=filePath(path);need(path!=='/'&&typeof expected==='string','A saved version is required.');await this.#mutate(path,(old,all)=>{need(!all.some(r=>!r.deleted&&parent(r.path)===path),'Folder must be empty before deleting.');if(old?.moving)throw Error('Wait for this move to finish syncing.');if(!old||old.deleted||old.version!==expected)throw new MirrorConflict('This item changed; reload before deleting.');return [{...old,version:crypto.randomUUID(),dirty:true,deleted:true,conflict:!!old.conflict},true];});this.#changed();this.sync().catch(()=>{});}
  // Journal both sides atomically; server rename is version checked.
  async move(source,destination,expected){
    source=filePath(source);destination=filePath(destination);need(source!=='/'&&destination!=='/'&&source!==destination&&typeof expected==='string','Choose a different destination.');
    await this.#tx('readwrite',(store,done,fail)=>{const req=store.index('scope').getAll(this.#scope);req.onsuccess=()=>{try{this.#check();const all=req.result,old=all.find(r=>r.path===source);if(!old||old.deleted||old.directory||old.version!==expected)throw new MirrorConflict('This file changed; reload before moving.');need(!old.dirty&&!old.conflict&&!old.moving&&typeof old.base==='string','Wait for this file to finish syncing before moving it.');need(!all.some(r=>r.path===destination),'An item with that name already exists.');if(parent(destination)!=='/'){const dir=all.find(r=>r.path===parent(destination));need(dir&&!dir.deleted&&dir.directory&&!dir.moving&&!dir.dirty&&!dir.conflict,'Wait for the destination folder to finish syncing.');}
      store.put({...old,path:destination,base:null,version:crypto.randomUUID(),dirty:true,deleted:false,moving:true,moveFrom:source});store.put({...old,version:crypto.randomUUID(),dirty:true,deleted:true,moving:true,moveTo:destination});done(true);
    }catch(e){fail(e);}};req.onerror=()=>fail(req.error);});this.#changed();this.sync().catch(()=>{});
  }
  async #finishMove(source,destination,{restore=false,conflict=false}={}){
    return this.#tx('readwrite',(store,done,fail)=>{const req=store.index('scope').getAll(this.#scope);req.onsuccess=()=>{try{const all=req.result,a=all.find(r=>r.path===source.path),b=all.find(r=>r.path===destination.path);if(!a||!b||a.version!==source.version||b.version!==destination.version||a.moveTo!==b.path||b.moveFrom!==a.path)throw new MirrorConflict('Move changed in another tab.');if(restore){const {moving,moveTo,...prior}=a;store.put({...prior,deleted:false,dirty:conflict,conflict,version:crypto.randomUUID()});store.delete([this.#scope,b.path]);}else{const {moving,moveFrom,...next}=b;store.put({...next,base:source.base,dirty:false,conflict:false,version:crypto.randomUUID()});store.delete([this.#scope,a.path]);}done(true);}catch(e){fail(e);}};req.onerror=()=>fail(req.error);});
  }
  async #remoteInventory(){
    const inventory=new Map(),queue=['/'];while(queue.length){this.#check();const dir=queue.shift(),result=await this.#server.list(dir==='/'?'':dir.slice(1));this.#check();need(Array.isArray(result.entries),'Invalid server folder listing.');
      for(const item of result.entries){need(item&&typeof item.name==='string'&&typeof item.directory==='boolean','Invalid server file listing.');const path=filePath((dir==='/'?'':dir)+'/'+item.name);need(!inventory.has(path)&&inventory.size<MAX_ENTRIES,'Server file list exceeds the browser limit.');inventory.set(path,{directory:item.directory});if(item.directory)queue.push(path);}
    }return inventory;
  }
  async #ack(row,base,{remove=false}={}){await this.#update(row.path,current=>{if(!current)return [undefined,false];if(current.version===row.version)return [remove?null:{...current,base,dirty:false,conflict:false},true];if(current.base===row.base)return [{...current,base},false];return [undefined,false];});}
  async #conflict(row){await this.#update(row.path,current=>current?.version===row.version?[{...current,conflict:true},true]:[undefined,false]);}
  async #install(row,remote){await this.#update(row.path,current=>{if(row.version===null?!!current:!current||current.version!==row.version||current.dirty)return [undefined,false];return [{scope:this.#scope,path:row.path,directory:remote.directory,data:remote.data??null,sha256:remote.sha256??null,base:remote.directory?'dir':remote.sha256,version:crypto.randomUUID(),dirty:false,deleted:false,conflict:false},true];});}
  async #pass(){
    this.#check();const canVersion=typeof this.#server.supportsVersion==='function'&&typeof this.#server.version==='function'&&await this.#server.supportsVersion();
    const version=async(path,item)=>item?.sha256?item:canVersion?await this.#server.version(path):await this.#server.read(path);
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
    for(const row of dirty){this.#check();const existing=remote.get(row.path),target=row.path.slice(1);
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
    for(const [path,item] of remote){this.#check();const row=local.get(path);if(row?.dirty)continue;
      if(item.directory){if(!row)await this.#install({path,version:null},{directory:true});else if(!row.directory)await this.#conflict({...row,dirty:true});continue;}
      if(row?.directory){await this.#conflict({...row,dirty:true});continue;}
      let value;try{value=await version(path.slice(1),item);if(!row||row.sha256!==value.sha256){if(canVersion)value=await this.#server.read(path.slice(1));this.#check();await this.#install({path,version:row?.version??null},{directory:false,data:new Blob([value.data]),sha256:value.sha256});}}catch(error){issues.push('Could not sync '+path+': '+(error.message||'server file unavailable'));continue;}
    }
    for(const row of fresh){if(row.dirty||remote.has(row.path))continue;if(row.directory&&fresh.some(child=>child.dirty&&child.path.startsWith(row.path+'/')))continue;await this.#update(row.path,current=>current&&!current.dirty&&current.version===row.version?[null,true]:[undefined,false]);}
    this.#changed();if(issues.length)throw Error(issues[0]+(issues.length>1?' (and '+(issues.length-1)+' other files)':''));return {pending:(await this.#all()).filter(r=>r.dirty).length};
  }
  sync(){this.#check();if(this.#running){this.#again=true;return this.#running;}const run=async()=>{let result;do{this.#again=false;result=await this.#pass();}while(this.#again&&!this.#closed&&this.#valid());return result;};const task=(globalThis.navigator?.locks?.request?navigator.locks.request('codi-mirror:'+this.#scope,{mode:'exclusive'},run):run()).then(result=>{this.#lastError=null;this.#lastSynced=Date.now();this.#changed();return result;},error=>{if(!this.#closed){this.#lastError=error.message||'Server sync unavailable.';this.#changed();}throw error;}).finally(()=>{if(this.#running===task)this.#running=null;});this.#running=task;return task;}
  async resolve(path,choice,expected){path=filePath(path);need(['local','server'].includes(choice),'Choose which copy to keep.');const row=await this.#get(path);if(!row||!row.conflict||row.version!==expected)throw new MirrorConflict('This item changed; reload before resolving.');need(!row.directory,'Folder conflicts require manual resolution.');
    const inventory=await this.#remoteInventory(),entry=inventory.get(path);need(!entry?.directory,'The server has a folder at this path.');const remote=entry?await this.#server.read(path.slice(1)):null;this.#check();
    if(choice==='local'){await this.#update(path,current=>{if(!current||current.version!==expected)throw new MirrorConflict();return [{...current,base:remote?.sha256??null,conflict:false,dirty:true},true];});}
    else{await this.#update(path,current=>{if(!current||current.version!==expected)throw new MirrorConflict();if(!remote)return [null,true];return [{scope:this.#scope,path,directory:false,data:new Blob([remote.data]),sha256:remote.sha256,base:remote.sha256,version:crypto.randomUUID(),dirty:false,deleted:false,conflict:false},true];});}
    this.#changed();if(choice==='local')this.sync().catch(()=>{});
  }
  async persistence(){return {supported:typeof navigator.storage?.persist==='function'&&typeof navigator.storage?.persisted==='function',persistent:typeof navigator.storage?.persisted==='function'&&await navigator.storage.persisted()===true};}
  async requestPersistence(){need(navigator.userActivation?.isActive,'Use the storage protection button.');need(typeof navigator.storage?.persist==='function','Storage protection is unavailable.');await navigator.storage.persist();return this.persistence();}
  close(){if(this.#closed)return;this.#closed=true;clearInterval(this.#timer);globalThis.removeEventListener?.('online',this.#online);this.#listeners.clear();this.#db?.close();this.#db=null;}
}
