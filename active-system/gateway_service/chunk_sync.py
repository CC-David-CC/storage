"""Research-only versioned, file-scoped chunk reader for signed gateway RPC.

No on-server chunk cache: manifests are derived from the authorized flat file.
"""
import base64,hashlib,os,re
from .policy import Denied
from .user_store import Conflict

MIN=16*1024
MAX=256*1024
MASK=(1<<16)-1
GEAR=tuple(int.from_bytes(hashlib.sha256(b'codi-chunk-v1:'+bytes([i])).digest()[:8],'big') for i in range(256))
HASH=re.compile(r'^[0-9a-f]{64}$')

def manifest(fd,size,version):
    chunks=[];current=bytearray();rolling=0;position=0;offset=0;whole=hashlib.sha256()
    while position<size:
        data=os.pread(fd,min(65536,size-position),position)
        if not data:raise Denied('Snapshot truncated')
        position+=len(data);whole.update(data)
        for byte in data:
            current.append(byte);rolling=((rolling<<1)+GEAR[byte])&0xffffffffffffffff
            if len(current)>=MAX or (len(current)>=MIN and not (rolling&MASK)):
                chunks.append([offset,len(current),hashlib.sha256(current).hexdigest()]);offset+=len(current);current.clear();rolling=0
    if current:chunks.append([offset,len(current),hashlib.sha256(current).hexdigest()])
    if whole.hexdigest()!=version:raise Denied('Snapshot changed during manifest generation')
    return {'version':'codi-file-chunks/1','size':size,'sha256':version,'chunks':chunks}

def read_chunk(fd,size,offset,length,expected):
    if type(offset) is not int or type(length) is not int or offset<0 or not 0<length<=MAX or offset+length>size or not isinstance(expected,str) or not HASH.fullmatch(expected):raise Denied('Invalid chunk range')
    data=os.pread(fd,length,offset)
    if len(data)!=length or hashlib.sha256(data).hexdigest()!=expected:raise Denied('Chunk changed or hash mismatch')
    return {'offset':offset,'length':length,'sha256':expected,'data':base64.b64encode(data).decode('ascii')}

# Research cache: an unlinked private copy of a verified account file avoids
# trusting in-place host writes and avoids a whole-file hash per chunk request.
import tempfile,threading,time
from collections import OrderedDict

def identity(info):return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)

class SnapshotLease:
    def __init__(self,cache,key,item,fd):self.cache=cache;self.key=key;self.item=item;self.fd=fd;self.closed=False;self.lock=threading.Lock()
    def close(self):
        with self.lock:
            if self.closed:return
            self.closed=True
        # An ambiguous close error may leave the duplicate alive. Keep its
        # entry pinned (fail closed) rather than undercounting disk usage.
        os.close(self.fd)
        self.cache._release(self.key,self.item)

class SnapshotCache:
    def __init__(self,store,maximum_bytes=1024*1024*1024,ttl=60,maximum_entries=128,minimum_free_bytes=2*1024*1024*1024,temporary_directory=None):
        if type(maximum_bytes) is not int or maximum_bytes<0 or type(maximum_entries) is not int or maximum_entries<1 or type(minimum_free_bytes) is not int or minimum_free_bytes<0:raise ValueError('Invalid cache capacity')
        self.store=store;self.maximum_bytes=maximum_bytes;self.maximum_entries=maximum_entries;self.minimum_free_bytes=minimum_free_bytes;self.temporary_directory=temporary_directory or tempfile.gettempdir();self.ttl=ttl;self.lock=threading.Lock();self.entries=OrderedDict();self.bytes=0;self.reserved=0;self.inflight=0;self.closed=False
    def _free_bytes(self):
        stats=os.statvfs(self.temporary_directory)
        return stats.f_bavail*stats.f_frsize
    def _drop(self,key):
        item=self.entries[key]
        if item['users']:raise RuntimeError('Cannot evict an active snapshot')
        del self.entries[key];self.bytes-=item['size'];item['file'].close()
    def _lease(self,key,item):
        fd=os.dup(item['file'].fileno())
        try:lease=SnapshotLease(self,key,item,fd)
        except BaseException:
            os.close(fd);raise
        item['users']+=1;item['last']=time.monotonic();self.entries.move_to_end(key)
        return lease
    def _release(self,key,item):
        with self.lock:
            if self.entries.get(key) is not item or item['users']<1:raise RuntimeError('Invalid snapshot lease')
            item['users']-=1;item['last']=time.monotonic()
            if self.closed and not item['users']:self._drop(key)
    def close(self):
        with self.lock:
            self.closed=True
            for key,item in list(self.entries.items()):
                if not item['users']:self._drop(key)
    def open(self,principal,path,version,maximum):
        key=(principal.sub,path,version);current=self.store.file_identity(principal,path,maximum_bytes=maximum);now=time.monotonic();size_hint=current[2]
        with self.lock:
            if self.closed:raise Denied('Snapshot cache closed')
            for old,item in list(self.entries.items()):
                if not item['users'] and now-item['last']>self.ttl:self._drop(old)
            item=self.entries.get(key)
            if item and item['identity']==current:
                return self._lease(key,item),item['size'],item['manifest'],current
            if item:
                if item['users']:raise Conflict('Previous snapshot is still in use')
                self._drop(key)
            while self.bytes+self.reserved+size_hint>self.maximum_bytes or len(self.entries)+self.inflight>=self.maximum_entries:
                idle=next((k for k,v in self.entries.items() if not v['users']),None)
                if idle is None:raise Denied('Snapshot cache capacity exceeded')
                self._drop(idle)
            # Reservations are included even if their writes have already
            # consumed blocks; conservative double counting avoids overcommit.
            if self._free_bytes()<self.minimum_free_bytes+self.reserved+size_hint:raise Denied('Snapshot filesystem reserve reached')
            self.reserved+=size_hint;self.inflight+=1
        fd=None;snapshot=None
        try:
            fd,size,actual=self.store.open_read_snapshot(principal,path,maximum_bytes=maximum)
            before=identity(os.fstat(fd))
            if actual!=version or before!=current or size!=size_hint:raise Conflict('File version changed')
            snapshot=tempfile.TemporaryFile(mode='w+b',dir=self.temporary_directory);h=hashlib.sha256();offset=0
            while offset<size:
                part=os.pread(fd,min(65536,size-offset),offset)
                if not part:raise Denied('Snapshot truncated')
                snapshot.write(part);h.update(part);offset+=len(part)
            if h.hexdigest()!=version or identity(os.fstat(fd))!=before or self.store.file_identity(principal,path,maximum_bytes=maximum)!=before:raise Denied('File changed during snapshot')
            snapshot.flush();description=manifest(snapshot.fileno(),size,version)
            if self.store.file_identity(principal,path,maximum_bytes=maximum)!=before:raise Denied('File changed during snapshot')
            with self.lock:
                if self.closed:raise Denied('Snapshot cache closed')
                if self._free_bytes()<self.minimum_free_bytes:raise Denied('Snapshot filesystem reserve reached')
                item=self.entries.get(key)
                if item:
                    if item['identity']!=before:raise Conflict('File version changed')
                    return self._lease(key,item),size,item['manifest'],before
                item={'file':snapshot,'size':size,'manifest':description,'identity':before,'last':time.monotonic(),'users':0}
                # Duplicate first, so an OS descriptor failure cannot strand a cache entry.
                duplicate=os.dup(snapshot.fileno())
                try:lease=SnapshotLease(self,key,item,duplicate)
                except BaseException:
                    os.close(duplicate);raise
                item['users']=1;self.entries[key]=item;self.bytes+=size;snapshot=None
                return lease,size,description,before
        finally:
            try:
                if fd is not None:os.close(fd)
            finally:
                try:
                    if snapshot is not None:snapshot.close()
                finally:
                    with self.lock:self.reserved-=size_hint;self.inflight-=1
