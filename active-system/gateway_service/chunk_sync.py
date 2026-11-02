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

class SnapshotCache:
    def __init__(self,store,maximum_bytes=512*1024*1024,ttl=60):
        self.store=store;self.maximum_bytes=maximum_bytes;self.ttl=ttl;self.lock=threading.Lock();self.entries=OrderedDict();self.bytes=0
    def _drop(self,key):
        item=self.entries.pop(key);self.bytes-=item['size'];item['file'].close()
    def close(self):
        with self.lock:
            for key in list(self.entries):self._drop(key)
    def open(self,principal,path,version,maximum):
        key=(principal.sub,path,version);current=self.store.file_identity(principal,path,maximum_bytes=maximum);now=time.monotonic()
        with self.lock:
            for old,item in list(self.entries.items()):
                if now-item['last']>self.ttl:self._drop(old)
            item=self.entries.get(key)
            if item and item['identity']==current:
                item['last']=now;self.entries.move_to_end(key);return os.dup(item['file'].fileno()),item['size'],item['manifest'],current
            if item:self._drop(key)
        fd,size,actual=self.store.open_read_snapshot(principal,path,maximum_bytes=maximum)
        snapshot=None
        try:
            before=identity(os.fstat(fd))
            if actual!=version or before!=current:raise Conflict('File version changed')
            snapshot=tempfile.TemporaryFile(mode='w+b');h=hashlib.sha256();offset=0
            while offset<size:
                part=os.pread(fd,min(65536,size-offset),offset)
                if not part:raise Denied('Snapshot truncated')
                snapshot.write(part);h.update(part);offset+=len(part)
            if h.hexdigest()!=version or identity(os.fstat(fd))!=before or self.store.file_identity(principal,path,maximum_bytes=maximum)!=before:raise Denied('File changed during snapshot')
            snapshot.flush();description=manifest(snapshot.fileno(),size,version)
            if self.store.file_identity(principal,path,maximum_bytes=maximum)!=before:raise Denied('File changed during snapshot')
            with self.lock:
                if key in self.entries:self._drop(key)
                while self.entries and self.bytes+size>self.maximum_bytes:self._drop(next(iter(self.entries)))
                if size>self.maximum_bytes:raise Denied('Snapshot cache capacity exceeded')
                self.entries[key]={'file':snapshot,'size':size,'manifest':description,'identity':before,'last':time.monotonic()};self.bytes+=size
                dup=os.dup(snapshot.fileno());snapshot=None
            return dup,size,description,before
        finally:
            os.close(fd)
            if snapshot is not None:snapshot.close()
