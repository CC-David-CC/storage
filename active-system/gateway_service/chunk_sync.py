"""Research-only versioned, file-scoped chunk reader for signed gateway RPC.

No on-server chunk cache: manifests are derived from the authorized flat file.
"""
import base64,hashlib,os,re
from .policy import Denied

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
