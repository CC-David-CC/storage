"""Bounded rolling-checksum delta protocol, scoped by the caller's open file.

Weak checksums are matching hints only. The final reconstructed SHA-256 and
atomic previous-version comparison remain the security boundary.
"""
import hashlib
import os
import struct
import zlib
from .policy import Denied

BLOCK = 64 * 1024
MAX_FILE = 128 * 1024 * 1024
MAX_OPS = 8192


def signatures(fd, size, sha256):
    if type(size) is not int or not 0 <= size <= MAX_FILE:
        raise Denied('Invalid base file size')
    chunks=[]
    for offset in range(0, size - BLOCK + 1, BLOCK):
        data=os.pread(fd, BLOCK, offset)
        if len(data)!=BLOCK:raise Denied('Base snapshot truncated')
        chunks.append([zlib.adler32(data) & 0xffffffff, hashlib.sha256(data).hexdigest()])
    return {'version':'codi-file-delta/1','size':size,'sha256':sha256,'block':BLOCK,'chunks':chunks}


def apply_patch(base_fd, base_size, patch, patch_size, output, output_size, output_sha256):
    if any(type(n) is not int or n<0 or n>MAX_FILE for n in (base_size,patch_size,output_size)):
        raise Denied('Invalid delta bounds')
    consumed=produced=operations=0
    digest=hashlib.sha256()
    def read(n):
        nonlocal consumed
        if n>patch_size-consumed:raise Denied('Truncated delta')
        value=patch.read(n);consumed+=len(value)
        if len(value)!=n:raise Denied('Truncated delta')
        return value
    def emit(data):
        nonlocal produced
        produced+=len(data)
        if produced>output_size:raise Denied('Delta output exceeds size')
        digest.update(data);output.write(data)
    while consumed<patch_size:
        operations+=1
        if operations>MAX_OPS:raise Denied('Too many delta operations')
        opcode=read(1)
        if opcode==b'C':
            offset,length=struct.unpack('>II',read(8))
            if not length or offset>base_size or length>base_size-offset:raise Denied('Invalid delta copy')
            while length:
                data=os.pread(base_fd,min(BLOCK,length),offset)
                if not data:raise Denied('Base snapshot truncated')
                emit(data);offset+=len(data);length-=len(data)
        elif opcode==b'I':
            length=struct.unpack('>I',read(4))[0]
            if not length or length>output_size-produced:raise Denied('Invalid delta literal')
            while length:
                part=read(min(BLOCK,length));emit(part);length-=len(part)
        else:raise Denied('Invalid delta opcode')
    if produced!=output_size or digest.hexdigest()!=output_sha256:raise Denied('Delta result does not match declared size and hash')
    if patch.read(1):raise Denied('Unexpected trailing delta data')
    output.seek(0)
