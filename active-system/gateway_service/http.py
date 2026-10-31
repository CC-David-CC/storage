"""Loopback personal-files RPC: proof before upload, bounded I/O and no public files.

Externally mounted under the configured prefix; the hosting proxy strips that
prefix, as for the issuer. Only the two exact logical routes are accepted here.
No private account/permission database, key or host path is ever a response.
"""
import asyncio
import base64
import hashlib
import io
import os
import re
import struct
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit
from aiohttp import web
from .auth import MAX_REQUEST_BYTES, Gatekeeper, jose
from .policy import Denied, exact, parts
from .transfers import Pacer, Quotas, AllowanceExceeded
from .user_store import Conflict

MAX_FILE_BYTES=128*1024*1024

@dataclass(frozen=True)
class ReadResponse:
    fd: int
    size: int
    sha256: str

async def offload(function,*args,**kwargs):
    # Keep the admission slot until the actual disk/SQLite work finishes, even
    # if a client cancels; cancellation cannot create unbounded orphan workers.
    task=asyncio.create_task(asyncio.to_thread(function,*args,**kwargs))
    try:return await asyncio.shield(task)
    except asyncio.CancelledError:
        try:
            result=await task
            if isinstance(result,ReadResponse):os.close(result.fd)
        finally:raise

class FileGateway:
    def __init__(self, store, issuer_policy, *, base_path='', quotas=None, pacer=None, seconds_per_use=900, idle_seconds=5, upload_idle_seconds=60, max_requests_per_minute=256):
        self.store=store;self.gate=Gatekeeper(store,issuer_policy,base_path=base_path,clock=store.clock)
        self.host=urlsplit(self.gate.origin).netloc;self.quotas=quotas or Quotas(store);self.pacer=pacer or Pacer()
        if type(seconds_per_use) is not int or not 1<=seconds_per_use<=900 or not 0<idle_seconds<=10 or not 0<upload_idle_seconds<=120:
            raise ValueError('Bounded transfer lifetime and idle timeout required')
        if type(max_requests_per_minute) is not int or not 1<=max_requests_per_minute<=100000:raise ValueError('Bounded request limit required')
        self.max_requests_per_minute=max_requests_per_minute
        self.seconds=seconds_per_use;self.idle=idle_seconds;self.upload_idle=upload_idle_seconds;self.active=0
        self.window=0;self.requests=0
        self.client_source=Path(__file__).with_name('client.mjs').read_bytes()

    def app(self):
        app=web.Application(client_max_size=MAX_REQUEST_BYTES,handler_args={'keepalive_timeout':5,'lingering_time':0,'max_line_size':8190,'max_field_size':8190,'max_headers':32,'read_bufsize':65536,'auto_decompress':False})
        app.router.add_route('*','/{tail:.*}',self.handle)
        return app

    def _headers(self, request):
        if request.raw_path not in ('/gateway/challenge','/gateway/use','/gateway/upload'):
            raise web.HTTPNotFound()
        for name in ['Host','Origin','Content-Type','Content-Length']:
            if len(request.headers.getall(name,[]))!=1:raise Denied('Unique request headers required')
        if request.headers['Host']!=self.host or request.headers['Origin']!=self.gate.origin:
            raise web.HTTPForbidden(text='Unexpected gateway origin')
        if request.method!='POST':raise web.HTTPMethodNotAllowed(request.method,['POST'])
        expected='application/octet-stream' if request.raw_path=='/gateway/upload' else 'application/json'
        if request.content_type!=expected or request.charset not in (None,'utf-8') or request.headers.get('Content-Encoding') or request.headers.get('Transfer-Encoding'):
            raise Denied('Supported content type and explicit size required')
        if request.content_length is None or not 0<request.content_length<=MAX_REQUEST_BYTES:
            raise web.HTTPRequestEntityTooLarge(max_size=MAX_REQUEST_BYTES,actual_size=request.content_length or 0)
        now=int(time.monotonic())//60
        if now!=self.window:self.window=now;self.requests=0
        self.requests+=1
        if self.requests>self.max_requests_per_minute or self.active>=4:raise web.HTTPTooManyRequests(text='Gateway request capacity reached')

    async def _read(self, request, *, principal=None, deadline, length=None, idle=None):
        chunks=io.BytesIO();total=0
        length=request.content_length if length is None else length
        while total<length:
            async with asyncio.timeout(min(self.idle if idle is None else idle,max(.001,deadline-time.monotonic()))):
                chunk=await request.content.read(min(self.pacer.burst if principal else 65536,length-total))
            if not chunk:raise Denied('Truncated gateway request')
            if principal:await self.pacer.wait(principal.sub,len(chunk),deadline)
            chunks.write(chunk);total+=len(chunk)
        return chunks.getvalue()

    async def _upload(self,request,use,principal,deadline):
        prefix=await self._read(request,principal=principal,deadline=deadline,length=4,idle=self.upload_idle)
        length=struct.unpack('>I',prefix)[0]
        if not 1<=length<=8192 or 4+length>request.content_length:raise Denied('Bounded upload metadata required')
        raw=await self._read(request,principal=principal,deadline=deadline,length=length,idle=self.upload_idle)
        metadata=use.decode(raw)
        operation=metadata.get('operation')
        exact(metadata,['resource','operation','path','format','size','sha256']+(['previousSHA256'] if operation=='replace' else []))
        if metadata['resource']!='my-files' or metadata['format']!='codi-binary-upload/1' or operation not in ('create','replace'):
            raise Denied('Unsupported binary upload')
        size=metadata['size'];digest=metadata['sha256']
        if type(size) is not int or not 0<=size<=MAX_FILE_BYTES or 4+length+size!=request.content_length:
            raise Denied('Upload size changed')
        if not isinstance(digest,str) or not re.fullmatch('[0-9a-f]{64}',digest):raise Denied('Upload hash required')
        path='/'.join(parts(metadata['path']))
        if not path:raise Denied('File path required')
        with tempfile.TemporaryFile(mode='w+b') as temporary:
            seen=0;hasher=hashlib.sha256()
            while seen<size:
                async with asyncio.timeout(min(self.upload_idle,max(.001,deadline-time.monotonic()))):
                    chunk=await request.content.read(min(self.pacer.burst,size-seen))
                if not chunk:raise Denied('Truncated upload')
                await self.pacer.wait(principal.sub,len(chunk),deadline)
                hasher.update(chunk);seen+=len(chunk)
                await offload(temporary.write,chunk)
            if hasher.hexdigest()!=digest:raise Denied('Upload hash changed')
            await offload(temporary.seek,0)
            return await offload(self.store.put_stream,principal,path,temporary,size,digest,previous_sha256=metadata.get('previousSHA256'))

    def _dispatch(self, principal, request):
        operation=request.get('operation')
        common=['resource','operation','path']
        extras={'create':['data'],'replace':['data','previousSHA256'],'delete':['previousSHA256'],'rename':['destination','previousSHA256'],'word-count':['previousSHA256']}
        if operation not in ('list','read','version','mkdir','create','replace','delete','rename','word-count'):raise Denied('File operation not permitted')
        exact(request,common+extras.get(operation,[]))
        if request['resource']!='my-files':raise Denied('Personal file resource required')
        path='/'.join(parts(request['path']))
        if operation!='list' and not path:raise Denied('File path required')
        if 'previousSHA256' in request:
            version=request['previousSHA256']
            if not (operation=='delete' and version is None) and (not isinstance(version,str) or not re.fullmatch('[0-9a-f]{64}',version)):
                raise Denied('Exact previous content hash required')
        if operation=='word-count':return self.store.word_count(principal,path,request['previousSHA256'])
        if operation=='list':return {'entries':self.store.list(principal,path)}
        if operation in ('read','version'):
            fd,size,sha256=self.store.open_read_snapshot(principal,path,maximum_bytes=min(MAX_FILE_BYTES,self.store.per_user_bytes))
            if operation=='version':
                os.close(fd);return {'bytes':size,'sha256':sha256}
            return ReadResponse(fd,size,sha256)
        if operation in ('create','replace'):
            text=request['data']
            if not isinstance(text,str) or len(text)>((MAX_FILE_BYTES+2)//3)*4:raise Denied('File size limit exceeded')
            data=base64.b64decode(text,validate=True)
            # validate=True checks the alphabet and padding placement. Recheck
            # only the last quartet to reject noncanonical unused pad bits,
            # avoiding another full-size base64 copy of a large upload.
            if len(data)>MAX_FILE_BYTES or (text and base64.b64encode(data[-(len(data)%3 or 3):]).decode('ascii')!=text[-4:]):raise Denied('Canonical bounded file encoding required')
            return self.store.put(principal,path,data,previous_sha256=request.get('previousSHA256'))
        if operation=='mkdir':self.store.mkdir(principal,path)
        elif operation=='delete':self.store.delete(principal,path,previous_sha256=request['previousSHA256'])
        else:
            destination='/'.join(parts(request['destination']))
            self.store.rename(principal,path,destination,previous_sha256=request['previousSHA256'])
        return {'ok':True}

    @staticmethod
    def _response(value,status=200):
        response=web.Response(body=jose.dumps(value).encode(),status=status,content_type='application/json',headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'})
        if status!=200:response.force_close()
        return response

    async def handle(self, request):
        admitted=False;transfer=None;response=None;read_fd=None
        try:
            if request.method=='GET' and request.raw_path in ('/gateway/client.mjs','/gateway/capabilities','/gateway/upload-capabilities','/healthz'):
                if request.headers.get('Host')!=self.host:raise web.HTTPForbidden()
                if request.raw_path=='/healthz':return self._response({'status':'ok','scope':'personal-files'})
                if request.raw_path=='/gateway/capabilities':return self._response({'version':'codi-file-capabilities/1','fileVersion':True})
                if request.raw_path=='/gateway/upload-capabilities':return self._response({'version':'codi-binary-upload/1','maxBytes':MAX_FILE_BYTES})
                return web.Response(body=self.client_source,content_type='text/javascript',headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
            self._headers(request);self.active+=1;admitted=True
            if request.path=='/gateway/challenge':
                if request.content_length>16384:raise Denied('Bounded challenge required')
                data=jose.loads(await self._read(request,deadline=time.monotonic()+self.idle))
                exact(data,['key','request_sha256'])
                result=await offload(self.gate.challenge,data['key'],data['request_sha256'])
                return self._response(result)
            # Keep both one-use proofs in the standard sensitive header, which
            # hosting access logs redact. Do not introduce unredacted headers.
            authorization=request.headers.getall('Authorization',[])
            fields=authorization[0].split(' ') if len(authorization)==1 else []
            if len(fields)!=3 or fields[0]!='Codi-File':raise web.HTTPUnauthorized(text='Gateway identity proof required')
            try:
                use=await offload(self.gate.begin,fields[1],fields[2],seconds=self.seconds)
            except ValueError:raise web.HTTPUnauthorized(text='Invalid, expired or already used gateway identity') from None
            principal=use.principal
            await offload(self.store.ensure_user,principal)
            transfer=await offload(self.quotas.begin,principal,request.content_length+512)
            deadline=time.monotonic()+max(0,principal.deadline-self.store.clock())
            async with asyncio.timeout(max(.001,deadline-time.monotonic())):
                if request.raw_path=='/gateway/upload':
                    result=await self._upload(request,use,principal,deadline)
                else:
                    raw=await self._read(request,principal=principal,deadline=deadline)
                    data=use.decode(raw)
                    del raw
                    result=await offload(self._dispatch,principal,data)
                    del data
                if isinstance(result,ReadResponse):
                    # Encode directly to the response in bounded blocks. The old
                    # all-at-once encoding held multiple 170+ MiB copies of a
                    # 128 MiB file and exceeded the live service memory cap.
                    read_fd=result.fd
                    prefix=b'{"data":"'
                    suffix=b'",'+jose.dumps({'bytes':result.size,'sha256':result.sha256})[1:].encode()
                    length=len(prefix)+((result.size+2)//3)*4+len(suffix)
                    if length>MAX_REQUEST_BYTES:raise Denied('File response size limit exceeded')
                    await offload(self.quotas.extend,transfer,max(0,length-512))
                    response=web.StreamResponse(status=200,headers={'Content-Type':'application/json','Content-Length':str(length),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'})
                    await response.prepare(request)
                    async def send(chunk):
                        await self.pacer.wait(principal.sub,len(chunk),deadline);await response.write(chunk)
                    await send(prefix)
                    block=(self.pacer.burst//4)*3;remaining=result.size
                    def read_exact(fd,length):
                        chunks=[];got=0
                        while got<length:
                            part=os.read(fd,length-got)
                            if not part:raise Denied('File changed while streaming')
                            chunks.append(part);got+=len(part)
                        return b''.join(chunks)
                    while remaining:
                        length=min(block,remaining);raw=await offload(read_exact,read_fd,length)
                        await send(base64.b64encode(raw));remaining-=length
                    await send(suffix);await response.write_eof();return response
                output=jose.dumps(result).encode()
                if len(output)>MAX_REQUEST_BYTES:raise Denied('File response size limit exceeded')
                await offload(self.quotas.extend,transfer,max(0,len(output)-512))
                response=web.StreamResponse(status=200,headers={'Content-Type':'application/json','Content-Length':str(len(output)),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'})
                await response.prepare(request)
                for offset in range(0,len(output),self.pacer.burst):
                    chunk=output[offset:offset+self.pacer.burst];await self.pacer.wait(principal.sub,len(chunk),deadline);await response.write(chunk)
                await response.write_eof();return response
        except Exception as error:
            if response is not None and response.prepared:
                response.force_close()
                if request.transport:request.transport.close()
                return response
            if isinstance(error,web.HTTPException):status,message=error.status,error.text
            elif isinstance(error,FileNotFoundError):status,message=404,'File or folder not found'
            elif isinstance(error,(Conflict,FileExistsError)):status,message=409,'File changed or destination exists; reload before saving'
            elif isinstance(error,AllowanceExceeded):status,message=429,'Transfer allowance reached; try later'
            elif isinstance(error,TimeoutError):status,message=408,'File request timed out'
            elif isinstance(error,(Denied,ValueError,TypeError,KeyError,UnicodeError,OSError)):status,message=403,'File request refused; check permissions, path, version or allowance'
            else:status,message=503,'File service unavailable'
            return self._response({'error':message},status)
        finally:
            if read_fd is not None:os.close(read_fd)
            if transfer:await offload(self.quotas.finish,transfer)
            if admitted:self.active-=1
