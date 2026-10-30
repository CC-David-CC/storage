"""Loopback personal-files RPC: proof before upload, bounded I/O and no public files.

Externally mounted under the configured prefix; the hosting proxy strips that
prefix, as for the issuer. Only the two exact logical routes are accepted here.
No private account/permission database, key or host path is ever a response.
"""
import asyncio
import base64
import hashlib
import re
import time
from pathlib import Path
from urllib.parse import urlsplit
from aiohttp import web
from .auth import MAX_REQUEST_BYTES, Gatekeeper, jose
from .policy import Denied, exact, parts
from .transfers import Pacer, Quotas, AllowanceExceeded
from .user_store import Conflict

MAX_FILE_BYTES=8*1024*1024

async def offload(function,*args,**kwargs):
    # Keep the admission slot until the actual disk/SQLite work finishes, even
    # if a client cancels; cancellation cannot create unbounded orphan workers.
    task=asyncio.create_task(asyncio.to_thread(function,*args,**kwargs))
    try:return await asyncio.shield(task)
    except asyncio.CancelledError:
        try:await task
        finally:raise

class FileGateway:
    def __init__(self, store, issuer_policy, *, base_path='', quotas=None, pacer=None, seconds_per_use=120, idle_seconds=5):
        self.store=store;self.gate=Gatekeeper(store,issuer_policy,base_path=base_path,clock=store.clock)
        self.host=urlsplit(self.gate.origin).netloc;self.quotas=quotas or Quotas(store);self.pacer=pacer or Pacer()
        if type(seconds_per_use) is not int or not 1<=seconds_per_use<=120 or not 0<idle_seconds<=10:
            raise ValueError('Bounded transfer lifetime and idle timeout required')
        self.seconds=seconds_per_use;self.idle=idle_seconds;self.active=0
        self.window=0;self.requests=0
        self.client_source=Path(__file__).with_name('client.mjs').read_bytes()

    def app(self):
        app=web.Application(client_max_size=MAX_REQUEST_BYTES,handler_args={'keepalive_timeout':5,'lingering_time':0,'max_line_size':8190,'max_field_size':8190,'max_headers':32,'read_bufsize':65536,'auto_decompress':False})
        app.router.add_route('*','/{tail:.*}',self.handle)
        return app

    def _headers(self, request):
        if request.raw_path not in ('/gateway/challenge','/gateway/use'):
            raise web.HTTPNotFound()
        for name in ['Host','Origin','Content-Type','Content-Length']:
            if len(request.headers.getall(name,[]))!=1:raise Denied('Unique request headers required')
        if request.headers['Host']!=self.host or request.headers['Origin']!=self.gate.origin:
            raise web.HTTPForbidden(text='Unexpected gateway origin')
        if request.method!='POST':raise web.HTTPMethodNotAllowed(request.method,['POST'])
        if request.content_type!='application/json' or request.charset not in (None,'utf-8') or request.headers.get('Content-Encoding') or request.headers.get('Transfer-Encoding'):
            raise Denied('Plain UTF-8 JSON with an explicit size required')
        if request.content_length is None or not 0<request.content_length<=MAX_REQUEST_BYTES:
            raise web.HTTPRequestEntityTooLarge(max_size=MAX_REQUEST_BYTES,actual_size=request.content_length or 0)
        now=int(time.monotonic())//60
        if now!=self.window:self.window=now;self.requests=0
        self.requests+=1
        if self.requests>256 or self.active>=4:raise web.HTTPTooManyRequests(text='Gateway request capacity reached')

    async def _read(self, request, *, principal=None, deadline):
        chunks=[];total=0
        while total<request.content_length:
            async with asyncio.timeout(min(self.idle,max(.001,deadline-time.monotonic()))):
                chunk=await request.content.read(min(self.pacer.burst if principal else 65536,request.content_length-total))
            if not chunk:raise Denied('Truncated gateway request')
            if principal:await self.pacer.wait(principal.sub,len(chunk),deadline)
            chunks.append(chunk);total+=len(chunk)
        return b''.join(chunks)

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
            result=self.store.read(principal,path,maximum_bytes=min(MAX_FILE_BYTES,self.store.per_user_bytes))
            if operation=='version':return {'bytes':len(result['bytes']),'sha256':result['sha256']}
            return {'data':base64.b64encode(result['bytes']).decode('ascii'),'bytes':len(result['bytes']),'sha256':result['sha256']}
        if operation in ('create','replace'):
            text=request['data']
            if not isinstance(text,str) or len(text)>((MAX_FILE_BYTES+2)//3)*4:raise Denied('File size limit exceeded')
            data=base64.b64decode(text,validate=True)
            if len(data)>MAX_FILE_BYTES or base64.b64encode(data).decode('ascii')!=text:raise Denied('Canonical bounded file encoding required')
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
        admitted=False;transfer=None;response=None
        try:
            if request.method=='GET' and request.raw_path in ('/gateway/client.mjs','/gateway/capabilities','/healthz'):
                if request.headers.get('Host')!=self.host:raise web.HTTPForbidden()
                if request.raw_path=='/healthz':return self._response({'status':'ok','scope':'personal-files'})
                if request.raw_path=='/gateway/capabilities':return self._response({'version':'codi-file-capabilities/1','fileVersion':True})
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
                raw=await self._read(request,principal=principal,deadline=deadline)
                data=use.decode(raw)
                result=await offload(self._dispatch,principal,data)
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
            if transfer:await offload(self.quotas.finish,transfer)
            if admitted:self.active-=1
