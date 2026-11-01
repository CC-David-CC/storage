"""Unwired gateway admission experiment. NOT a deployable security boundary.

It partitions signed, legacy and invalid traffic after a bounded verification
step. Verification capacity itself remains shared and can be saturated. A fresh
process epoch invalidates outstanding challenge proofs on restart; replay state
within an epoch remains bounded and in memory.
"""
import asyncio,contextvars,secrets,threading,time
from aiohttp import web
from .http import FileGateway,MAX_REQUEST_BYTES,offload
from .auth import jose,digest,window
from .policy import Denied,Principal
from .user_store import registered

TICKET_TYPE='codi-gateway-admission+jwt'
PROOF_TYPE='codi-gateway-admission-proof+jws'
_preverified=contextvars.ContextVar('codi_experimental_gateway_use',default=None)

class Shares:
    """Separate bounded fixed-window counters; no account eviction within a window."""
    def __init__(self,*,verified=1536,legacy=256,invalid=256,per_account=240,max_accounts=4096,max_proofs=4096,clock=time.monotonic,wall=time.time):
        for value in (verified,legacy,invalid,per_account,max_accounts,max_proofs):
            if type(value) is not int or value<1 or value>100000:raise ValueError('Bounded admission shares required')
        if verified+legacy+invalid>100000 or max_accounts>16384 or max_proofs>16384:raise ValueError('Admission capacity exceeded')
        self.limits={'verified':verified,'legacy':legacy,'invalid':invalid};self.per_account=per_account;self.max_accounts=max_accounts;self.max_proofs=max_proofs;self.clock=clock;self.wall=wall;self.lock=threading.Lock();self.window=None;self.counts={};self.accounts={};self.proofs={}
    def take(self,kind,subject=None,proof=None,expiry=None):
        with self.lock:
            tick=int(self.clock())//60;now=int(self.wall())
            if tick!=self.window:self.window=tick;self.counts.clear();self.accounts.clear()
            self.proofs={key:end for key,end in self.proofs.items() if end>now}
            if kind not in self.limits:raise ValueError('Unknown admission lane')
            if self.counts.get(kind,0)>=self.limits[kind]:raise web.HTTPTooManyRequests(text='Gateway admission share exhausted')
            if kind=='verified':
                if not subject:raise ValueError('Verified subject required')
                if subject not in self.accounts and len(self.accounts)>=self.max_accounts:raise web.HTTPTooManyRequests(text='Gateway account table full')
                if self.accounts.get(subject,0)>=self.per_account:raise web.HTTPTooManyRequests(text='Account admission share exhausted')
                if proof is not None:
                    if proof in self.proofs:raise web.HTTPUnauthorized(text='Admission proof already used')
                    if len(self.proofs)>=self.max_proofs:raise web.HTTPTooManyRequests(text='Gateway proof table full')
                    if type(expiry) is not int or expiry<=now:raise web.HTTPUnauthorized(text='Expired admission proof')
                    self.proofs[proof]=expiry
                self.accounts[subject]=self.accounts.get(subject,0)+1
            self.counts[kind]=self.counts.get(kind,0)+1

class ExperimentalFileGateway(FileGateway):
    def __init__(self,*args,shares=None,verification_slots=2,verification_waiters=32,**kwargs):
        super().__init__(*args,**kwargs)
        # Never persist or share this process instance's epoch. A proof signed
        # for an earlier process cannot be reused after a restart.
        self.admission_epoch=secrets.token_urlsafe(32)
        if type(verification_slots) is not int or not 1<=verification_slots<=4 or type(verification_waiters) is not int or not 1<=verification_waiters<=128:raise ValueError('Bounded verification queue required')
        self.shares=shares or Shares();self.verification_slots=asyncio.Semaphore(verification_slots);self.verification_waiters=verification_waiters;self.verification_waiting=0
        if sum(self.shares.limits.values())>self.max_requests_per_minute:raise ValueError('Admission shares exceed shared limit')
        self._real_begin=self.gate.begin
        def already_verified(confirmation,proof,*,seconds=900):
            item=_preverified.get()
            if item is None or item[0]!=confirmation or item[1]!=proof:raise Denied('Verified request context required')
            return item[2]
        self.gate.begin=already_verified
    def _headers(self,request):
        # Same structural checks as FileGateway; shares are charged by handle.
        if request.raw_path not in ('/gateway/challenge','/gateway/challenge-v2','/gateway/use','/gateway/upload'):raise web.HTTPNotFound()
        for name in ['Host','Origin','Content-Type','Content-Length']:
            if len(request.headers.getall(name,[]))!=1:raise Denied('Unique request headers required')
        if request.headers['Host']!=self.host or request.headers['Origin']!=self.gate.origin:raise web.HTTPForbidden(text='Unexpected gateway origin')
        if request.method!='POST':raise web.HTTPMethodNotAllowed(request.method,['POST'])
        expected='application/octet-stream' if request.raw_path=='/gateway/upload' else 'application/json'
        if request.content_type!=expected or request.charset not in (None,'utf-8') or request.headers.get('Content-Encoding') or request.headers.get('Transfer-Encoding'):raise Denied('Supported content type and explicit size required')
        if request.content_length is None or not 0<request.content_length<=MAX_REQUEST_BYTES:raise web.HTTPRequestEntityTooLarge(max_size=MAX_REQUEST_BYTES,actual_size=request.content_length or 0)
    async def _acquire_verification(self):
        if self.verification_waiting>=self.verification_waiters:raise web.HTTPTooManyRequests(text='Gateway verification queue full')
        self.verification_waiting+=1
        try:
            try:
                async with asyncio.timeout(5):await self.verification_slots.acquire()
            except TimeoutError:raise web.HTTPTooManyRequests(text='Gateway verification queue timed out') from None
        finally:self.verification_waiting-=1
    async def _verify_slot(self,fn,*args):
        await self._acquire_verification()
        try:return await offload(fn,*args)
        finally:self.verification_slots.release()
    async def _ticket_request(self,request):
        await self._acquire_verification()
        try:
            data=jose.loads(await self._read(request,deadline=time.monotonic()+self.idle))
            return await offload(self._ticket,data)
        finally:self.verification_slots.release()
    def _ticket(self,data):
        if not isinstance(data,dict) or set(data)!={'ticket','proof','request_sha256'}:raise Denied('Invalid admission envelope')
        request_sha=digest(data['request_sha256']);header,_,_,_=jose.inspect(data['ticket'],TICKET_TYPE,8192);authority=self.gate.keys.get(header.get('kid'))
        if not authority:raise Denied('Untrusted admission authority')
        c=jose.verify(data['ticket'],authority,TICKET_TYPE,8192);now=int(self.gate.clock());window(c,now)
        if set(c)!={'v','iss','aud','sub','sid','cnf','scope','iat','exp','jti'} or type(c['v']) is not int or c['v']!=1 or c['iss']!=self.gate.origin or c['aud']!=self.gate.audience or c['scope']!='gateway-challenge' or c['exp']-c['iat']>20 or not isinstance(c['sid'],str) or not 1<=len(c['sid'])<=80:raise Denied('Wrong admission context')
        if not isinstance(c['cnf'],dict) or set(c['cnf'])!={'jwk'}:raise Denied('Invalid admission key')
        key=jose.public_jwk(jose.load_public(c['cnf']['jwk']));registered(Principal(c['sub'],c['sid'],'registered',key,c['exp']));digest(c['jti'])
        p=jose.verify(data['proof'],key,PROOF_TYPE,8192);window(p,now)
        if set(p)!={'v','iss','aud','method','path','iat','exp','jti','ticket_sha256','request_sha256','epoch'} or type(p['v']) is not int or p['v']!=1 or p['iss']!=c['sid'] or p['aud']!=self.gate.audience or p['method']!='POST' or p['path']!=self.gate.use_path.removesuffix('/use')+'/challenge-v2' or p['ticket_sha256']!=jose.digest(data['ticket']) or p['request_sha256']!=request_sha or p['epoch']!=self.admission_epoch:raise Denied('Wrong admission proof context')
        digest(p['jti']);return c['sub'],key,request_sha,jose.digest(data['ticket'])+':'+p['jti'],min(c['exp'],p['exp'])
    async def handle(self,request):
        if request.raw_path=='/gateway/admission-capabilities' and request.method=='GET':
            if request.headers.get('Host')!=self.host:return self._response({'error':'Unexpected host'},403)
            return self._response({'version':'codi-gateway-admission/2','epoch':self.admission_epoch})
        if request.raw_path not in ('/gateway/challenge','/gateway/challenge-v2','/gateway/use','/gateway/upload'):return await super().handle(request)
        token=None
        try:
            self._headers(request)
            if request.raw_path=='/gateway/challenge':
                self.shares.take('legacy');return await super().handle(request)
            if request.raw_path=='/gateway/challenge-v2':
                if request.content_length>16384:self.shares.take('invalid');raise Denied('Bounded challenge required')
                try:subject,key,request_sha,proof_id,expires=await self._ticket_request(request)
                except (ValueError,TypeError,KeyError):self.shares.take('invalid');raise web.HTTPUnauthorized(text='Invalid admission ticket or proof') from None
                self.shares.take('verified',subject,proof_id,expires)
                await self._admit()
                try:result=await offload(self.gate.challenge,key,request_sha)
                finally:self.active-=1;self.slots.release()
                return self._response(result)
            fields=request.headers.getall('Authorization',[]);parts=fields[0].split(' ') if len(fields)==1 else []
            if len(parts)!=3 or parts[0]!='Codi-File':self.shares.take('invalid');raise web.HTTPUnauthorized(text='Gateway identity proof required')
            try:use=await self._verify_slot(lambda:self._real_begin(parts[1],parts[2],seconds=self.seconds))
            except (ValueError,TypeError,KeyError):self.shares.take('invalid');raise web.HTTPUnauthorized(text='Invalid, expired or already used gateway identity') from None
            self.shares.take('verified',use.principal.sub);token=_preverified.set((parts[1],parts[2],use))
            return await super().handle(request)
        except Exception as error:
            if isinstance(error,web.HTTPException):status,message=error.status,error.text
            elif isinstance(error,(ValueError,TypeError,KeyError,UnicodeError)):status,message=403,'Invalid gateway request'
            else:status,message=500,'Gateway request unavailable'
            return self._response({'error':message},status)
        finally:
            if token is not None:_preverified.reset(token)
