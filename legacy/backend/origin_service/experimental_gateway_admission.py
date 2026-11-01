"""Experimental issuer-side gateway admission; not wired into live services.

An admission ticket is not a file permission. It only lets a future gateway
choose a verified account budget before issuing its own one-use challenge.
"""
import secrets
from urllib.parse import urlsplit
from codiauth import jose
from codiauth.service import Failure
from origin_service.gateway_authority import GatewayAuthority

ADMISSION='/api/v1/gateway/admission'
CHALLENGE=ADMISSION+'/challenge'
CAPABILITIES=ADMISSION+'/capabilities'
TICKET_TYPE='codi-gateway-admission+jwt'

class AdmissionAuthority:
    def __init__(self, issuer, application=None, *, seconds=20, per_minute=120, global_per_minute=2048):
        for value in (seconds,per_minute,global_per_minute):
            if type(value) is not int or value<1:raise ValueError('Positive integer admission limits required')
        if seconds>30 or per_minute>100000 or global_per_minute>100000:raise ValueError('Bounded admission limits required')
        self.issuer=issuer;self.legacy=GatewayAuthority(issuer,application);self.seconds=seconds;self.per_minute=per_minute;self.global_per_minute=global_per_minute

    def _session(self, authorization):
        subject=self.legacy.session_bucket(authorization)
        if not subject:
            self.issuer.throttle('admission-unverified',limit=128)
            raise Failure(401,'Registered session required')
        return subject

    def _nonce(self, data, authorization, subject):
        issuer=self.issuer
        if not isinstance(data,dict) or set(data)!={'key','path'} or data['path']!=issuer.base_path+ADMISSION:raise Failure(400,'Invalid admission challenge')
        key=jose.public_jwk(jose.load_public(data['key']))
        with issuer.lock:
            issuer.cleanup();session=issuer.sessions.get(jose.digest(authorization[5:]))
            if not session or session.get('sub')!=subject or jose.thumbprint(session['key'])!=jose.thumbprint(key):raise Failure(401,'Invalid session binding')
            if len(issuer.challenges)>=issuer.c.max_challenges:raise Failure(429,'Challenge capacity reached')
            nonce=secrets.token_urlsafe(32);issuer.challenges[nonce]={'key':key,'path':issuer.base_path+ADMISSION,'expires':issuer.now()+60}
        return {'nonce':nonce,'expires_at':issuer.now()+60}

    def _issue(self, data, key, proof, authorization, subject):
        if data!={'resource':'my-files','purpose':'gateway-challenge'}:raise Failure(400,'Invalid admission request')
        issuer=self.issuer
        with issuer.lock:
            # Reuse the persisted-session, revoked-account, key/SID, deadline
            # and account-generation checks used by ordinary renewals.
            checked=issuer.continue_session({},key,proof,'/api/v1/renew',authorization);identity=checked['identity']
            if identity['kind']!='registered' or identity['sub']!=subject:raise Failure(401,'Registered session required')
            now=issuer.now();expiry=min(now+self.seconds,checked['expires_at'])
            if expiry<=now:raise Failure(401,'Session expired')
            claims={'v':1,'iss':issuer.c.origin,'aud':issuer.c.origin+issuer.base_path+'/gateway','sub':identity['sub'],'sid':identity['sid'],'cnf':{'jwk':identity['key']},'scope':'gateway-challenge','iat':now,'exp':expiry,'jti':secrets.token_urlsafe(32)}
            return {'ticket':jose.sign(claims,issuer.key,TICKET_TYPE,issuer.kid),'expires_at':expiry}

    def __call__(self, env, start):
        path=env.get('PATH_INFO','/')
        if path not in (ADMISSION,CHALLENGE,CAPABILITIES):return self.legacy(env,start)
        issuer=self.issuer
        try:
            if env.get('HTTP_HOST')!=urlsplit(issuer.c.origin).netloc:raise Failure(403,'Unexpected admission host')
            if path==CAPABILITIES:
                if env.get('REQUEST_METHOD')!='GET':raise Failure(405,'GET required')
                if env.get('HTTP_ORIGIN') not in (None,issuer.c.origin):raise Failure(403,'Unexpected admission origin')
                return issuer.json_response(start,200,{'version':'codi-gateway-admission/2'})
            if env.get('HTTP_ORIGIN')!=issuer.c.origin:raise Failure(403,'Unexpected admission origin')
            if env.get('REQUEST_METHOD')!='POST':raise Failure(405,'POST required')
            if env.get('CONTENT_TYPE','').split(';')[0].strip()!='application/json' or env.get('HTTP_TRANSFER_ENCODING'):raise Failure(400,'Bounded JSON required')
            length=env.get('CONTENT_LENGTH','')
            if not length.isascii() or not length.isdecimal() or len(length)>5 or not 0<int(length)<=16384:raise Failure(413,'Bounded admission request required')
            authorization=env.get('HTTP_AUTHORIZATION','');subject=self._session(authorization)
            phase='challenge' if path==CHALLENGE else 'issue'
            issuer.throttle('admission-'+phase+'-account:'+subject,limit=self.per_minute);issuer.throttle('admission-global',limit=self.global_per_minute)
            raw=env['wsgi.input'].read(int(length))
            if len(raw)!=int(length):raise Failure(400,'Truncated request')
            envelope=jose.loads(raw)
            if path==CHALLENGE:result=self._nonce(envelope,authorization,subject)
            else:
                data,key,proof=issuer.consume_proof(envelope,ADMISSION)
                result=self._issue(data,key,proof,authorization,subject)
            return issuer.json_response(start,200,result)
        except Failure as error:return issuer.json_response(start,error.status,{'error':error.message})
        except (ValueError,TypeError,KeyError,UnicodeError):return issuer.json_response(start,400,{'error':'Invalid gateway admission request'})
        except Exception:return issuer.json_response(start,500,{'error':'Gateway admission unavailable'})
