/** Unwired admission client experiment; not a production fallback policy. */
import {UserFiles,FileRequestError} from './client.mjs';
import {hash,signJws,inspectJws,verifyJws,sameKey,validateTimes,nowSeconds,requireThat,b64} from '../network/crypto.mjs';
import {PROOF_TYPE} from '../network/identity.mjs';

const VERSION='codi-gateway-admission/2',TICKET='codi-gateway-admission+jwt',ADMISSION_PROOF='codi-gateway-admission-proof+jws';
const options={mode:'same-origin',credentials:'same-origin',redirect:'error',cache:'no-store',referrerPolicy:'no-referrer'};
async function bounded(response){
  const reader=response.body?.getReader();requireThat(reader,'Missing admission response');const parts=[];let size=0;
  try{while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;requireThat(size<=16384,'Admission response too large');parts.push(value)}}catch(e){await reader.cancel().catch(()=>{});throw e}
  const all=new Uint8Array(size);let offset=0;for(const part of parts){all.set(part,offset);offset+=part.length;}
  try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(all))}catch{throw Error('Invalid admission response')}
}
export class ExperimentalAdmissionFiles extends UserFiles{
  constructor(config,session,{allowExplicitLegacy=false,...opts}={}){super(config,session,opts);this.allowExplicitLegacy=allowExplicitLegacy;}
  async capability(path){
    this.check();const r=await fetch(path,{...options,method:'GET',signal:AbortSignal.timeout(10000)});const v=await bounded(r);this.check();
    if(!r.ok)throw new FileRequestError('Admission capability unavailable',r.status);
    requireThat(v&&typeof v==='object'&&!Array.isArray(v),'Invalid admission capability');return v;
  }
  async post(path,body,opts={}){
    if(path!==this.base+'/challenge')return super.post(path,body,opts);
    return this.enhancedChallenge(body);
  }
  async enhancedChallenge(body){
    this.check();const req=JSON.parse(body);requireThat(req&&Object.keys(req).sort().join(',')==='key,request_sha256'&&sameKey(req.key,this.session.public.key),'Invalid challenge request');
    const [issuer,gate]=await Promise.all([this.capability(this.api+'/gateway/admission/capabilities'),this.capability(this.base+'/admission-capabilities')]);
    // Downgrade only after two explicit, successful legacy advertisements.
    if(this.allowExplicitLegacy&&Object.keys(issuer).join(',')==='version'&&Object.keys(gate).join(',')==='version'&&issuer.version==='codi-gateway-admission/1'&&gate.version===issuer.version)
      return super.post(this.base+'/challenge',body);
    requireThat(Object.keys(issuer).join(',')==='version'&&issuer.version===VERSION&&Object.keys(gate).sort().join(',')==='epoch,version'&&gate.version===VERSION&&/^[A-Za-z0-9_-]{43}$/.test(gate.epoch),'Unsupported or mismatched admission capability');
    const session=this.session,sid=session.public.sid,key=session.privateKey,admission=this.api+'/gateway/admission';
    const nonce=await super.post(admission+'/challenge',JSON.stringify({key:session.public.key,path:admission}),{token:session.token});
    requireThat(typeof nonce.nonce==='string'&&/^[A-Za-z0-9_-]{43}$/.test(nonce.nonce),'Invalid admission nonce');
    const raw=JSON.stringify({resource:'my-files',purpose:'gateway-challenge'}),now=nowSeconds();
    const issuerProof=await signJws({v:1,nonce:nonce.nonce,iss:sid,aud:this.config.identity.issuer,method:'POST',path:admission,iat:now,exp:now+60,request_sha256:await hash(raw)},key,PROOF_TYPE);
    const result=await super.post(admission,JSON.stringify({request:raw,proof:issuerProof}),{token:session.token});
    const inspected=inspectJws(result.ticket,TICKET,8192),authority=this.config.identity.authorityKeys.find(k=>k.kid===inspected.header.kid);requireThat(authority,'Unknown admission issuer');
    const c=await verifyJws(result.ticket,authority.jwk,TICKET,8192);validateTimes(c,20);
    const audience=location.origin+this.base;
    requireThat(c.v===1&&c.iss===this.config.identity.issuer&&c.aud===audience&&c.sub===session.public.sub&&c.sid===sid&&c.scope==='gateway-challenge'&&sameKey(c.cnf?.jwk,session.public.key),'Invalid admission ticket binding');
    let epoch=gate.epoch;
    for(let attempt=0;attempt<2;attempt++){
      this.check();requireThat(session.public.sid===sid,'File session changed');validateTimes(c,20);
      const proof=await signJws({v:1,iss:sid,aud:audience,method:'POST',path:this.base+'/challenge-v2',iat:c.iat,exp:c.exp,jti:b64(crypto.getRandomValues(new Uint8Array(32))),ticket_sha256:await hash(result.ticket),request_sha256:req.request_sha256,epoch},key,ADMISSION_PROOF);
      const response=await fetch(this.base+'/challenge-v2',{...options,method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ticket:result.ticket,proof,request_sha256:req.request_sha256}),signal:AbortSignal.timeout(15000)});
      const value=await bounded(response);this.check();
      if(response.ok)return value;
      if(attempt===0&&response.status===409&&value?.code==='stale_epoch'){
        const fresh=await this.capability(this.base+'/admission-capabilities');requireThat(Object.keys(fresh).sort().join(',')==='epoch,version'&&fresh.version===VERSION&&/^[A-Za-z0-9_-]{43}$/.test(fresh.epoch)&&fresh.epoch!==epoch,'Invalid new gateway epoch');epoch=fresh.epoch;continue;
      }
      throw new FileRequestError(value?.error||'Enhanced admission failed',response.status);
    }
    throw Error('Gateway epoch changed repeatedly');
  }
}
