"""Root-owned file worker, explicit durable migration and private socket proxy.

Does not enable boot, configure a public route, change the issuer, restore data
or choose registered accounts. The storage foundation must already exist.
"""
from contextlib import contextmanager
import fcntl
import grp
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time
from urllib.parse import quote, urlsplit

WORKER_FILES={*('gateway_service/'+n for n in ['__init__.py','auth.py','policy.py','user_store.py','http.py','transfers.py','client.mjs']),
              'codiserver-server-v0.3.0/codiauth/__init__.py','codiserver-server-v0.3.0/codiauth/jose.py','scripts/serve-user-files.py','requirements.lock'}
SAFE=re.compile(r'/[A-Za-z0-9_./-]+\Z')
def digest(raw):return hashlib.sha256(raw).hexdigest()
def run(args,**kwargs):return subprocess.run(list(map(str,args)),check=True,capture_output=True,text=True,timeout=60,**kwargs).stdout.strip()
def systemctl(*args):return run(['/usr/bin/systemctl',*args])
def sync(folder):
    fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
def location(value):
    p=Path(value)
    if not p.is_absolute() or '..' in p.parts or not SAFE.fullmatch(str(p)):raise ValueError('Simple absolute managed path required')
    for part in [p,*p.parents]:
        if part.is_symlink():raise ValueError('Managed paths cannot contain symlinks')
    return p
def protected(value,*,mode=None,directory=False,uid=0):
    p=location(value)
    for parent in p.parents:
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,uid) or info.st_mode&0o022:raise ValueError('Protected immutable ancestors required')
    info=p.lstat()
    if info.st_uid!=uid or info.st_mode&0o022 or (mode is not None and stat.S_IMODE(info.st_mode)!=mode):raise ValueError('Managed ownership/mode changed')
    if directory:
        if not stat.S_ISDIR(info.st_mode):raise ValueError('Regular managed directory required')
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise ValueError('Regular unlinked managed file required')
    return p
def read(value,mode=0o600,maximum=65536):
    p=protected(value,mode=mode)
    with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        info=os.fstat(stream.fileno())
        if info.st_size>maximum:raise ValueError('Managed input too large')
        raw=stream.read(maximum+1)
        if len(raw)>maximum:raise ValueError('Managed input too large')
        return raw
def atomic(path,raw,mode=0o600):
    path=location(path);protected(path.parent,directory=True)
    if path.exists() or path.is_symlink():protected(path,mode=mode)
    fd,name=tempfile.mkstemp(prefix='.file-operator-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as output:os.fchmod(output.fileno(),mode);output.write(raw);output.flush();os.fsync(output.fileno())
        os.replace(name,path);sync(path.parent)
    finally:
        if os.path.exists(name):os.unlink(name)
def write(path,value):atomic(path,(json.dumps(value,sort_keys=True,indent=2)+'\n').encode())
def directory(value,mode=0o755):
    p=location(value)
    if not p.exists():protected(p.parent,directory=True);p.mkdir(mode=mode);sync(p.parent)
    return protected(p,mode=mode,directory=True)
def verify_worker(folder,pin):
    folder=protected(folder,mode=0o755,directory=True);raw=read(folder/'files-service.json',0o644)
    if digest(raw)!=pin:raise ValueError('File worker manifest pin changed')
    value=json.loads(raw)
    if set(value)!={'version','files'} or value['version']!='codi-private-file-service/1' or set(value['files'])!=WORKER_FILES:raise ValueError('Unexpected file worker manifest')
    found=set()
    for p in folder.rglob('*'):
        if p.is_dir():protected(p,mode=0o755,directory=True);continue
        raw=read(p,0o644,262144);name=str(p.relative_to(folder));found.add(name)
        if name!='files-service.json' and value['files'].get(name)!={'bytes':len(raw),'sha256':digest(raw)}:raise ValueError('Changed/extra file worker input')
    if found!=WORKER_FILES|{'files-service.json'}:raise ValueError('Missing file worker input')
def verify_python(python,release):
    python=Path(python);location(python.parent);venv=protected(python.parent.parent,directory=True)
    if python.name!='python' or python.parent.name!='bin' or not python.is_file():raise ValueError('Explicit installed virtualenv bin/python required')
    for p in venv.rglob('*'):
        info=p.lstat()
        if info.st_uid or (not p.is_symlink() and info.st_mode&0o022):raise ValueError('Virtualenv is writable by another identity')
        if p.is_symlink():
            target=p.resolve(strict=True)
            if not target.is_relative_to(venv):
                if p.parent!=venv/'bin' or not re.fullmatch(r'python(?:3(?:\.[0-9]+)?)?',p.name) or target.parent!=Path('/usr/bin') or not re.fullmatch(r'python3\.[0-9]+',target.name):raise ValueError('Unsafe virtualenv link')
                protected(target)
    expected={line.strip().lower() for line in (Path(release)/'requirements.lock').read_text().splitlines() if line.strip()}
    if expected!={line.lower() for line in run([python,'-I','-B','-m','pip','freeze']).splitlines() if line}:raise ValueError('Virtualenv dependency lock changed')
    run([python,'-I','-B','-m','pip','check'])
def account(name):
    user=pwd.getpwnam(name)
    group=grp.getgrgid(user.pw_gid)
    if user.pw_uid==0 or user.pw_gid==0 or group.gr_name!=name or set(group.gr_mem)-{name} or user.pw_dir!='/nonexistent' or user.pw_shell!='/usr/sbin/nologin' or set(os.getgrouplist(name,user.pw_gid))!={user.pw_gid}:raise ValueError('Dedicated non-login account without extra groups required')
    if run(['/usr/bin/passwd','-S',name]).split()[1]!='L':raise ValueError('Locked service account required')
    return user
def context(policy,base):
    fields={'mode','apiBase','issuer','audience','authorityClass','authorityKeys'}
    if not isinstance(policy,dict) or set(policy)!=fields or policy.get('mode')!='server' or policy.get('audience')!='codiserver-peers-v1' or policy.get('authorityClass')!='development':raise ValueError('Only the public development issuer policy is accepted')
    origin=policy['issuer'];url=urlsplit(origin)
    if not url.hostname or url.username or url.password or url.path or url.query or url.fragment or origin!=url.geturl() or not (url.scheme=='https' or url.scheme=='http' and url.hostname=='127.0.0.1'):raise ValueError('HTTPS or loopback issuer required')
    if not isinstance(base,str) or base and not re.fullmatch(r'(?:/[A-Za-z0-9_-]+)+',base):raise ValueError('Canonical application prefix required')
    if policy['apiBase']!=base+'/api/v1':raise ValueError('Issuer policy API prefix changed')
    # This is public key material only; never persist a credential-bearing config.
    entries=policy.get('authorityKeys')
    if not isinstance(entries,list) or not 1<=len(entries)<=4:raise ValueError('Pinned issuer authorities required')
    for entry in entries:
        if set(entry)!={'kid','jwk'} or not isinstance(entry['kid'],str) or not 1<=len(entry['kid'])<=128:raise ValueError('Bounded issuer public key required')
        if set(entry['jwk'])!={'kty','crv','x','y'} or entry['jwk']['kty']!='EC' or entry['jwk']['crv']!='P-256':raise ValueError('Only public P-256 identity keys permitted')
        if any(not isinstance(entry['jwk'][name],str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}',entry['jwk'][name]) for name in ['x','y']):raise ValueError('Canonical P-256 public coordinates required')
    return origin

class Manager:
    def __init__(self,folder):
        self.folder=location(folder);self.config_path=self.folder/'managed.json';self.journal=self.folder/'pending.json'
    @contextmanager
    def locked(self,instance=None):
        if os.geteuid()!=0:raise ValueError('Root-owned native operator required')
        directory(self.folder)
        if instance is None:
            if self.config_path.exists():instance=json.loads(read(self.config_path))['instance']
            elif self.journal.exists():instance=json.loads(read(self.journal))['candidate']['instance']
            else:raise ValueError('No installed file configuration or pending recovery')
        if not re.fullmatch(r'codi-files-[a-z0-9][a-z0-9-]{0,36}',instance):raise ValueError('Bounded file unit namespace required')
        global_dir=directory('/run/codi-file-operators',0o700);descriptors=[]
        try:
            for lock in [self.folder/'.operator.lock',global_dir/(instance+'.lock'),Path('/run/lock/codi-user-storage.lock')]:
                fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);descriptors.append(fd)
                info=os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:raise ValueError('Unsafe file/storage operator lock')
                try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:raise ValueError('Another file/storage operation is in progress') from None
            yield
        finally:
            for fd in reversed(descriptors):os.close(fd)
    @staticmethod
    def names(config):
        name=config['instance'];return [name+'.service',name+'-proxy.service',name+'-proxy.socket']
    def policy(self,config):
        raw=read(self.folder/'issuer-policy.json',0o644,32768)
        if digest(raw)!=config['issuerPolicySHA256'] or context(json.loads(raw),config['basePath'])!=config['origin']:raise ValueError('Issuer public policy pin/context changed')
        return raw
    def validate(self,config):
        expected={'version','instance','user','uid','gid','release','manifestSHA256','python','unitDir','stateRoot','dataRoot','origin','basePath','port','issuerPolicySHA256','socketProxy','socketProxySHA256'}
        if set(config)!=expected or config['version']!='codi-files-managed/1' or not re.fullmatch(r'codi-files-[a-z0-9][a-z0-9-]{0,36}',config['instance']):raise ValueError('Unexpected file service config')
        if config['unitDir'] not in ('/etc/systemd/system','/run/systemd/system'):raise ValueError('Explicit system unit directory required')
        if config['user']!='codi-gateway' and not (config['unitDir']=='/run/systemd/system' and re.fullmatch(r'codi-file-fixture-[0-9a-f]{8}',config['user'])):raise ValueError('Prepared gateway service identity required')
        user=account(config['user'])
        if [user.pw_uid,user.pw_gid]!=[config['uid'],config['gid']]:raise ValueError('Service identity changed')
        if type(config['port']) is not int or not 1024<=config['port']<=65535:raise ValueError('Unprivileged loopback port required')
        roots=[location(config[name]) for name in ['stateRoot','dataRoot','release']]+[self.folder,location(Path(config['python']).parent.parent)]
        if any(a.is_relative_to(b) or b.is_relative_to(a) for i,a in enumerate(roots) for b in roots[i+1:]):raise ValueError('Code, environment, config and private roots must be disjoint')
        for p in roots:
            if any(p.is_relative_to(Path(base)) for base in ['/home','/root','/tmp','/var/tmp','/run']):raise ValueError('Install persistent roots outside homes/temp/runtime')
        for name in ['stateRoot','dataRoot']:protected(config[name],mode=0o700,directory=True,uid=user.pw_uid)
        protected(Path(config['stateRoot'])/'permissions.sqlite3',mode=0o600,uid=user.pw_uid)
        verify_worker(config['release'],config['manifestSHA256']);verify_python(config['python'],config['release'])
        proxy=protected(config['socketProxy'],mode=0o755)
        if str(proxy) not in ('/usr/lib/systemd/systemd-socket-proxyd','/lib/systemd/systemd-socket-proxyd') or digest(proxy.read_bytes())!=config['socketProxySHA256']:raise ValueError('Installed socket proxy pin changed')
        self.policy(config)
    def units(self,c):
        worker,proxy,socket=self.names(c);common={'UMask':'0077','ProtectSystem':'strict','ProtectHome':'yes','PrivateTmp':'yes','PrivateDevices':'yes','PrivateNetwork':'yes','NoNewPrivileges':'yes','ProtectKernelTunables':'yes','ProtectKernelModules':'yes','ProtectControlGroups':'yes','RestrictSUIDSGID':'yes','RestrictNamespaces':'yes','LockPersonality':'yes','RestrictAddressFamilies':'AF_UNIX AF_INET','CapabilityBoundingSet':'','AmbientCapabilities':'','TasksMax':'64','LimitNOFILE':'256','Environment':'PYTHONDONTWRITEBYTECODE=1','Restart':'on-failure','RestartSec':'1s','TimeoutStopSec':'12s'}
        def unit(description,settings,extra=''):
            return ('[Unit]\nDescription='+description+'\nStartLimitIntervalSec=60\nStartLimitBurst=5\n'+extra+'\n[Service]\n'+''.join(k+'='+str(v)+'\n' for k,v in settings.items())).encode()
        command=[c['python'],'-I','-B',str(Path(c['release'])/'scripts/serve-user-files.py'),'serve','--state-root',c['stateRoot'],'--data-root',c['dataRoot'],'--issuer-policy',str(self.folder/'issuer-policy.json'),'--issuer-policy-sha256',c['issuerPolicySHA256'],'--port',str(c['port']),'--base-path',c['basePath']]
        if any('"' in arg or '\n' in arg or '%' in arg for arg in command):raise ValueError('Unsafe systemd command argument')
        settings={**common,'Type':'exec','User':c['user'],'Group':str(c['gid']),'WorkingDirectory':c['release'],'ExecStart':' '.join('"'+arg+'"' for arg in command),'ReadWritePaths':c['stateRoot']+' '+c['dataRoot'],'MemoryMax':'384M','InaccessiblePaths':'-/etc/codi-connected -/var/lib/codi-connected -/etc/caddy -/var/lib/caddy'}
        values={worker:unit('Codi private registered files',settings)}
        settings={**common,'Type':'notify','DynamicUser':'yes','ExecStart':c['socketProxy']+' --connections-max=16 127.0.0.1:'+str(c['port']),'MemoryMax':'32M','TasksMax':'16','InaccessiblePaths':c['stateRoot']+' '+c['dataRoot']}
        values[proxy]=unit('Codi fixed private file proxy',settings,'Requires='+worker+' '+socket+'\nAfter='+worker+' '+socket+'\nBindsTo='+worker+'\nJoinsNamespaceOf='+worker+'\n')
        values[socket]=('[Unit]\nDescription=Codi loopback file socket\n\n[Socket]\nListenStream=127.0.0.1:'+str(c['port'])+'\nAccept=no\nNoDelay=true\nBacklog=16\nService='+proxy+'\n').encode()
        return values
    def check_units(self,c):
        for name,raw in self.units(c).items():
            if read(Path(c['unitDir'])/name,0o644)!=raw:raise ValueError('Managed file unit changed')
            for root in ['/etc/systemd/system','/run/systemd/system','/usr/lib/systemd/system']:
                override=Path(root)/(name+'.d')
                if override.exists() or override.is_symlink():raise ValueError('Unmanaged file unit drop-in')
                other=Path(root)/name
                if other!=Path(c['unitDir'])/name and (other.exists() or other.is_symlink()):raise ValueError('Ambiguous file unit definition')
            fields=dict(line.split('=',1) for line in systemctl('show',name,'-p','FragmentPath','-p','DropInPaths').splitlines())
            if fields['FragmentPath']!=str(Path(c['unitDir'])/name) or fields['DropInPaths']:raise ValueError('Loaded file unit differs from managed input')
    def load(self,*,pending=False):
        if self.journal.exists() and not pending:raise ValueError('Pending file operation; explicit recovery required')
        c=json.loads(read(self.config_path));self.validate(c);self.check_units(c);return c
    def states(self,c):
        values={name:dict(line.split('=',1) for line in systemctl('show',name,'-p','ActiveState','-p','MainPID','-p','UnitFileState').splitlines()) for name in self.names(c)}
        # Socket units have no process and do not expose MainPID.
        for name,value in values.items():
            if name.endswith('.socket'):value['MainPID']='0'
        return values
    def inactive(self,c):
        if any(s['ActiveState'] not in ('inactive','failed') or int(s['MainPID']) for s in self.states(c).values()):raise ValueError('Stop private file units before migration/configuration')
    def apply(self,c):
        for name,raw in self.units(c).items():
            target=Path(c['unitDir'])/name
            if target.exists() and read(target,0o644)!=raw:raise ValueError('Refusing to replace an unmanaged unit')
            atomic(target,raw,0o644)
        write(self.config_path,c);systemctl('daemon-reload');self.check_units(c)
    def clear(self):self.journal.unlink();sync(self.folder)
    def configure(self,*,instance,user,release,manifest_sha256,python,state_root,data_root,issuer_policy,base_path='',port=8140,unit_dir='/etc/systemd/system'):
        if self.journal.exists():raise ValueError('Recover the pending file operation first')
        raw=read(issuer_policy,0o644,32768);policy=json.loads(raw);origin=context(policy,base_path)
        who=account(user);proxy=Path('/usr/lib/systemd/systemd-socket-proxyd')
        c={'version':'codi-files-managed/1','instance':instance,'user':user,'uid':who.pw_uid,'gid':who.pw_gid,'release':str(location(release)),'manifestSHA256':manifest_sha256,'python':str(Path(python)),'stateRoot':str(location(state_root)),'dataRoot':str(location(data_root)),'origin':origin,'basePath':base_path,'port':port,'unitDir':str(unit_dir),'issuerPolicySHA256':digest(raw),'socketProxy':str(proxy),'socketProxySHA256':digest(proxy.read_bytes())}
        if self.config_path.exists():
            existing=self.load()
            if existing!=c:raise ValueError('Existing file config differs; retain it and review an explicit upgrade')
            return {'status':'already-configured','servicesRestarted':False}
        # Validate before creating any units. The policy copy is public, immutable
        # operator input, not an issuer credential or session database.
        policy_path=self.folder/'issuer-policy.json'
        if policy_path.exists() and read(policy_path,0o644)!=raw:raise ValueError('Retained issuer policy changed')
        atomic(policy_path,raw,0o644);self.validate(c)
        for name in self.names(c):
            if (Path(c['unitDir'])/name).exists():raise ValueError('Pre-existing file unit must be reviewed')
        write(self.journal,{'version':'codi-file-operation/1','kind':'configure','candidate':c,'phase':'prepared'})
        self.apply(c);self.inactive(c);self.clear()
        return {'status':'configured','started':False,'bootEnabled':False}
    def baseline(self,c):
        p=protected(Path(c['stateRoot'])/'permissions.sqlite3',mode=0o600,uid=c['uid'])
        if p.stat().st_size>64*1024*1024:raise ValueError('Permission database exceeds reviewed migration bound')
        with sqlite3.connect('file:'+quote(str(p),safe='/')+'?mode=ro',uri=True) as db:
            if db.execute('PRAGMA quick_check(1)').fetchall()!=[('ok',)]:raise ValueError('Retain corrupt permission state for recovery')
            rows={name:db.execute('SELECT * FROM '+name+' ORDER BY 1,2 LIMIT '+str(limit+1)).fetchall() for name,limit in [('users',1024),('permissions',7168)]}
            rows['metadata']=db.execute('SELECT * FROM metadata LIMIT 2').fetchall()
            if len(rows['users'])>1024 or len(rows['permissions'])>7168 or rows['metadata']!=[(1,)]:raise ValueError('Permission state exceeds reviewed schema/capacity')
        return digest(json.dumps(rows,sort_keys=True,separators=(',',':')).encode())
    def initialize(self,phase=lambda name:None):
        c=self.load();self.inactive(c);backup_dir=directory(self.folder/'backups',0o700)
        backup=backup_dir/('permissions-'+str(time.time_ns())+'.sqlite3');fd=os.open(backup,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
        source=Path(c['stateRoot'])/'permissions.sqlite3'
        before=self.baseline(c)
        with sqlite3.connect('file:'+quote(str(source),safe='/')+'?mode=ro',uri=True) as original,sqlite3.connect(backup) as copy:original.backup(copy)
        with backup.open('rb') as stream:os.fsync(stream.fileno())
        sync(backup_dir)
        journal={'version':'codi-file-operation/1','kind':'initialize','candidate':c,'phase':'prepared','baselineSHA256':before,'backup':str(backup),'backupSHA256':digest(read(backup,maximum=64*1024*1024))}
        write(self.journal,journal);phase('prepared');return self.finish_initialize(journal,phase)
    def finish_initialize(self,journal,phase=lambda name:None):
        c=self.load(pending=True)
        if c!=journal['candidate'] or self.baseline(c)!=journal['baselineSHA256']:raise ValueError('Existing account-folder bindings/permissions changed; retain migration journal')
        if digest(read(journal['backup'],maximum=64*1024*1024))!=journal['backupSHA256']:raise ValueError('Migration backup changed')
        self.inactive(c)
        command=[c['python'],'-I','-B',str(Path(c['release'])/'scripts/serve-user-files.py'),'initialize','--state-root',c['stateRoot'],'--data-root',c['dataRoot'],'--issuer-policy',str(self.folder/'issuer-policy.json'),'--issuer-policy-sha256',c['issuerPolicySHA256'],'--base-path',c['basePath']]
        value=json.loads(run(['/usr/sbin/runuser','-u',c['user'],'--',*command]));phase('initialized')
        if value['status']!='initialized' or self.baseline(c)!=journal['baselineSHA256']:raise ValueError('File extension did not preserve folder/permission state')
        result={'status':'initialized','existingBindingsAndACLsPreserved':True,'backup':journal['backup'],'backupSHA256':journal['backupSHA256'],'dataRestored':False,'servicesStarted':False}
        write(self.folder/'migration-last.json',result);journal['phase']='committed';write(self.journal,journal);phase('committed');self.clear();return result
    def recover(self):
        j=json.loads(read(self.journal))
        if j.get('version')!='codi-file-operation/1' or j.get('kind') not in ('configure','initialize') or j.get('phase') not in ('prepared','committed'):raise ValueError('Unrecognized file journal; retain for review')
        self.validate(j['candidate'])
        if j['kind']=='configure':
            if set(j)!={'version','kind','candidate','phase'}:raise ValueError('Unexpected configure recovery record')
            if self.config_path.exists() and json.loads(read(self.config_path))!=j['candidate']:raise ValueError('Different installed configuration; retain pending journal')
            self.apply(j['candidate']);self.inactive(j['candidate']);self.clear();return {'status':'configuration-recovered','started':False}
        if set(j)!={'version','kind','candidate','phase','baselineSHA256','backup','backupSHA256'} or not Path(j['backup']).is_relative_to(self.folder/'backups'):raise ValueError('Unexpected migration recovery record')
        return self.finish_initialize(j)
    def health(self,c):
        connection=http.client.HTTPConnection('127.0.0.1',c['port'],timeout=2)
        try:
            connection.request('GET','/healthz',headers={'Host':urlsplit(c['origin']).netloc});response=connection.getresponse();raw=response.read(1024)
            if response.status!=200 or json.loads(raw)!={'status':'ok','scope':'personal-files'}:raise ValueError('Private file worker is not ready')
        finally:connection.close()
    def start(self):
        c=self.load()
        for name in self.names(c):
            if self.states(c)[name]['ActiveState']=='failed':systemctl('reset-failed',name)
        try:
            systemctl('start',self.names(c)[0],self.names(c)[2]);end=time.monotonic()+20
            while True:
                try:self.health(c);break
                except (OSError,ValueError,http.client.HTTPException):
                    if time.monotonic()>end:raise ValueError('Private file worker readiness failed; preserve state and inspect unit logs')
                    time.sleep(.1)
        except (OSError,ValueError,subprocess.SubprocessError):
            systemctl('stop',*reversed(self.names(c)));raise
        return {'status':'started','units':self.states(c),'bootEnabled':False}
    def stop(self):
        c=self.load();systemctl('stop',*reversed(self.names(c)));self.inactive(c)
        return {'status':'stopped','privateDataPreserved':True}
