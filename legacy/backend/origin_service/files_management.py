"""Journaled issuer-only private-file enablement; caller holds native lock.

Schema4 pins the independently installed file operator/config. Disabling returns
to schema3, preserving TURN and current data so native10 code rollback is possible.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import secrets
import subprocess
import time
from origin_service import maintenance

VERSION='codi-managed-instance/4'
JOURNAL='codi-files-transition/1'
OPERATOR_FILES={'file_service/__init__.py','file_service/operator.py','scripts/manage-user-files.py'}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def write(op,path,value):op.atomic(path,(json.dumps(value,indent=2)+'\n').encode())
def slot(config_path,name):return Path(config_path).parent/name
def validate(op,config,read_inputs=True):
    value=config.get('userFiles')
    if value is None:
        if config.get('version')==VERSION or 'userFiles' in config:raise ValueError('Disabled files must omit the userFiles field')
        return
    if config.get('version') not in (VERSION,'codi-managed-instance/5') or not isinstance(value,dict) or set(value)!={'configFile','configSHA256','operatorRelease','operatorManifestSHA256'}:raise ValueError('Invalid managed file backend pin')
    for key in ['configSHA256','operatorManifestSHA256']:
        if not isinstance(value[key],str) or not re.fullmatch('[0-9a-f]{64}',value[key]):raise ValueError('Exact file backend pins required')
    config_file=op.path(value['configFile']);operator=op.path(value['operatorRelease'])
    for path in [config_file,operator]:
        if any(path.is_relative_to(Path(base)) for base in ['/home','/root','/tmp','/var/tmp','/run']):raise ValueError('File backend requires persistent protected installation')
    if not read_inputs:return
    raw=op.read_owned(operator/'file-operator.json',0,0o644)
    if sha(raw)!=value['operatorManifestSHA256']:raise ValueError('File operator manifest pin changed')
    metadata=json.loads(raw)
    if set(metadata)!={'version','files'} or metadata['version']!='codi-file-operator/1' or set(metadata['files'])!=OPERATOR_FILES:raise ValueError('Unexpected file operator manifest')
    found=set()
    for path in operator.rglob('*'):
        info=path.lstat()
        if path.is_symlink() or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('File operator is not immutable root code')
        if path.is_dir():continue
        name=str(path.relative_to(operator));found.add(name)
        if name=='file-operator.json':continue
        code=op.read_owned(path,0,0o644,262144)
        if metadata['files'].get(name)!={'bytes':len(code),'sha256':sha(code)}:raise ValueError('File operator code changed')
    if found!=OPERATOR_FILES|{'file-operator.json'}:raise ValueError('Incomplete/extra file operator input')
    if sha(op.read_owned(config_file,0,0o600))!=value['configSHA256']:raise ValueError('File backend configuration pin changed')
    spec=importlib.util.spec_from_file_location('codi_file_boundary_'+value['operatorManifestSHA256'],operator/'file_service/operator.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    manager=module.Manager(config_file.parent)
    with manager.locked():
        backend=manager.load()
        if backend['origin']!=config['origin'] or backend['basePath']!=config['basePath']:raise ValueError('File backend origin/mount differs from native issuer')
        expected=json.loads(op.read_owned(Path(config['stateRoot'])/'public/origin-discovery.json',0,0o444))['identity']
        if json.loads(manager.policy(backend))!=expected:raise ValueError('File backend issuer keys differ from the native public pin')
    return manager,backend
def policy(op,config_file,operator):
    config_file=op.path(config_file);operator=op.path(operator)
    return {'configFile':str(config_file),'configSHA256':sha(op.read_owned(config_file,0,0o600)),
            'operatorRelease':str(operator),'operatorManifestSHA256':sha(op.read_owned(operator/'file-operator.json',0,0o644))}
def ready(op,config):
    public=op.issuer_config(config).get('gateway')
    if not config.get('userFiles'):
        if public is not None:raise ValueError('Issuer still advertises disabled private files')
        return
    expected={'version':'codi-user-files/1','basePath':config['basePath']+'/gateway','fileBytes':8*1024*1024}
    if public!=expected:raise ValueError('Issuer file metadata differs from managed policy')
    manager,backend=validate(op,config);manager.health(backend)
def validate_pair(op,current,before,after):
    if before.get('version') not in ('codi-managed-instance/3',VERSION,'codi-managed-instance/5') or after.get('version') not in ('codi-managed-instance/3',VERSION,'codi-managed-instance/5') or before.get('maintenance')!=1 or after.get('maintenance')!=1:raise ValueError('File changes require checkpointed TURN-capable metadata')
    stable=lambda c:{k:v for k,v in c.items() if k not in ('version','userFiles')}
    if current not in (before,after) or stable(before)!=stable(after):raise ValueError('File policy cannot change code, TURN, identity, state, mount or ports')
    for c in (before,after):
        if c['version']!='codi-managed-instance/5' and (c['version']==VERSION)!=('userFiles' in c):raise ValueError('File metadata schema/field mismatch')
        validate(op,c,read_inputs=False)
def history(op,config,config_path):
    file=slot(config_path,'files-history.json')
    if not file.exists():return {'version':'codi-files-history/1','instance':config['instance'],'entries':[]}
    value=json.loads(op.read_owned(file,0,0o600))
    if set(value)!={'version','instance','entries'} or value['version']!='codi-files-history/1' or value['instance']!=config['instance'] or not isinstance(value['entries'],list) or len(value['entries'])>16:raise ValueError('Invalid file policy history')
    return value
def committed(op,config,config_path,journal):return any(e['id']==journal['id'] and e['outcome']=='applied' for e in history(op,config,config_path)['entries'])
def record(op,config,config_path,journal,outcome):
    value=history(op,config,config_path);entry={k:journal[k] for k in ['id','before','after','activeRoles']};entry.update(outcome=outcome,completed=int(time.time()))
    value['entries']=[old for old in value['entries'] if old['id']!=entry['id']]+[entry];value['entries']=value['entries'][-16:];write(op,slot(config_path,'files-history.json'),value)
def clear(config_path):slot(config_path,'maintenance.json').unlink();maintenance.sync_directory(Path(config_path).parent)
def apply(op,config,config_path):
    op.atomic(Path(config['unitDir'])/op.unit(config,'issuer'),op.render(config,'issuer'),0o644);write(op,config_path,config);op.systemctl('daemon-reload')
def start(op,config,roles,config_path):
    maintenance.guard_epoch(op,config,config_path)
    if roles:
        if op.systemctl('show',op.unit(config,'issuer'),'-p','ActiveState','--value').strip()=='failed':op.systemctl('reset-failed',op.unit(config,'issuer'))
        op.systemctl('start',op.unit(config,'issuer'));op.ready(config,['issuer'])
        expected=json.loads(op.read_owned(Path(config['stateRoot'])/'public/origin-discovery.json',0,0o444))['identity']
        if op.issuer_config(config)['identity']!=expected:raise ValueError('Issuer identity pin changed during files configuration')
        ready(op,config)
def revert(op,config_path,journal):
    before=journal['before'];op.installed(before);journal['phase']='rolling-back';write(op,slot(config_path,'maintenance.json'),journal)
    op.stop(before,['issuer']);apply(op,before,config_path);start(op,before,journal['activeRoles'],config_path)
    record(op,before,config_path,journal,'reverted');clear(config_path)
    return {'status':'files-failed-rolled-back','id':journal['id'],'otherRolesRestarted':False,'dataRestored':False}
def configure(op,config,config_path,value):
    from origin_service import deployment
    maintenance.guard(op,config,config_path)
    if value is None:after={k:v for k,v in config.items() if k!='userFiles'};after['version']='codi-managed-instance/5' if config.get('guestNetwork') else 'codi-managed-instance/3'
    else:after={**config,'version':'codi-managed-instance/5' if config.get('guestNetwork') else VERSION,'userFiles':value}
    validate_pair(op,config,config,after);op.installed(after);deployment.syntax(op,after,config_path)
    if after==config:return {'status':'files-already-current','otherRolesRestarted':False}
    if value is not None:
        manager,backend=validate(op,after);manager.health(backend)
    selected=deployment.active(op,config);roles=['issuer'] if 'issuer' in selected else []
    journal={'version':JOURNAL,'id':secrets.token_hex(16),'phase':'prepared','before':config,'after':after,'activeRoles':roles,'created':int(time.time())}
    write(op,slot(config_path,'maintenance.json'),journal)
    try:
        op.stop(config,['issuer']);journal['phase']='switching';write(op,slot(config_path,'maintenance.json'),journal);apply(op,after,config_path)
        journal['phase']='starting';write(op,slot(config_path,'maintenance.json'),journal);start(op,after,roles,config_path)
        record(op,after,config_path,journal,'applied');clear(config_path)
        return {'status':'files-configured','id':journal['id'],'enabled':value is not None,'otherRolesRestarted':False,'dataRestored':False}
    except (OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
        if committed(op,after,config_path,journal):raise ValueError('File policy committed; finish recover-operation') from error
        try:return revert(op,config_path,journal)
        except (OSError,ValueError,subprocess.SubprocessError) as failure:raise ValueError('File policy rollback incomplete; retain journal and recover-operation: '+str(failure)) from failure
def recover(op,config,config_path):
    journal=json.loads(op.read_owned(slot(config_path,'maintenance.json'),0,0o600))
    if set(journal)!={'version','id','phase','before','after','activeRoles','created'} or journal['version']!=JOURNAL or journal['activeRoles'] not in ([],['issuer']):raise ValueError('Invalid files transition journal')
    validate_pair(op,config,journal['before'],journal['after'])
    if not committed(op,config,config_path,journal):
        result=revert(op,config_path,journal);result['status']='interrupted-files-rolled-back';return result
    after=journal['after'];op.installed(after);op.stop(after,['issuer']);apply(op,after,config_path);start(op,after,journal['activeRoles'],config_path);clear(config_path)
    return {'status':'committed-files-recovered','id':journal['id'],'otherRolesRestarted':False,'dataRestored':False}
