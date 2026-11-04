"""Disposable signed fixture with the verified generated SDK."""
import hashlib,os
from pathlib import Path
root=Path(__file__).resolve().parents[2]; path=Path(os.environ['CODI_SDK']);source=path.read_bytes()
if hashlib.sha256(source).hexdigest()!='44da83bdccf43a2b36ae4b3f48eaf94fc1006b88180456e26faba61aae344869':raise ValueError('Unexpected SDK')
old_sdk=Path('/mnt/data10tb/codi-beta-batch-c0465afe/gateway_service/client.mjs')
if old_sdk.is_symlink() or hashlib.sha256(old_sdk.read_bytes()).hexdigest()!='7474528c22ac08c7fde1ddc18c05862b03f8b07d4c9ac501ffde7a49a5396659':raise ValueError('Unexpected old SDK')
original=root/'tests/file-status-caddy-server-research.py';text=original.read_text()
if os.environ.get('CODI_GATEWAY_BASELINE'):
 text=text.replace('sys.path.insert(0,str(ROOT))','sys.path.insert(0,str(ROOT));sys.path.insert(0,os.environ[\'CODI_GATEWAY_BASELINE\'])')
needle='  # The combined file client loads its verifier beside the served client.\n';assert text.count(needle)==1
text=text.replace(needle,"  shutil.copy2(os.environ['CODI_SDK'],public/'gateway_service/client.mjs')\n"+needle)
text=text.replace(needle,"  shutil.copytree('/mnt/data10tb/codi-worker-packaging/research/opfs-storage',public/'opfs')\n"+needle)
text=text.replace(needle,"  shutil.copy2('/mnt/data10tb/codi-beta-batch-c0465afe/gateway_service/client.mjs',public/'gateway_service/client-old.mjs')\n"+needle)
# Tests can use the exact deployed desktop CSP on an isolated localhost site.
if os.environ.get('CODI_CSP'):
 policy=os.environ['CODI_CSP'].replace(chr(39),chr(92)+chr(39))
 old=r'http://127.0.0.1:19864 {\n handle /gateway/* {'
 new=r'http://127.0.0.1:19864 {\n header >Content-Security-Policy '+chr(34)+policy+chr(34)+r'\n handle /gateway/* {'
 if text.count(old)!=1:raise ValueError('Fixture CSP insertion did not match')
 text=text.replace(old,new)
 for port in ('gport','server.server_port'):
  oldport="str("+port+")+'\\n }"
  newport="str("+port+")+' {\\n header_down -Content-Security-Policy\\n }\\n }"
  if text.count(oldport)!=1:raise ValueError('Fixture proxy CSP insertion did not match')
  text=text.replace(oldport,newport)
if os.environ.get('CODI_CADDY'):
 text=text.replace("'/tmp/codi-microduck-hosting-evidence/caddy'","os.environ['CODI_CADDY']")
text=text.replace('19864','19874').replace("cfg.write_text(\x27http://","cfg.write_text(\x27{\\n admin off\\n}\\nhttp://")
exec(compile(text,str(original),'exec'),{'__name__':'__main__','__file__':str(original)})
