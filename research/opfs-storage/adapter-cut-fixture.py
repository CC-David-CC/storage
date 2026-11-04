"""Disposable signed fixture with the verified generated SDK."""
import hashlib,os
from pathlib import Path
root=Path(__file__).resolve().parents[2]; path=Path(os.environ['CODI_SDK']);source=path.read_bytes()
if hashlib.sha256(source).hexdigest()!='44da83bdccf43a2b36ae4b3f48eaf94fc1006b88180456e26faba61aae344869':raise ValueError('Unexpected SDK')
original=root/'tests/file-status-caddy-server-research.py';text=original.read_text()
if os.environ.get('CODI_GATEWAY_BASELINE'):
 text=text.replace('sys.path.insert(0,str(ROOT))','sys.path.insert(0,str(ROOT));sys.path.insert(0,os.environ[\'CODI_GATEWAY_BASELINE\'])')
# A dedicated upload-only TCP proxy forwards the full request but closes both
# sockets as soon as the gateway starts its post-commit response.
needle2="  gate=None;gate_runner=None\n"
proxy="""  async def cut_upload(client_r,client_w):
   upstream_r,upstream_w=await asyncio.open_connection('127.0.0.1',gport)
   async def send():
    try:
     while True:
      data=await client_r.read(65536)
      if not data:break
      upstream_w.write(data);await upstream_w.drain()
    except (ConnectionError,asyncio.CancelledError):pass
   task=asyncio.create_task(send())
   try:
    data=await upstream_r.read(1)
    if data:print('fault proxy cut gateway response after upload',flush=True)
   finally:
    task.cancel();upstream_w.close();client_w.close()
    await asyncio.gather(upstream_w.wait_closed(),client_w.wait_closed(),return_exceptions=True)
  cutserver=await asyncio.start_server(cut_upload,'127.0.0.1',19868)
"""
assert text.count(needle2)==1;text=text.replace(needle2,proxy+needle2)
old=r" handle /gateway/* {\n reverse_proxy 127.0.0.1:"
new=r" handle /gateway/upload {\n reverse_proxy 127.0.0.1:19868\n }\n handle /gateway/* {\n reverse_proxy 127.0.0.1:"
assert text.count(old)==1;text=text.replace(old,new)
needle='  # The combined file client loads its verifier beside the served client.\n';assert text.count(needle)==1
text=text.replace(needle,"  shutil.copy2(os.environ['CODI_SDK'],public/'gateway_service/client.mjs')\n"+needle)
text=text.replace(needle,"  shutil.copy2(ROOT/'storage/browser/verified-content.mjs',public/'storage/browser/verified-content.mjs')\n  shutil.copytree(ROOT/'storage/browser/opfs',public/'storage/browser/opfs')\n"+needle)
# Tests can use the exact deployed desktop CSP on an isolated localhost site.
if os.environ.get('CODI_CSP'):
 policy=os.environ['CODI_CSP'].replace(chr(39),chr(92)+chr(39))
 old=r'http://127.0.0.1:19864 {\n handle /gateway/upload {'
 new=r'http://127.0.0.1:19864 {\n header >Content-Security-Policy '+chr(34)+policy+chr(34)+r'\n handle /gateway/upload {'
 if text.count(old)!=1:raise ValueError('Fixture CSP insertion did not match')
 text=text.replace(old,new)
 for port in ('gport','server.server_port'):
  oldport="str("+port+")+'\\n }"
  newport="str("+port+")+' {\\n header_down -Content-Security-Policy\\n }\\n }"
  if text.count(oldport)!=1:raise ValueError('Fixture proxy CSP insertion did not match')
  text=text.replace(oldport,newport)
if os.environ.get('CODI_CADDY'):
 text=text.replace("'/tmp/codi-microduck-hosting-evidence/caddy'","os.environ['CODI_CADDY']")
text=text.replace("cfg.write_text('http://","cfg.write_text('{\\n admin off\\n}\\nhttp://")
exec(compile(text,str(original),'exec'),{'__name__':'__main__','__file__':str(original)})
