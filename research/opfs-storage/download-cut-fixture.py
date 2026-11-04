"""Disposable signed c046/44da fixture; cut selected real response sockets."""
import hashlib, os
from pathlib import Path
root=Path(__file__).resolve().parents[2];sdk=Path(os.environ['CODI_SDK'])
assert hashlib.sha256(sdk.read_bytes()).hexdigest()=='44da83bdccf43a2b36ae4b3f48eaf94fc1006b88180456e26faba61aae344869'
original=root/'tests/file-status-caddy-server-research.py';text=original.read_text();text=text.replace('sys.path.insert(0,str(ROOT))',"sys.path.insert(0,str(ROOT));sys.path.insert(0,os.environ['CODI_GATEWAY_BASELINE'])")
needle='  # The combined file client loads its verifier beside the served client.\n';assert text.count(needle)==1;text=text.replace(needle,"  shutil.copy2(os.environ['CODI_SDK'],public/'gateway_service/client.mjs')\n"+needle)
needle='  gate=None;gate_runner=None\n';assert text.count(needle)==1
proxy='''  armed={'operation':None,'cuts':0,'bytes':0}
  async def fault_proxy(cr,cw):
   uw=None
   try:
    header=await cr.readuntil(b'\\r\\n\\r\\n');lines=header.split(b'\\r\\n');target=lines[0].split()[1].decode();length=next((int(x.split(b':',1)[1]) for x in lines[1:] if x.lower().startswith(b'content-length:')),0);body=await cr.readexactly(length)
    if target.startswith('/__fault/'):
     if target.startswith('/__fault/arm/'):
      op=target.rsplit('/',1)[-1];assert op in ('read-binary','chunk-read-batch-v1');armed.update(operation=op,cuts=0,bytes=0)
     import json
     data=json.dumps(armed).encode();cw.write(b'HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\nContent-Length: '+str(len(data)).encode()+b'\\r\\nConnection: close\\r\\n\\r\\n'+data);await cw.drain();return
    import json
    operation=json.loads(body).get('operation');header=b'\\r\\n'.join(x for x in lines if not x.lower().startswith(b'connection:') and x)+b'\\r\\nConnection: close\\r\\n\\r\\n';ur,uw=await asyncio.open_connection('127.0.0.1',gport);uw.write(header+body);await uw.drain()
    if operation==armed['operation']:
     response=await ur.readuntil(b'\\r\\n\\r\\n');cw.write(response);await cw.drain();chunk=await ur.read(4096);assert chunk;cw.write(chunk);await cw.drain();armed.update(operation=None,cuts=armed['cuts']+1,bytes=len(chunk));print('CUT',operation,len(chunk),flush=True);cw.transport.abort();return
    while True:
     data=await ur.read(65536)
     if not data:break
     cw.write(data);await cw.drain()
   except (ConnectionError,asyncio.IncompleteReadError,asyncio.CancelledError):pass
   finally:
    if uw:uw.close()
    cw.close()
  cutserver=await asyncio.start_server(fault_proxy,'127.0.0.1',19988)
'''
text=text.replace(needle,proxy+needle)
old=r' handle /gateway/* {\n reverse_proxy 127.0.0.1:';new=r' handle /__fault/* {\n reverse_proxy 127.0.0.1:19988\n }\n handle /gateway/use {\n reverse_proxy 127.0.0.1:19988\n }\n handle /gateway/* {\n reverse_proxy 127.0.0.1:';assert text.count(old)==1;text=text.replace(old,new)
text=text.replace('19864','19987').replace("cfg.write_text('http://","cfg.write_text('{\\n admin off\\n}\\nhttp://")
exec(compile(text,str(original),'exec'),{'__name__':'__main__','__file__':str(original)})
