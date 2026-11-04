"""Signed local fixture for 128 MiB worker-budget regression."""
import hashlib,os
from pathlib import Path
root=Path(__file__).resolve().parents[2];sdk=Path(os.environ['CODI_SDK']);assert hashlib.sha256(sdk.read_bytes()).hexdigest()=='44da83bdccf43a2b36ae4b3f48eaf94fc1006b88180456e26faba61aae344869'
base=Path(os.environ['CODI_GATEWAY_BASELINE']);assert hashlib.sha256((base/'files-service.json').read_bytes()).hexdigest()=='c0465afeb10dac4a761b274eb6871a8af750fccc5523a333da2c98dac8b90960'
source=root/'tests/file-status-caddy-server-research.py';text=source.read_text().replace('sys.path.insert(0,str(ROOT))',"sys.path.insert(0,str(ROOT));sys.path.insert(0,os.environ['CODI_GATEWAY_BASELINE'])")
needle='  # The combined file client loads its verifier beside the served client.\n';assert text.count(needle)==1;text=text.replace(needle,"  shutil.copy2(os.environ['CODI_SDK'],public/'gateway_service/client.mjs')\n"+needle)
text=text.replace('19864','19989').replace("'/tmp/codi-microduck-hosting-evidence/caddy'","os.environ['CODI_CADDY']").replace("cfg.write_text('http://","cfg.write_text('{\\n admin off\\n}\\nhttp://")
exec(compile(text,str(source),'exec'),{'__name__':'__main__','__file__':str(source)})
