import json,os,pathlib,signal,shutil,time
end=False
signal.signal(signal.SIGUSR1,lambda *_:globals().__setitem__('end',True))
peak=0;samples=0;reason=None;start=time.monotonic()
while not end and time.monotonic()-start<300:
 total=0
 for p in pathlib.Path('/proc').iterdir():
  if not p.name.isdigit():continue
  try:
   cmd=(p/'cmdline').read_bytes().replace(b'\0',b' ').decode(errors='replace')
   if '/mnt/data10tb/codi-opfs-evidence/profile' not in cmd or 'chrome' not in cmd:continue
   total+=next(int(x.split()[1])*1024 for x in (p/'status').read_text().splitlines() if x.startswith('VmRSS:'))
  except (OSError,StopIteration):pass
 peak=max(peak,total);samples+=1
 if total>3*1024**3 or shutil.disk_usage('/mnt/data10tb').free<5*1024**3:
  reason='resource threshold'
  for p in pathlib.Path('/proc').iterdir():
   if not p.name.isdigit():continue
   try:
    cmd=(p/'cmdline').read_bytes().replace(b'\0',b' ').decode(errors='replace')
    if '/mnt/data10tb/codi-opfs-evidence/profile' in cmd and 'chrome' in cmd and '--type=' not in cmd:os.kill(int(p.name),signal.SIGTERM)
   except OSError:pass
  break
 time.sleep(.25)
pathlib.Path('/mnt/data10tb/codi-opfs-evidence/monitor.json').write_text(json.dumps({'peakRSS':peak,'samples':samples,'reason':reason,'seconds':time.monotonic()-start}))
