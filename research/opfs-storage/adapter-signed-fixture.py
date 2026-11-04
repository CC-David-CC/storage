from pathlib import Path
here=Path(__file__).resolve().parent
text=(here/'signed-fixture.py').read_text()
needle='text=text.replace(needle,"  shutil.copytree(\'/mnt/data10tb/codi-worker-packaging/research/opfs-storage\',public/\'opfs\')\\n"+needle)'
assert needle in text
text=text.replace(needle, """text=text.replace(needle,"  shutil.copy2(ROOT/'storage/browser/verified-content.mjs',public/'storage/browser/verified-content.mjs')\\n  shutil.copytree(ROOT/'storage/browser/opfs',public/'storage/browser/opfs')\\n"+needle)""")
exec(compile(text,str(here/'signed-fixture.py'),'exec'),{'__name__':'__main__','__file__':str(here/'signed-fixture.py')})
