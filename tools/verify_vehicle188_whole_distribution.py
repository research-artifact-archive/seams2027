#!/usr/bin/env python3
"""Check saved distribution bytes; never execute a scientific payload."""
import argparse, hashlib, importlib.util, json, sys, zipfile
from pathlib import Path
sys.dont_write_bytecode=True
TAG='vehicle188-whole-region-evidence-20261024-v1'
ROWS_SHA='33cdd3785007d6f543353eeddd63edd1be54e952013698e6158a55b189d61c41'
EXT_SHA='b214a5c31a0e95ef3a0c0ef72d52c7a1df07d404a9a9bcfd29213d228b0d2b0c'
def digest(value):return hashlib.sha256(value).hexdigest()
def objects(value):return digest(json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode())
def need(value,label):
 if not value:raise ValueError(label)
def verify(root,overlay=None):
 spec=importlib.util.spec_from_file_location('historical_byte_helpers',root/'tools/verify_vehicle188_distribution.py')
 h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
 actual=h.inventory(root)
 if overlay is not None:actual.update(h.inventory(overlay))
 read=lambda name:actual[h.safe(name)].read_bytes()
 m=h.decode(read('CURRENT_DISTRIBUTION_MANIFEST.json'))
 need(m['schema']=='current-anonymous-distribution-v6' and m['version_tag']==TAG,'distribution identity')
 need(m['publication_mode']=='evidence-only' and m['scientific_executions_for_publication']==0,'publication scope')
 pins=h.pin_rows(m['files'],'distribution')
 need(set(actual)==set(pins)|{'CURRENT_DISTRIBUTION_MANIFEST.json'} and len(actual)==319,'exact file roster')
 for name,row in pins.items():
  hh=hashlib.sha256()
  with actual[name].open('rb') as f:
   for block in iter(lambda:f.read(1024*1024),b''):hh.update(block)
  need(actual[name].stat().st_size==row['bytes'] and hh.hexdigest()==row['sha256'],'file identity '+name)
 modified=set(m['modified_existing_files']);added=set(m['added_files'])
 preserved=h.pin_rows(m['preserved_file_pins'],'preserved')
 need(len(modified)==7 and len(added)==5 and not m['removed_files'],'change scope')
 need(set(preserved)==set(actual)-modified-added and len(preserved)==307,'preserved roster')
 for n,row in preserved.items():need(row==pins[n],'preserved pin '+n)
 downloads=sorted(n for n in actual if n.startswith(('archives/','documents/')))
 need(len(downloads)==26 and sum(n.startswith('archives/') for n in downloads)==16,'download counts')
 need(read('SHA256SUMS').decode()==''.join(pins[n]['sha256']+'  '+n+'\n' for n in downloads),'download checksums')
 idx=h.decode(read('EVIDENCE_READER_INDEX.json'))
 need(read('EVIDENCE_READER_INDEX.json')==read('CLAIM_TO_FILE_INDEX.json'),'index mirrors')
 need(len(idx['rows'])==idx['reader_row_count']==28 and len(idx['extensions'])==13,'index counts')
 need(objects(idx['rows'][:27])==ROWS_SHA and objects(idx['extensions'][:12])==EXT_SHA,'old index objects unchanged')
 need(idx['rows'][-1]['id']=='vehicle188-whole-region' and idx['current_distribution']['tags']==[TAG],'new reader identity')
 d=h.decode(read('VEHICLE188_WHOLE_REGION_EVIDENCE_MANIFEST.json'))
 need(d['version_tag']==TAG,'descriptor identity')
 ap=d['archive'];h.verify_pin(read(ap['path']),ap)
 members=h.pin_rows(d['members'],'archive members')
 with zipfile.ZipFile(actual[ap['path']]) as z:
  need(z.testzip() is None and len(z.namelist())==len(set(z.namelist()))==60 and set(z.namelist())==set(members),'archive roster/CRC')
  for name,row in members.items():
   h.safe(name);need(name.startswith(TAG+'/'),'archive root');h.verify_pin(z.read(name),row)
  need(d['internal_manifest']['sha256']=='c70ebc8d72b5ff9c423dcc678c9858c686397d4bf13f4747d7f6b5066e94e07c','accepted inner manifest')
  inner=h.decode(z.read(TAG+'/MANIFEST.json'))
  ip=h.pin_rows(inner['files'],'inner files')
  need({TAG+'/'+n for n in ip}|{TAG+'/MANIFEST.json'}==set(members),'inner exact roster')
  for n,row in ip.items():h.verify_pin(z.read(TAG+'/'+n),row)
  for key in ('input_navigation','input_models','saved_outputs','checkers'):
   for n in idx['rows'][-1].get(key,[]):need(TAG+'/'+n in members,'reader reference '+n)
 need(read('VEHICLE188_WHOLE_REGION_CITATION.bib')==zipped_citation(actual[ap['path']]),'citation identity')
 return dict(status='PASS_WHOLE_REGION_DISTRIBUTION_INTEGRITY_ONLY',repository_files=319,scientific_archives=16,historical_document_downloads=10,reader_rows=28,archive_members=60,scientific_payload_executed=False)
def zipped_citation(path):
 with zipfile.ZipFile(path) as z:return z.read(TAG+'/CITATION.bib')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--repository',type=Path,default=Path(__file__).resolve().parent.parent);p.add_argument('--overlay',type=Path);a=p.parse_args();print(json.dumps(verify(a.repository.resolve(),a.overlay.resolve() if a.overlay else None),indent=2))
