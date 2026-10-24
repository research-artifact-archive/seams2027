#!/usr/bin/env python3
"""Check saved distribution bytes; never execute a scientific payload."""
import argparse, hashlib, importlib.util, json, sys, zipfile
from pathlib import Path
sys.dont_write_bytecode=True
TAG='fixed-seven-native-evidence-20261024-v1'
PREFIX='fixed-seven-native/'
ROWS_SHA='0d851f8c2197bcf1833e2b8b274bab258e3d3d0f7e9ff8ddda1017abae286c82'
EXT_SHA='c326f393d74b98c58b3730e714f51c532fd3621289d12c3c85416705a5d087c7'
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
 need(m['schema']=='current-anonymous-distribution-v7' and m['version_tag']==TAG,'distribution identity')
 need(m['publication_mode']=='evidence-only' and m['scientific_executions_for_publication']==0,'publication scope')
 pins=h.pin_rows(m['files'],'distribution')
 need(set(actual)==set(pins)|{'CURRENT_DISTRIBUTION_MANIFEST.json'} and len(actual)==324,'exact file roster')
 for name,row in pins.items():
  hh=hashlib.sha256()
  with actual[name].open('rb') as f:
   for block in iter(lambda:f.read(1024*1024),b''):hh.update(block)
  need(actual[name].stat().st_size==row['bytes'] and hh.hexdigest()==row['sha256'],'file identity '+name)
 modified=set(m['modified_existing_files']);added=set(m['added_files'])
 preserved=h.pin_rows(m['preserved_file_pins'],'preserved')
 need(len(modified)==7 and len(added)==5 and not m['removed_files'],'change scope')
 need(set(preserved)==set(actual)-modified-added and len(preserved)==312,'preserved roster')
 for n,row in preserved.items():need(row==pins[n],'preserved pin '+n)
 downloads=sorted(n for n in actual if n.startswith(('archives/','documents/')))
 need(len(downloads)==27 and sum(n.startswith('archives/') for n in downloads)==17,'download counts')
 need(read('SHA256SUMS').decode()==''.join(pins[n]['sha256']+'  '+n+'\n' for n in downloads),'download checksums')
 idx=h.decode(read('EVIDENCE_READER_INDEX.json'))
 need(read('EVIDENCE_READER_INDEX.json')==read('CLAIM_TO_FILE_INDEX.json'),'index mirrors')
 need(len(idx['rows'])==idx['reader_row_count']==29 and len(idx['extensions'])==14,'index counts')
 need(objects(idx['rows'][:28])==ROWS_SHA and objects(idx['extensions'][:13])==EXT_SHA,'old index objects unchanged')
 need(idx['rows'][-1]['id']=='fixed-seven-native' and idx['current_distribution']['tags']==[TAG],'new reader identity')
 d=h.decode(read('FIXED_SEVEN_NATIVE_EVIDENCE_MANIFEST.json'))
 need(d['version_tag']==TAG,'descriptor identity')
 ap=d['archive'];h.verify_pin(read(ap['path']),ap)
 members=h.pin_rows(d['members'],'archive members')
 with zipfile.ZipFile(actual[ap['path']]) as z:
  need(z.testzip() is None and len(z.namelist())==len(set(z.namelist()))==882 and set(z.namelist())==set(members),'archive roster/CRC')
  for name,row in members.items():
   h.safe(name);need(name.startswith(PREFIX),'archive root');h.verify_pin(z.read(name),row)
  need(d['internal_manifest']['sha256']=='44961086d2fdddf7db4272a9001e8f83abbb15a1debe7d931a7d2f2c589f2fe3','accepted inner manifest')
  h.verify_pin(z.read(PREFIX+'MANIFEST.json'),d['internal_manifest'])
  inner=h.decode(z.read(PREFIX+'MANIFEST.json'))
  ip=h.pin_rows(inner['files'],'inner files')
  need({PREFIX+n for n in ip}|{PREFIX+'MANIFEST.json'}==set(members),'inner exact roster')
  for n,row in ip.items():h.verify_pin(z.read(PREFIX+n),row)
  for key in ('input_navigation','input_models','saved_outputs','checkers'):
   for n in idx['rows'][-1].get(key,[]):need(PREFIX+n in members,'reader reference '+n)
 h.verify_pin(read('FIXED_SEVEN_NATIVE_CITATION.bib'),d['citation'])
 q=d['saved_replay_qualification']
 need(objects(q)=='321676e73ee77be3be6f053beaa0bcd7d13b42bf5a62dee86e88e971e0707a13','accepted saved qualification identity')
 need(q['status']=='PASS' and q['fixed_cases']==7 and q['native_calls']==q['retry_count']==0,'qualification scope')
 need(q['math_core_sha256']=='bf92749b52f83ba79e1ae8723eaf23fee94943d9e5f023f997c0206dd50e9fc2','qualified core')
 need([r['case'] for r in q['case_results']]==['corpus'+n+'__original' for n in ('039','040','041','135','148','150','187')],'qualified fixed roster')
 for r in q['case_results']:
  need(r['status']=='PASS' and r['full_audit_object_equal'] and r['typed_csv_equal'] and r['native_calls']==0,'qualified case outputs')
  need(r['elapsed_seconds']<=120 and r['max_RSS_bytes']<=1073741824,'qualified resource caps')
 return dict(status='PASS_FIXED_SEVEN_DISTRIBUTION_INTEGRITY_ONLY',repository_files=324,scientific_archives=17,historical_document_downloads=10,reader_rows=29,archive_members=882,scientific_payload_executed=False)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--repository',type=Path,default=Path(__file__).resolve().parent.parent);p.add_argument('--overlay',type=Path);a=p.parse_args();print(json.dumps(verify(a.repository.resolve(),a.overlay.resolve() if a.overlay else None),indent=2))
