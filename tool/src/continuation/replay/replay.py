#!/usr/bin/env python3
"""Portable saved evidence verification. Python standard library; no native calls."""
from pathlib import Path
import argparse
import datetime
import hashlib
import importlib.util
import json
import sys
import time
import traceback

sys.dont_write_bytecode = True
if sys.flags.optimize:
    raise RuntimeError('Optimized Python is unsupported: saved auditors require assertions. Run without -O/-OO and unset PYTHONOPTIMIZE.')

def sha(data): return hashlib.sha256(data).hexdigest()
def need(ok, label):
    if not ok: raise AssertionError(label)
def save(path, value): path.write_text(json.dumps(value, indent=2) + '\n')
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    obj = importlib.util.module_from_spec(spec)
    sys.modules[name] = obj
    spec.loader.exec_module(obj)
    return obj

class Bundle:
    def __init__(self, root):
        self.root = root.resolve()
        self.ledger = json.loads((self.root / 'INPUT_LEDGER.json').read_text())
        self.by_alias = {r['source_alias']: r for r in self.ledger['files']}
        self.by_package = {str((self.root / r['package_path']).resolve()): r for r in self.ledger['files']}
        self.read_anchors = {}
    def verify(self):
        man = json.loads((self.root / 'MANIFEST.json').read_text())
        count = 0
        for row in man['files']:
            p = (self.root / row['path']).resolve()
            need(p.is_relative_to(self.root), 'manifest path stays inside bundle')
            raw = p.read_bytes()
            need(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'bundle checksum: '+row['path'])
            count += 1
        for row in self.ledger['files']:
            p = self.root / row['package_path']
            raw = p.read_bytes()
            need(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'input ledger checksum: '+row['package_path'])
        return dict(status='PASS_TRANSPORT_IDENTITY_ONLY',manifest_files=count,input_files=len(self.ledger['files']))
    def resolve(self, value):
        name = str(value)
        if name.startswith('<WORKSPACE>/'):
            need(name in self.by_alias, 'file must be an included ledger input: '+name)
            return self.root / self.by_alias[name]['package_path']
        p = Path(name).resolve()
        need(p.is_relative_to(self.root), 'read path stays inside bundle')
        return p
    def relocate(self, obj):
        if isinstance(obj, str) and obj in self.by_alias:
            return str(self.root / self.by_alias[obj]['package_path'])
        if isinstance(obj, dict): return {k:self.relocate(v) for k,v in obj.items()}
        if isinstance(obj, list): return [self.relocate(v) for v in obj]
        return obj
    def pin(self, value):
        p = self.resolve(value)
        raw = p.read_bytes()
        row = dict(path=str(p.relative_to(self.root)),bytes=len(raw),sha256=sha(raw))
        self.read_anchors[row['path']] = row
        return row
    def read(self, value):
        p = self.resolve(value)
        self.pin(p)
        return self.relocate(json.loads(p.read_text()))
    def read_jsonl(self, value):
        p = self.resolve(value)
        self.pin(p)
        return self.relocate([json.loads(line) for line in p.read_text().splitlines() if line.strip()])

def raw_module(bundle):
    obj = module('audit_native_certificates', bundle.root / 'data/evidence/native/independent_audit/audit_native_certificates.py')
    obj.ROOT = bundle.root / 'data'
    obj.EXP = bundle.root / 'data/evidence/native'
    obj.CERT = bundle.root / 'data/support/primary277/execution/finite_certificates_01'
    obj.anchors.clear()
    return obj

def patrol(bundle):
    raw = raw_module(bundle)
    boundary = raw.loadjson(raw.CERT / 'BOUNDARY.json')
    old = raw.Model('old-original')
    new = raw.Model('new-original')
    released = raw.Model('new-released')
    raw.require(old.test('thetaE',boundary['initial']) and old.test('thetaS',boundary['initial']),'old initializer')
    raw.require(old.test('rhoE',boundary['initial'],boundary['boundary']) and old.test('rhoS',boundary['initial'],boundary['boundary']),'native actual BOOT')
    raw.require(boundary['initial']['request']=='S0' and boundary['boundary']['request']=='S2','pending monitor carried')
    raw.require(not new.test('thetaS',boundary['boundary']),'pending root is noninitial')
    result = dict(old_graph=raw.audit_graph(old,'OLD_GRAPH',boundary),
                  new_graph=raw.audit_graph(new,'NEW_GRAPH',boundary),
                  countercertificate=raw.audit_counter(new,released,boundary))
    module('audit_explicit_slice', bundle.root / 'data/evidence/native/independent_audit/audit_explicit_slice.py')
    quad = module('audit_native_quadrants_v2', bundle.root / 'data/evidence/native/independent_audit/audit_native_quadrants_v2.py')
    result['actual_new_quadrants'] = quad.audit('new')
    counter = result['countercertificate']
    need((counter['states'],counter['nonexit_rows'],counter['all_safe_replies']) == (26,25,103),'frozen actual-export countercertificate counts')
    q = result['actual_new_quadrants']
    need(q['F_equals_C'] and q['helper_trap']['U_equals_full_D'] and q['all_source_AUX_retained'],'actual-new retained-constraint premises')
    result.update(status='PASS_SAVED_ACTUAL_EXPORT_CERTIFICATE_AND_NEW_PREMISES',
                  boundary=dict(initial_request='S0',pending_request='S2',new_root_fails_initializer=True),
                  file_hash_anchors=raw.anchors,
                  trust_boundary='Native compiler/exporter and typed field encoding metadata; this replay independently parses saved native tables and checks finite certificates.',
                  full_helper_native_query='UNKNOWN_NOT_RETRIED',native_calls=0)
    return result

def manager(bundle):
    original = module('preserved_manager_auditor', bundle.root / 'data/evidence/lift_manager_loop/independent_audit/audit_manager.py')
    original.read = bundle.read
    original.pin = bundle.pin
    derived = module('portable_manager_semantics', bundle.root / 'manager_semantics.py')
    # Retain exact helper implementations; all filesystem entry points are bound
    # to this bundle. The extracted audit suffix is preserved in its source file.
    for name, value in vars(original).items():
        if not name.startswith('__'): setattr(derived,name,value)
    derived.EXP = bundle.root / 'data/evidence/lift_manager_loop'
    derived.P58 = bundle.root / 'data/support/external/experiment/v58_submission_20261023/pending_handoff'
    derived.read = bundle.read
    derived.read_jsonl = bundle.read_jsonl
    derived.pin = bundle.pin
    result = derived.audit_saved_manager()
    need(result['event_count']==69 and len(result['episodes'])==3,'frozen manager event/boundary counts')
    need(sum(r['post_update_commits'] for r in result['episodes'])==36,'frozen manager commit count')
    result.update(status='PASS_SAVED_MANAGER_GRAPH_EVENT_AND_TYPED_TABLES',
                  bytecode_cache_checks=None,
                  historical_runtime_source_pin_rechecks='OMITTED_SEE_OMITTED_HISTORICAL_CHECKS.json',
                  checks=original.checks,
                  scope=['Independent saved finite graph coverage, safety, SCC, source-predicate truth-table and event-sequence verification.',
                         'One observed execution is evidence in saved records; no manager worker is reexecuted by this replay.',
                         'Native exporter/encoding and process-provenance records remain trusted.'])
    return result

def reduced(bundle):
    raw = raw_module(bundle)
    derived = module('portable_reduced_semantics', bundle.root / 'reduced_semantics.py')
    derived.EXP = bundle.root / 'data/evidence/native_reduced_query'
    derived.PRIOR = bundle.root / 'data/evidence/native'
    derived.raw = raw
    derived.read = bundle.read
    checks = []
    def check(ok, label, detail=None):
        checks.append(dict(check=label,passed=bool(ok),detail=detail))
        need(ok,label)
    derived.need = check
    result = derived.audit_saved_reduced_query()
    need(result['native_region_counts']['Q']==1152 and result['native_region_counts']['FQ']==1104,'frozen native region counts')
    result.update(checks=checks,file_hash_anchors=raw.anchors,
                  historical_runtime_source_pin_rechecks='OMITTED_SEE_OMITTED_HISTORICAL_CHECKS.json',
                  full_helper_native_query='UNKNOWN_NOT_RETRIED',
                  trust_boundary='Saved native winning region, native exporter and typed field metadata. Full membership binding is recomputed; native winning fixed point is not recomputed.')
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--stages',nargs='+',choices=['patrol','manager','reduced'],default=['patrol','manager','reduced'])
    args = parser.parse_args()
    out = args.out.resolve()
    need(not out.exists() or not any(out.iterdir()), 'output directory must be new or empty')
    out.mkdir(parents=True,exist_ok=True)
    start = time.monotonic()
    summary = dict(schema='v65-portable-saved-evidence-replay-v1',status='RUNNING',
                   started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   stages_requested=args.stages,stages={},native_calls=0,controller_extractions=0,
                   manager_worker_reruns=0,full_reset_uses=0,network_requests=0,
                   provenance_scope='Saved scientific semantics plus transport identity. Omitted historical runtime/source pins are not replaced by transport identity.')
    bundle = None
    try:
        bundle = Bundle(args.bundle)
        summary['transport'] = bundle.verify()
        for stage in args.stages:
            stage_start = time.monotonic()
            result = globals()[stage](bundle)
            result['replay_elapsed_seconds'] = time.monotonic()-stage_start
            save(out / (stage.upper() + '_REPLAY.json'),result)
            summary['stages'][stage] = dict(status=result['status'],elapsed_seconds=result['replay_elapsed_seconds'])
            print(stage, result['status'], flush=True)
        summary['status']='PASS_PORTABLE_SAVED_EVIDENCE'
    except BaseException as exc:
        summary.update(status='FAIL_PORTABLE_SAVED_EVIDENCE',error=repr(exc),traceback=traceback.format_exc())
        print(summary['traceback'],file=sys.stderr,flush=True)
    summary['elapsed_seconds']=time.monotonic()-start
    if bundle is not None: summary['read_anchors']=list(bundle.read_anchors.values())
    save(out / 'REPLAY_RESULT.json',summary)
    print(json.dumps({k:summary[k] for k in ('status','stages','elapsed_seconds')},indent=2),flush=True)
    return 0 if summary['status'].startswith('PASS') else 1

if __name__=='__main__': sys.exit(main())
