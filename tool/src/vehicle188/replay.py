#!/usr/bin/env python3
"""Bounded, offline dual replay of immutable saved Vehicle188 evidence."""
import argparse
import ast
import contextlib
import csv
import datetime
import encodings.ascii
import hashlib
import io
import itertools
import json
import math
import os
from pathlib import Path
import resource
import signal
import socket
import sys
import threading
import time
import types
from functools import lru_cache


def need(value, label):
    if not value:
        raise ValueError(label)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(path.read_text())


def dump(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def verify_files(bundle):
    manifest = read_json(bundle / 'MANIFEST.json')
    rows = manifest['files']
    names = [row['path'] for row in rows]
    need(len(names) == len(set(names)), 'duplicate manifest path')
    actual = {p.relative_to(bundle).as_posix() for p in bundle.rglob('*') if p.is_file()}
    need(actual == set(names) | {'MANIFEST.json'}, 'exact immutable package file roster')
    need(not any(p.is_symlink() for p in bundle.rglob('*')), 'no symbolic links in package')
    for row in rows:
        rel = Path(row['path'])
        need(not rel.is_absolute() and '..' not in rel.parts, 'safe relative manifest path')
        p = bundle / rel
        need(p.resolve().is_relative_to(bundle), 'input remains within bundle')
        data = p.read_bytes()
        need(len(data) == row['bytes'] and sha(data) == row['sha256'], 'file checksum: ' + row['path'])
    for arm in ['original', 'released']:
        m = read_json(bundle / 'data/native/arms' / arm / 'native_result/model.json')
        for ref in list(m['original_bdds'].values()) + [v for refs in m['original_justices'].values() for v in refs]:
            need(Path(ref['file']).name == ref['file'] and ref['file'].endswith('.bdd'), 'predicate input is a local BDD filename')
    return len(rows) + 1


def check_core_identity(bundle):
    bindings = read_json(bundle / 'TRANSFORMATIONS.json')['mathematical_core_bindings']
    programs = {n: (bundle / n).read_text() for n in ['producer_core.py', 'independent_core.py']}
    parsed = {}
    for name, source in programs.items():
        lines = source.splitlines(keepends=True)
        parts = {}
        for node in ast.parse(source).body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                start = min([node.lineno] + [d.lineno for d in node.decorator_list])
                parts[node.name] = ''.join(lines[start - 1:node.end_lineno])
        parsed[name] = (source, lines, parts)
    checked = []
    for row in bindings:
        name = row['name']
        if row['operation'] == 'byte_identical_body_extraction':
            found = [part[name] for _, _, part in parsed.values() if name in part]
            need(len(found) == 1 and sha(found[0].encode()) == row['exact_utf8_sha256'], 'exact adopted mathematical body: ' + name)
        elif name.startswith('producer_main_'):
            source, lines, _ = parsed['producer_core.py']
            node = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'run')
            if name == 'producer_main_mathematical_statements':
                first = next(n.lineno for n in node.body if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name) and n.value.func.id == 'qualify')
                last = next(n.lineno for n in node.body if isinstance(n, ast.Return)) - 1
                block = ''.join(lines[first - 1:last])
            else:
                ret = next(n for n in node.body if isinstance(n, ast.Return))
                block = ''.join(lines[ret.lineno - 1:ret.end_lineno])
            need(sha(block.encode()) == row['exact_utf8_sha256'], 'exact adopted mathematical block: ' + name)
        elif name == 'independent_main':
            block = parsed['independent_core.py'][2]['main']
            need(sha(block.encode()) == row['portable_utf8_sha256'], 'independent main with documented I/O-only edits')
        else:
            raise ValueError('unknown mathematical core binding')
        checked.append(name)
    return checked


def install_guards(bundle, out):
    def hook(event, args):
        if event.startswith('socket.') or event in {'subprocess.Popen', 'os.system', 'os.posix_spawn', 'os.spawn', 'os.exec'}:
            raise PermissionError('network and subprocess calls are disabled for saved replay')
        if event == 'open':
            file, mode, flags = args
            if isinstance(file, int):
                return
            path = Path(os.fsdecode(file)).resolve()
            write = (isinstance(mode, str) and any(c in mode for c in 'wax+')) or bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            if write:
                if not path.is_relative_to(out):
                    raise PermissionError('writes are restricted to the fresh replay output')
            elif not (path.is_relative_to(bundle) or path.is_relative_to(out)):
                raise PermissionError('reads are restricted to the package and replay output')
    sys.addaudithook(hook)
    tested = {}
    probes = {
        'outside_read_denied': lambda: open(out.parent / '__forbidden_replay_read_probe__', 'rb'),
        'bundle_write_denied': lambda: open(bundle / 'README.txt', 'a'),
        'network_creation_denied': lambda: socket.socket(),
    }
    for label, action in probes.items():
        try:
            value = action()
        except PermissionError:
            tested[label] = True
        else:
            if hasattr(value, 'close'):
                value.close()
            raise ValueError('boundary probe unexpectedly permitted: ' + label)
    return tested


def load_core(bundle, filename):
    source = (bundle / filename).read_text()
    module = types.ModuleType(filename[:-3])
    module.__file__ = str(bundle / filename)
    exec(compile(source, filename, 'exec'), module.__dict__)
    return module


def compare_table_files(bundle, out):
    pairs = [
        ('producer/state_table.tsv', 'records/producer/state_table.tsv'),
        ('producer/environment_all_clear.tsv', 'records/producer/environment_all_clear.tsv'),
        ('independent/all_source_states.csv', 'records/independent_audit/all_source_states.csv'),
        ('independent/all_W_fixed_predecessors.csv', 'records/independent_audit/all_W_fixed_predecessors.csv'),
    ]
    rows = []
    for actual, historical in pairs:
        data, expected = (out / actual).read_bytes(), (bundle / historical).read_bytes()
        need(data == expected, 'exact full table matches adopted evidence: ' + actual)
        rows.append(dict(output=actual, adopted=historical, bytes=len(data), sha256=sha(data), byte_identical=True))
    names = ['pedestrianFirstLane', 'pedestrianSecondLane', 'pedestrianThirdLane', 'greenLightFirstLane', 'greenLightSecondLane', 'greenLightThirdLane', 'obstacleFirstLane', 'obstacleSecondLane', 'obstacleThirdLane', 'crosswalk', 'currentLane', 'speed']
    with (out / 'producer/state_table.tsv').open(newline='') as f:
        producer = list(csv.DictReader(f, delimiter='\t'))
    by_values = {tuple(r[n] for n in names): r for r in producer}
    need(len(producer) == len(by_values) == 33792, 'unique complete producer state roster')
    with (out / 'independent/all_source_states.csv').open(newline='') as f:
        independent = list(csv.DictReader(f))
    seen = set()
    independent_w_ids = set()
    loss_count = 0
    for row in independent:
        key = tuple(row[n] for n in names)
        need(key in by_values and key not in seen, 'independent named valuation correspondence')
        seen.add(key)
        other = by_values[key]
        for left, right in [('W', 'original_W'), ('WF', 'released_false_W'), ('WT', 'released_true_W'), ('loss', 'loss'), ('gain', 'gain')]:
            need(other[left] == row[right], 'cross-implementation membership correspondence')
        if row['original_W'] == '1':
            independent_w_ids.add(row['state_id'])
            need(all(other[n] == '1' for n in ['pred_thetaE', 'pred_thetaS', 'pred_W', 'rhoE_pred_target', 'rhoS_pred_target', 'source_rhoE_pred_target', 'source_rhoS_pred_target']), 'producer full fixed predecessor obligation')
            loss_count += int(row['loss'])
    need(seen == set(by_values) and len(independent_w_ids) == 8064 and loss_count == 1408, 'full 33792-row and W/loss correspondence')
    with (out / 'independent/all_W_fixed_predecessors.csv').open(newline='') as f:
        preds = list(csv.DictReader(f))
    need(len(preds) == 8064 and {r['state_id'] for r in preds} == independent_w_ids, 'complete independent predecessor target roster')
    need(all(all(r[k] == '1' for k in ['predecessor_initial', 'predecessor_W', 'rhoE', 'rhoS', 'target_W', 'all_pass']) for r in preds), 'independent full fixed predecessor checks')
    return dict(table_files=rows, named_states=33792, membership_fields_per_state=5, mismatches=0, W_predecessors=8064, loss_predecessors=1408)


def main():
    need(__debug__ and sys.flags.optimize == 0, 'optimized Python is unsupported because adopted core asserts must execute')
    parser = argparse.ArgumentParser()
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    bundle, out = args.bundle.resolve(), args.out.resolve()
    need(bundle.is_dir(), 'bundle directory exists')
    need(not out.exists() and not out.is_relative_to(bundle) and not bundle.is_relative_to(out), 'fresh external nonancestor output directory')
    need(out.parent.is_dir(), 'output parent exists')
    start = time.monotonic()
    file_count = verify_files(bundle)
    identities = check_core_identity(bundle)
    out.mkdir()
    (out / 'producer').mkdir()
    (out / 'independent').mkdir()
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('fresh replay 180-second wall cap')))
    signal.alarm(180)
    stop = threading.Event()
    def guard():
        while not stop.wait(0.02):
            rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            rss = rss if sys.platform == 'darwin' else rss * 1024
            if rss > 1024**3:
                os._exit(86)
            if sum(p.stat().st_size for p in out.rglob('*') if p.is_file()) > 32*1024**2:
                os._exit(87)
    threading.Thread(target=guard, daemon=True).start()
    boundaries = install_guards(bundle, out)
    producer = load_core(bundle, 'producer_core.py')
    producer.initialize(bundle, out / 'producer')
    p = producer.run()
    p['status'] = 'PASS_PORTABLE_PRODUCER'
    if sys.platform != 'darwin':
        p['peak_rss_bytes'] *= 1024
    dump(out / 'producer/RESULT.json', p)
    expected = read_json(bundle / 'records/producer/RESULT.json')
    pkeys = ['counts', 'original_initializer', 'environment_certificate', 'fixed_predecessors', 'failed_checks', 'mask_byte_sha256', 'enumeration_order', 'enumeration_values', 'examples']
    for key in pkeys:
        need(p[key] == expected[key], 'producer scientific result equals adopted record: ' + key)
    need(all(c['passed'] for c in p['checks']), 'all producer replay checks pass')
    independent = load_core(bundle, 'independent_core.py')
    independent.initialize(bundle, out / 'independent')
    stream = io.StringIO()
    with contextlib.redirect_stdout(stream):
        independent.main()
    (out / 'independent/stdout.txt').write_text(stream.getvalue())
    i = read_json(out / 'independent/AUDIT_RESULT.json')
    old_i = read_json(bundle / 'records/independent_audit/AUDIT_RESULT.json')
    ikeys = ['status', 'counts', 'joint_membership_cells_original_false_true', 'failure_counts', 'failures', 'fixed_predecessors', 'all_clear', 'initial_quantifier', 'source_semantic_checks_all_pass', 'independence']
    for key in ikeys:
        need(i[key] == old_i[key], 'independent scientific result equals adopted record: ' + key)
    need(i['status'] == 'PASS', 'independent replay PASS')
    for name in ['SOURCE_SEMANTIC_IDENTITY.json', 'INITIAL_RESPONSE_FIBERS.json']:
        need(read_json(out / 'independent' / name) == read_json(bundle / 'records/independent_audit' / name), 'independent exact semantic result: ' + name)
    tables = compare_table_files(bundle, out)
    need(verify_files(bundle) == file_count, 'immutable package unchanged after dual replay')
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    rss = rss if sys.platform == 'darwin' else rss * 1024
    output_bytes = sum(p.stat().st_size for p in out.rglob('*') if p.is_file())
    need(rss <= 1024**3 and output_bytes < 32*1024**2 and time.monotonic()-start < 180, 'fresh replay remains within resource caps')
    result = dict(schema='vehicle188-whole-region-dual-replay-v1', status='PASS_WHOLE_REGION_DUAL_REPLAY', created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), package_manifest=dict(bytes=(bundle/'MANIFEST.json').stat().st_size, sha256=sha((bundle/'MANIFEST.json').read_bytes())), verified_package_files=file_count, mathematical_body_checks=identities, boundary_checks=boundaries, producer_scientific_fields_equal_adopted=pkeys, independent_scientific_fields_equal_adopted=ikeys, tables=tables, counts=p['counts'], source_predicate_equivalence=i['source_semantic_checks_all_pass'], initialized_environment_fibers=1024, limits=dict(wall_seconds=180, RSS_bytes=1024**3, output_bytes=32*1024**2), usage=dict(elapsed_seconds=time.monotonic()-start, peak_RSS_bytes=rss, output_bytes_before_summary=output_bytes), native_solver_invocations=0, game_fixed_point_invocations=0, network_requests=0, historical_deadline_used_as_replay_gate=False, trust_boundary='Saved native W evaluated; native solver/exporter/maps remain shared dependencies. Per-target policy existence, not one common or deployed policy.')
    dump(out / 'REPLAY_RESULT.json', result)
    stop.set()
    signal.alarm(0)
    print(json.dumps(dict(status=result['status'], counts=result['counts'], named_state_comparison=tables['named_states'], elapsed_seconds=result['usage']['elapsed_seconds']), ensure_ascii=False))


if __name__ == '__main__':
    main()
