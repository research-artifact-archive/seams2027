#!/usr/bin/env python3
"""Portable I/O and bounded orchestration around the unchanged saved-data core.

Only the Python standard library is used. No native solver is invoked.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True
import independent_auditor as core

HERE = Path(__file__).resolve().parent
IDS = ['corpus' + n + '__original' for n in ('039', '040', '041', '135', '148', '150', '187')]
LIMIT = 1073741824


def read(path):
    return json.loads(Path(path).read_text())


def write(path, obj):
    with Path(path).open('x') as stream:
        json.dump(obj, stream, indent=2)
        stream.write('\n')


def local(name):
    p = HERE / name
    core.require(not Path(name).is_absolute() and p.resolve().is_relative_to(HERE), 'nonportable payload reference')
    return p


def verify_manifest():
    manifest = read(HERE / 'MANIFEST.json')
    actual = {str(p.relative_to(HERE)) for p in HERE.rglob('*') if p.is_file()}
    expected = {row['path'] for row in manifest['files']} | {'MANIFEST.json'}
    core.require(actual == expected, 'payload member roster changed')
    for row in manifest['files']:
        p = local(row['path'])
        core.require(p.stat().st_size == row['bytes'] and core.sha(p) == row['sha256'], 'payload manifest mismatch: ' + row['path'])
    return manifest


def bind_case(case_id):
    case = read(HERE / 'cases' / case_id / 'case.json')
    core.require(case['id'] == case_id, 'case identity')
    for row in case['source_and_imports']:
        p = local(row['path'])
        core.require(p.stat().st_size == row['bytes'] and core.sha(p) == row['sha256'], 'unchanged source/import hash')
    source_sha = case['source']['sha256']
    for folder in ('old', 'original/native_result', 'route/native_result'):
        model = read(HERE / 'cases' / case_id / folder / 'model.json')
        core.require(model['input']['sha256'] == source_sha, 'old/native source hash binding')
    for mode in ('original', 'route'):
        arm = HERE / 'cases' / case_id / mode
        process = read(arm / 'PROCESS.json')
        result = read(arm / 'native_result/RESULT.json')
        core.require(process['returncode'] == 0 and not process['reasons'] and not process['remaining_owned_processes'], 'saved producer incomplete')
        core.require(process['status'] == 'COMPLETE_CANDIDATE_REQUIRES_INDEPENDENT_AUDIT', 'saved producer status')
        core.require(result['input_sha256'] == source_sha, 'native result source hash')
        core.require(result['helper_introduced'] == (mode == 'route' and case['expected_helper_introduced_on_route']), 'helper activation differs')
        core.require(result['conversion_skipped'] == (mode == 'route' and not case['expected_helper_introduced_on_route']), 'released skip differs')
        core.require(result['teardown'] == 'COMPLETED', 'native teardown')
    # The only adaptation made to the qualified audit invocation is resolving
    # these two data-location fields in memory. Mathematical code is unchanged.
    resolved = copy.deepcopy(case)
    resolved['saved_original_directory'] = str(local(case['saved_original_directory']))
    resolved['derived_regions']['path'] = str(local(case['derived_regions']['path']))
    return resolved


def worker(case_id, output):
    started = time.monotonic()
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('saved replay 120-second cap')))
    signal.alarm(120)
    output.mkdir(parents=True, exist_ok=False)
    write(output / 'RESERVATION.json', {'case': case_id, 'native_calls': 0, 'wall_cap_seconds': 120, 'RSS_cap_bytes': LIMIT})
    def guard():
        while True:
            raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            rss = raw if sys.platform == 'darwin' else raw * 1024
            if rss > LIMIT or sum(p.stat().st_size for p in output.parent.rglob('*') if p.is_file()) > LIMIT:
                os._exit(86)
            time.sleep(.02)
    threading.Thread(target=guard, daemon=True).start()
    try:
        verify_manifest()
        case = bind_case(case_id)
        folders = [HERE / 'cases' / case_id / mode / 'native_result' for mode in ('original', 'route')]
        result = core.audit_saved_case(case, folders[0], folders[1], output / 'audit')
        expected = read(HERE / 'cases' / case_id / 'expected/AUDIT_RESULT.json')
        core.require(read(output / 'audit/AUDIT_RESULT.json') == expected, 'replay differs from independently adopted full audit result')
        expected_csv = read(HERE / 'cases' / case_id / 'expected/CSV_PIN.json')
        csv = output / 'audit/ALL_TYPED_STATES.csv'
        core.require(csv.stat().st_size == expected_csv['bytes'] and core.sha(csv) == expected_csv['sha256'], 'all typed rows differ')
        raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        receipt = {'case': case_id, 'status': 'PASS', 'counts': result['counts'], 'full_audit_object_equal': True, 'typed_csv_equal': True, 'native_calls': 0, 'elapsed_seconds': time.monotonic() - started, 'max_RSS_bytes': raw if sys.platform == 'darwin' else raw * 1024}
        core.require(receipt['elapsed_seconds'] <= 120 and receipt['max_RSS_bytes'] <= LIMIT, 'worker final resource cap')
        write(output / 'REPLAY_RESULT.json', receipt)
        return 0
    except BaseException as error:
        write(output / 'FIRST_FAILURE.json', {'status': 'FAIL', 'case': case_id, 'error': repr(error), 'native_calls': 0})
        return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='new directory outside the immutable payload')
    parser.add_argument('--worker', choices=IDS)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    core.require(not output.is_relative_to(HERE), 'output must be outside payload')
    if args.worker:
        return worker(args.worker, output)
    verify_manifest()
    output.mkdir(parents=True, exist_ok=False)
    write(output / 'REPLAY_RESERVATION.json', {'fixed_order': IDS, 'max_calls': 7, 'retry_count': 0, 'native_calls': 0, 'per_case_seconds': 120, 'RSS_bytes': LIMIT, 'total_output_bytes': LIMIT})
    results = []
    for case in IDS:
        started = time.monotonic()
        target = output / case
        with (output / (case + '.stdout.txt')).open('xb') as stdout, (output / (case + '.stderr.txt')).open('xb') as stderr:
            child = subprocess.Popen([sys.executable, '-B', str(HERE / 'replay.py'), '--worker', case, '--output', str(target)], stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                code = child.wait(timeout=120)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=2)
                code = -9
        process = {'case': case, 'returncode': code, 'wall_seconds': time.monotonic() - started, 'native_calls': 0}
        write(output / (case + '.PROCESS.json'), process)
        if code != 0 or sum(p.stat().st_size for p in output.rglob('*') if p.is_file()) > LIMIT:
            write(output / 'FIRST_FAILURE.json', {'status': 'STOPPED_FIRST_FAILURE', 'case': case, 'completed_cases': results, 'process': process, 'native_calls': 0})
            return 1
        result = read(target / 'REPLAY_RESULT.json')
        results.append(result)
        print(json.dumps({'case': case, 'status': result['status'], 'elapsed_seconds': result['elapsed_seconds']}), flush=True)
    write(output / 'REPLAY_SUMMARY.json', {'status': 'PASS', 'fixed_cases': 7, 'case_results': results, 'native_calls': 0, 'retry_count': 0, 'math_core_sha256': core.sha(HERE / 'independent_auditor.py'), 'scope': 'Saved-data consistency, typed membership, source-view correspondence and quantified initialization; no native regeneration or proof of solver correctness.'})
    return 0


if __name__ == '__main__':
    sys.exit(main())
