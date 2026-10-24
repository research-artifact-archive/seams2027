#!/usr/bin/env python3
"""Replay one saved Lift lasso; the fresh invocation has a maximum 60-second deadline."""
from pathlib import Path
import argparse
import datetime
import hashlib
import json
import signal
import sys
import time

sys.dont_write_bytecode = True
SavedDag = None
source = None


def check(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def safe(name):
    check(name and not name.startswith('/') and '\\' not in name
          and all(p not in ('', '.', '..') for p in name.split('/')), 'Unsafe member path')
    return name


def pin(raw, row):
    check(len(raw) == row['bytes'] and digest(raw) == row['sha256'],
          'Input pin mismatch: ' + row['path'])


def pointer(value, path):
    for component in path.split('/')[1:]:
        value = value[component.replace('~1', '/').replace('~0', '~')]
    return value


def evaluate(model, receipt, p, pinned, NATIVE, report, pins):
    fields = {row['name']: row for row in model['fields']}
    prefix = p['candidate']['prefix_state']
    loop = dict(prefix, **{'~envHelp': 'true'})
    check(set(prefix) == set(fields), 'Exact complete field roster')
    check(len(fields) == 11 and model['bdd_variable_count'] == 22, 'Fixed tiny fixture dimensions')
    report['states'] = {'prefix': prefix, 'loop': loop}

    def bits(state, primed=False):
        result = {}
        for name, value in state.items():
            field = fields[name]
            check(value in field['values'], 'Value outside field domain')
            mapping = field['encoding'][value]['next' if primed else 'current']
            for key, bit in mapping.items():
                check(int(key) not in result and type(bit) is bool, 'Non-disjoint Boolean encoding')
                result[int(key)] = bit
        expected = set(model['all_next_bits' if primed else 'all_current_bits'])
        check(set(result) == expected, 'Incomplete bit assignment')
        return result

    current = {name: bits(state) for name, state in [('prefix', prefix), ('loop', loop)]}
    next_bits = {name: bits(state, True) for name, state in [('prefix', prefix), ('loop', loop)]}
    loaded = {}

    def evaluate(ref, assignment):
        check(Path(ref['file']).name == ref['file'], 'Nonlocal BDD reference')
        raw = pinned(NATIVE / ref['file'])
        check(len(raw) == ref['bytes'] and digest(raw) == ref['sha256'], 'Model/receipt BDD pin mismatch')
        if ref['file'] not in loaded:
            loaded[ref['file']] = SavedDag(raw, model['bdd_variable_count'], model['bdd_variable_order'])
        dag = loaded[ref['file']]
        check(dag.support == set(ref['support']), 'BDD support mismatch')
        check(len(dag.nodes) == ref['node_count'], 'BDD node count mismatch')
        return dag.value(assignment)

    bdds = model['original_bdds']
    initial = {name: evaluate(bdds[name], current['prefix']) for name in ['thetaE', 'thetaS']}
    domains = {name: evaluate(bdds['domain'], current[name]) for name in current}
    edges = {}
    for start, end in [('prefix', 'loop'), ('loop', 'loop')]:
        assignment = dict(current[start], **{})
        assignment.update(next_bits[end])
        edges[start + '->' + end] = {
            name: evaluate(bdds[name], assignment)
            for name in ['rhoE', 'rhoS', 'domain_ENV_next', 'domain_SYS_next']}
    justice_sets = {'model': model['original_justices'],
                    'preconstructor': receipt['preconstructor_justices'],
                    'solver': receipt['solver_justices']}
    justice_truth = {}
    for stage, sets in justice_sets.items():
        check(len(sets['ENV']) == 1 and len(sets['SYS']) == 3, 'Fixed ordered justice roster')
        justice_truth[stage] = {
            owner: [{name: evaluate(ref, assignment) for name, assignment in current.items()} for ref in refs]
            for owner, refs in sets.items()}
    check(justice_truth['model'] == justice_truth['preconstructor'] == justice_truth['solver'],
          'Model/preconstructor/solver justice disagreement')
    for owner in ['ENV', 'SYS']:
        check(len({tuple(ref['sha256'] for ref in stage[owner]) for stage in justice_sets.values()}) == 1,
              'Ordered justice bytes differ across stages')

    source_checks = {
        'initial_ENV': source.lift_initial_env(prefix, False),
        'initial_SYS': source.lift_initial_sys(prefix),
        'initial_helper_false': prefix['~envHelp'] == 'false',
        'edges': {start + '->' + end: {
            'original_ENV_safety': source.lift_environment(s, t, False),
            'original_SYS_safety_and_monitors': source.lift_system(s, t),
            'helper_persistence': s['~envHelp'] == 'false' or t['~envHelp'] == 'true'}
            for start, end, s, t in [('prefix', 'loop', prefix, loop), ('loop', 'loop', loop, loop)]}}
    source_ok = all(source_checks[key] for key in ['initial_ENV', 'initial_SYS', 'initial_helper_false'])
    source_ok = source_ok and all(all(values.values()) for values in source_checks['edges'].values())
    arena_ok = all(initial.values()) and all(domains.values()) and all(all(edge.values()) for edge in edges.values())
    check(source_ok == arena_ok, 'Source/native disagreement for fixed lasso')
    sys_g = all(row['loop'] for row in justice_truth['solver']['SYS'])
    env_a = all(row['loop'] for row in justice_truth['solver']['ENV'])
    report.update({'initial_predicates': initial, 'state_domains': domains,
                   'edge_predicates': edges, 'justice_truth_by_stage': justice_truth,
                   'original_source_cross_check': source_checks,
                   'arena_lasso_legal': arena_ok, 'omega_SYS_G': sys_g, 'omega_ENV_A': env_a,
                   'status': 'POSITIVE' if arena_ok and sys_g and not env_a else 'NEGATIVE',
                   'verified_frozen_inputs': len(pins), 'evaluated_saved_DAGs': len(loaded),
                   'interpretation': 'For this exported transformed arena, the initialized trace prefix loop^omega has all SYS justices recurring and its sole ENV justice absent from the loop. It witnesses L(H,G) not subseteq L(H,A). This is not a returned-controller execution or a counterexample to a theorem with this inclusion as a hypothesis.',
                   'schema_caution': 'original_bdds/original_justices are legacy export names for the transformed native model in this run.'})
    return report


def replay(bundle, out, timeout):
    global SavedDag, source
    check(sys.flags.optimize == 0, 'Optimized Python is unsupported; use Python without -O/-OO')
    bundle, out = bundle.resolve(), out.resolve()
    check(bundle.is_dir() and not bundle.is_symlink(), 'Regular bundle directory required')
    check(not out.exists() and out != bundle and bundle not in out.parents,
          'Output must be a fresh directory outside the bundle')
    check(1 <= timeout <= 60, 'Fresh replay timeout must be in 1..60 seconds')
    out.mkdir(parents=True)
    started = datetime.datetime.now(datetime.timezone.utc)
    timer = time.monotonic()
    report = {'schema': 'anonymous-saved-lift-lasso-replay-v1',
              'started_utc': started.isoformat(), 'fresh_deadline_seconds': timeout,
              'historical_registration_deadline': 'Preserved as history; never reused as this replay deadline.',
              'phase': 'transport_integrity', 'native_solver_calls': 0,
              'controller_extractions': 0, 'arena_enumerations': 0,
              'candidate_lassos': 1, 'scientific_status': None,
              'original_25_pin_check_repeated': False,
              'source_text_and_final_region_rechecked': False}
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('Fresh replay deadline exceeded')))
    signal.alarm(timeout)
    try:
        manifest = json.loads((bundle / 'MANIFEST.json').read_text())
        check(manifest['schema'] == 'saved-lasso-replay-file-manifest-v1', 'Manifest schema')
        rows = manifest['files']
        names = [safe(r['path']) for r in rows]
        check(len(names) == len(set(names)), 'Duplicate manifest path')
        actual = set()
        for pth in bundle.rglob('*'):
            check(not pth.is_symlink(), 'Bundle symlink')
            if pth.is_file():
                actual.add(pth.relative_to(bundle).as_posix())
        check(actual == set(names) | {'MANIFEST.json'}, 'Complete bundle roster differs')
        transport = {r['path']: r for r in rows}
        for row in rows:
            pin((bundle / row['path']).read_bytes(), row)
        report['transport_files_checked'] = len(rows)
        report['tested_manifest_sha256'] = digest((bundle / 'MANIFEST.json').read_bytes())
        model = json.loads((bundle / 'data/model_projection.json').read_text())
        receipt = json.loads((bundle / 'data/justice_projection.json').read_text())
        report['phase'] = 'semantic_fixed_justice_roster'
        check(set(model) == {'fields', 'bdd_variable_count', 'bdd_variable_order', 'all_current_bits',
                            'all_next_bits', 'original_bdds', 'original_justices'}, 'Model projection key roster')
        check(set(receipt) == {'preconstructor_justices', 'solver_justices'}, 'Receipt projection key roster')
        for sets in [model['original_justices'], receipt['preconstructor_justices'], receipt['solver_justices']]:
            check(set(sets) == {'ENV', 'SYS'} and len(sets['ENV']) == 1 and len(sets['SYS']) == 3,
                  'Fixed ordered justice roster')
        report['fixed_justice_roster_checked'] = True
        report['phase'] = 'projection_binding'
        ledger = json.loads((bundle / 'BINDING_LEDGER.json').read_text())
        check(len(ledger['projection_files']) == 2 and ledger['selected_json_pointer_count'] == 9,
              'Projection ledger roster')
        compared = 0
        for item in ledger['projection_files']:
            values = json.loads((bundle / safe(item['public_path'])).read_text())
            pin((bundle / item['public_path']).read_bytes(), item['public_file'])
            check({r['pointer'][1:] for r in item['selected_values']} == set(values),
                  'Projection pointer coverage')
            for row in item['selected_values']:
                value_hash = digest(canonical(pointer(values, row['pointer'])))
                check(value_hash == row['source_value_canonical_sha256']
                      == row['public_value_canonical_sha256'], 'Selected JSON value differs: ' + row['pointer'])
                compared += 1
        check(compared == 9, 'Exactly nine projection values required')
        report['projection_values_checked'] = compared
        report['original_source_metadata_accessed'] = False
        report['projection_provenance_limit'] = 'The original-file SHA and source-value equality are packaging-time evidence. This replay checks public values against that ledger without accessing private originals.'
        sys.path.insert(0, str(bundle / 'code'))
        from independent_core import SavedDag as ImportedSavedDag
        import source_contracts as ImportedSource
        SavedDag, source = ImportedSavedDag, ImportedSource
        prereg = json.loads((bundle / 'history/LIFT_LASSO_PREREGISTRATION.json').read_text())
        check(prereg['candidate']['edges'] == ['prefix->loop', 'loop->loop'], 'Fixed preregistered edges')
        check(prereg['candidate']['loop_state'] == 'Identical valuation except ~envHelp=true.',
              'Fixed preregistered loop')
        native = bundle / 'data/native'
        pins = {r['path']: r for r in ledger['public_semantic_payloads']}
        check(len(pins) == 23, 'Exactly 23 public semantic payloads required')
        for row in pins.values():
            pin((bundle / row['path']).read_bytes(), row)
        def pinned(path):
            name = path.relative_to(bundle).as_posix()
            raw = path.read_bytes()
            pin(raw, pins[name])
            return raw
        report['phase'] = 'fixed_lasso_semantics'
        evaluate(model, receipt, prereg, pinned, native, report, pins)
        scientific_status = report.pop('status')
        report.pop('verified_frozen_inputs')
        report['verified_public_semantic_payloads'] = len(pins)
        report['scientific_status'] = scientific_status
        report['phase'] = 'historical_result_comparison'
        historical = json.loads((bundle / 'history/LIFT_LASSO_RESULT.json').read_text())
        compared_fields = ['states', 'initial_predicates', 'state_domains', 'edge_predicates',
                           'justice_truth_by_stage', 'original_source_cross_check', 'arena_lasso_legal',
                           'omega_SYS_G', 'omega_ENV_A', 'evaluated_saved_DAGs']
        check(scientific_status == historical['status'] == 'POSITIVE', 'Fixed saved lasso result differs')
        for key in compared_fields:
            check(report[key] == historical[key], 'Historical semantic field differs: ' + key)
        check(report['evaluated_saved_DAGs'] == 19, 'Exactly 19 evaluated DAG files required')
        report['historical_semantic_fields_compared'] = compared_fields
        check(time.monotonic() - timer < timeout, 'Fresh replay deadline exceeded')
        report['phase'] = 'complete'
        report['status'] = 'PASS_SAVED_LASSO_REPLAY'
    except Exception as exc:
        report['status'] = 'FAIL_SAVED_LASSO_REPLAY'
        report['error'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        signal.alarm(0)
    report['completed_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report['elapsed_seconds'] = time.monotonic() - timer
    (out / 'LASSO_REPLAY_RESULT.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'phase': report['phase'],
                      'error': report.get('error'), 'evaluated_saved_DAGs': report.get('evaluated_saved_DAGs')}))
    return 0 if report['status'] == 'PASS_SAVED_LASSO_REPLAY' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--timeout-seconds', type=int, default=60)
    args = parser.parse_args()
    raise SystemExit(replay(args.bundle, args.out, args.timeout_seconds))
