"""Independent raw-DAG/source checker; only file roots and output metadata ported."""
import csv, hashlib, itertools, json, pathlib, resource, sys, time
from functools import lru_cache
HERE = BASE = BUNDLE = PREREG = None
START = 0
ENV = [p + lane + 'Lane' for p in ('pedestrian', 'greenLight', 'obstacle') for lane in ('First', 'Second', 'Third')] + ['crosswalk']
LANES = ['First', 'Second', 'Third']
VALUES = {n: ['false', 'true'] for n in ENV}
VALUES.update(currentLane=LANES, speed=[str(i) for i in range(11)])
NAMES = ENV + ['currentLane', 'speed']
def initialize(bundle, out):
    global HERE, BASE, BUNDLE, PREREG, START
    BUNDLE = pathlib.Path(bundle).resolve()
    BASE = BUNDLE / 'data/native'
    HERE = pathlib.Path(out).resolve()
    PREREG = BUNDLE / 'REPLAY_INPUTS.json'
    START = time.monotonic()

def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def save(name, value):
    (HERE / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


class RawDAG:
    def __init__(self, path, model):
        self.path = path
        lines = [list(map(int, row.split())) for row in path.read_text().splitlines() if row.strip()]
        self.nodes = {}
        if len(lines) == 1 and lines[0][0] == 0 and len(lines[0]) == 2:
            assert lines[0][1] in (0, 1)
            self.root = lines[0][1]
            self.order = model['bdd_variable_order']
        else:
            assert lines[0] == [model['bdd_variable_count']]
            self.order = lines[1]
            assert self.order == model['bdd_variable_order']
            rank = {v: i for i, v in enumerate(self.order)}
            assert len(rank) == model['bdd_variable_count']
            for row in lines[2:]:
                assert len(row) == 4
                node, variable, low, high = row
                assert node not in (0, 1) and node not in self.nodes and variable in rank
                assert low != high
                for child in (low, high):
                    assert child in (0, 1) or child in self.nodes
                    if child not in (0, 1):
                        assert rank[self.nodes[child][0]] > rank[variable]
                self.nodes[node] = (variable, low, high)
            assert self.nodes
            self.root = lines[-1][0]
        reached = set()
        todo = [self.root]
        while todo:
            node = todo.pop()
            if node in (0, 1) or node in reached:
                continue
            reached.add(node)
            todo.extend(self.nodes[node][1:])
        assert reached == set(self.nodes)
        self.support = sorted({self.nodes[n][0] for n in reached})

    def point(self, assignment):
        node = self.root
        while node not in (0, 1):
            variable, low, high = self.nodes[node]
            assert variable in assignment, (self.path.name, variable)
            node = high if assignment[variable] else low
        return bool(node)


class Canonical:
    """Independently constructed reduced ordered Boolean functions, ascending bits."""
    def __init__(self):
        self.nodes = {0: (10**9, 0, 0), 1: (10**9, 1, 1)}
        self.unique = {}

    def mk(self, v, lo, hi):
        if lo == hi:
            return lo
        key = (v, lo, hi)
        if key not in self.unique:
            index = len(self.nodes)
            self.unique[key] = index
            self.nodes[index] = key
        return self.unique[key]

    @lru_cache(None)
    def negate(self, n):
        if n < 2:
            return 1 - n
        v, lo, hi = self.nodes[n]
        return self.mk(v, self.negate(lo), self.negate(hi))

    @lru_cache(None)
    def both(self, a, b):
        if a == 0 or b == 0:
            return 0
        if a == 1:
            return b
        if b == 1 or a == b:
            return a
        av, al, ah = self.nodes[a]
        bv, bl, bh = self.nodes[b]
        v = min(av, bv)
        if av != v:
            al = ah = a
        if bv != v:
            bl = bh = b
        return self.mk(v, self.both(al, bl), self.both(ah, bh))

    def all(self, *args):
        out = 1
        for a in args:
            out = self.both(out, a)
        return out

    def any(self, *args):
        return self.negate(self.all(*(self.negate(a) for a in args)))

    def implies(self, a, b):
        return self.any(self.negate(a), b)

    def cube(self, assignment):
        out = 1
        for v in sorted(assignment, reverse=True):
            out = self.mk(v, 0 if assignment[v] else out, out if assignment[v] else 0)
        return out

    def raw(self, dag):
        translation = {0: 0, 1: 1}
        for n, (v, lo, hi) in dag.nodes.items():
            translation[n] = self.mk(v, translation[lo], translation[hi])
        return translation[dag.root]


def main():
    prereg = json.loads(PREREG.read_text())
    pins = []
    for pin in prereg['input_pins']:
        p = BUNDLE / pin['path']
        actual = {'path': pin['path'], 'bytes': p.stat().st_size, 'sha256': digest(p)}
        actual['matches_preregistered'] = actual['bytes'] == pin['bytes'] and actual['sha256'] == pin['sha256']
        pins.append(actual)
    assert all(p['matches_preregistered'] for p in pins)
    models = {a: json.loads((BASE / 'arms' / a / 'native_result/model.json').read_text()) for a in ('original', 'released')}
    fields = {a: {f['name']: f for f in m['fields']} for a, m in models.items()}
    for a, m in models.items():
        assert len(fields[a]) == len(m['fields'])
        assert set(fields[a]) == set(NAMES + (['~envHelp'] if a == 'released' else []))
        allbits = []
        for name, f in fields[a].items():
            expected = VALUES.get(name, ['false', 'true'])
            assert set(f['values']) == set(expected) == set(f['encoding'])
            assert f['domain_size'] == len(expected)
            assert f['owner'] == f['role'] == ('ENV' if name in ENV or name == '~envHelp' else 'SYS')
            for phase in ('current', 'next'):
                bits = f[phase + '_bits']
                allbits.extend(bits)
                encoded = []
                for value in expected:
                    d = {int(k): v for k, v in f['encoding'][value][phase].items()}
                    assert set(d) == set(bits) and all(type(v) is bool for v in d.values())
                    encoded.append(tuple(d[b] for b in bits))
                assert len(set(encoded)) == len(expected)
        assert len(allbits) == len(set(allbits)) == m['bdd_variable_count']
        assert set(allbits) == set(range(m['bdd_variable_count']))
        for phase in ('current', 'next'):
            assert sorted(b for f in fields[a].values() for b in f[phase + '_bits']) == sorted(m['all_' + phase + '_bits'])

    def encode(arm, valuation, phase='current'):
        out = {}
        for name, value in valuation.items():
            d = fields[arm][name]['encoding'][str(value)][phase]
            for k, v in d.items():
                assert int(k) not in out
                out[int(k)] = v
        return out

    dags = {}
    for a, m in models.items():
        folder = BASE / 'arms' / a / 'native_result'
        names = ['native_strict_W_typed.bdd', 'domain.bdd', 'original_thetaE.bdd', 'original_thetaS.bdd']
        if a == 'original':
            names += ['original_rhoE.bdd', 'original_rhoS.bdd', 'original_SYS_justice_0.bdd'] + [f'original_ENV_justice_{i}.bdd' for i in range(3)]
        dags[a] = {n: RawDAG(folder / n, m) for n in names}
        assert set(dags[a]['native_strict_W_typed.bdd'].support) <= set(m['all_current_bits'])
    orig = dags['original']
    # Exact original-source transcription. The source has no INIT constraints;
    # current and next finite type domains are included by the exporter.
    c = Canonical()
    assert models['original']['bdd_variable_order'] == list(range(32))
    def eq(name, value, phase='current'):
        return c.cube(encode('original', {name: value}, phase))
    def b(name, phase='current'):
        return eq(name, 'true', phase)
    def lane_is(lane, phase='current'):
        return eq('currentLane', lane, phase)
    def can_drive(lane):
        return c.all(b('greenLight' + lane + 'Lane'), c.negate(b('pedestrian' + lane + 'Lane')), c.negate(b('obstacle' + lane + 'Lane')))
    domain = c.all(c.any(*(eq('currentLane', lane) for lane in LANES)), c.any(*(eq('speed', str(i)) for i in range(11))))
    next_domain = c.all(c.any(*(eq('currentLane', lane, 'next') for lane in LANES)), c.any(*(eq('speed', str(i), 'next') for i in range(11))))
    stopped = eq('speed', '0')
    moving = c.any(*(eq('speed', str(i)) for i in range(1, 11)))
    slow = c.any(*(eq('speed', str(i)) for i in range(5)))
    state_rules = [c.implies(b('crosswalk'), slow)]
    for lane in LANES:
        should_stop = c.any(b('pedestrian' + lane + 'Lane'), c.negate(b('greenLight' + lane + 'Lane')))
        state_rules += [c.implies(c.all(lane_is(lane), should_stop), stopped), c.implies(c.all(lane_is(lane), can_drive(lane)), moving)]
    ob = {lane: b('obstacle' + lane + 'Lane') for lane in LANES}
    nb = {lane: b('obstacle' + lane + 'Lane', 'next') for lane in LANES}
    rhoE = c.all(c.implies(ob['First'], c.negate(nb['Second'])), c.implies(ob['Second'], c.any(c.negate(nb['First']), c.negate(nb['Third']))), c.implies(ob['Third'], c.negate(nb['Second'])))
    transition_rules = [
        c.implies(c.all(lane_is('First'), ob['First']), lane_is('Second', 'next')),
        c.implies(c.all(lane_is('Second'), ob['Second'], nb['First']), lane_is('Third', 'next')),
        c.implies(c.all(lane_is('Second'), ob['Second'], nb['Third']), lane_is('First', 'next')),
        c.implies(c.all(lane_is('Second'), ob['Second'], c.negate(nb['Third']), c.negate(nb['First'])), c.negate(lane_is('Second', 'next'))),
        c.implies(c.all(lane_is('Third'), ob['Third']), lane_is('Second', 'next')),
        c.implies(lane_is('First'), c.negate(lane_is('Third', 'next'))),
        c.implies(lane_is('Third'), c.negate(lane_is('First', 'next'))),
    ]
    source_nodes = {
        'domain.bdd': domain,
        'original_thetaE.bdd': 1,
        'original_thetaS.bdd': domain,
        'original_rhoE.bdd': rhoE,
        'original_rhoS.bdd': c.all(domain, next_domain, *state_rules, *transition_rules),
        'original_SYS_justice_0.bdd': c.any(*(c.all(lane_is(lane), can_drive(lane)) for lane in LANES)),
    }
    source_nodes.update({f'original_ENV_justice_{i}.bdd': can_drive(lane) for i, lane in enumerate(LANES)})
    semantic = {name: {'source_equals_saved_on_all_Boolean_assignments': node == c.raw(orig[name]), 'saved_support': orig[name].support} for name, node in source_nodes.items()}
    env_bits = {bit for name in ENV for phase in ('current', 'next') for bit in fields['original'][name][phase + '_bits']}
    independent_env = all(set(orig[name].support) <= env_bits for name in ['original_rhoE.bdd'] + [f'original_ENV_justice_{i}.bdd' for i in range(3)])
    clear = {n: 'true' if n.startswith('greenLight') else 'false' for n in ENV}
    counts = dict(source_states=0, original_W=0, released_helper_false=0, released_helper_true=0, intersection=0, loss=0, gain=0)
    cells = {str((w, f, t)): 0 for w, f, t in itertools.product((0, 1), repeat=3)}
    failures = {k: [] for k in ['original_domain', 'released_false_domain', 'released_true_domain', 'fixed_predecessor', 'all_clear_env_edge', 'all_clear_justice', 'initial_env_without_original_W_response']}
    first_initial = []
    predecessors = {}
    for lane in LANES:
        p = dict(clear, currentLane=lane, speed='1')
        pe = encode('original', p)
        predecessors[lane] = {
            'valuation': p,
            'domain': orig['domain.bdd'].point(pe),
            'thetaE': orig['original_thetaE.bdd'].point(pe),
            'thetaS': orig['original_thetaS.bdd'].point(pe),
            'W': orig['native_strict_W_typed.bdd'].point(pe),
        }
    with (HERE / 'all_source_states.csv').open('w', newline='') as out, (HERE / 'all_W_fixed_predecessors.csv').open('w', newline='') as predout:
        writer = csv.writer(out)
        writer.writerow(['state_id', 'environment_mask'] + NAMES + ['original_W', 'released_false_W', 'released_true_W', 'loss', 'gain'])
        predwriter = csv.writer(predout)
        predwriter.writerow(['state_id', 'predecessor_lane', 'predecessor_initial', 'predecessor_W', 'rhoE', 'rhoS', 'target_W', 'all_pass'])
        for emask in range(1024):
            env = {n: 'true' if emask & (1 << i) else 'false' for i, n in enumerate(ENV)}
            clear_edge = dict(encode('original', env), **{})
            clear_edge.update(encode('original', clear, 'next'))
            if not orig['original_rhoE.bdd'].point(clear_edge):
                failures['all_clear_env_edge'].append(emask)
            fiber = []
            for li, lane in enumerate(LANES):
                for speed in range(11):
                    sid = emask * 33 + li * 11 + speed
                    state = dict(env, currentLane=lane, speed=str(speed))
                    x = encode('original', state)
                    xf = encode('released', dict(state, **{'~envHelp': 'false'}))
                    xt = encode('released', dict(state, **{'~envHelp': 'true'}))
                    for arm, assign, key in [('original', x, 'original_domain'), ('released', xf, 'released_false_domain'), ('released', xt, 'released_true_domain')]:
                        if not dags[arm]['domain.bdd'].point(assign):
                            failures[key].append(sid)
                    w = orig['native_strict_W_typed.bdd'].point(x)
                    f = dags['released']['native_strict_W_typed.bdd'].point(xf)
                    t = dags['released']['native_strict_W_typed.bdd'].point(xt)
                    vals = dict(source_states=1, original_W=w, released_helper_false=f, released_helper_true=t, intersection=w and f, loss=w and not f, gain=f and not w)
                    for key, value in vals.items():
                        counts[key] += int(value)
                    cells[str((int(w), int(f), int(t)))] += 1
                    writer.writerow([sid, emask] + [state[n] for n in NAMES] + [int(w), int(f), int(t), int(w and not f), int(f and not w)])
                    if w:
                        p = predecessors[lane]
                        edge = encode('original', p['valuation'])
                        edge.update(encode('original', state, 'next'))
                        checks = [p['domain'] and p['thetaE'] and p['thetaS'], p['W'], orig['original_rhoE.bdd'].point(edge), orig['original_rhoS.bdd'].point(edge), w]
                        passed = all(checks)
                        predwriter.writerow([sid, lane] + list(map(int, checks)) + [int(passed)])
                        if not passed:
                            failures['fixed_predecessor'].append({'state_id': sid, 'checks': checks})
                        if orig['original_thetaE.bdd'].point(x) and orig['original_thetaS.bdd'].point(x):
                            fiber.append(sid)
            first_initial.append({'environment_mask': emask, 'winning_initial_responses': len(fiber), 'first_witness_state_id': fiber[0] if fiber else None})
            if not fiber:
                failures['initial_env_without_original_W_response'].append(emask)
    for i in range(3):
        if not orig[f'original_ENV_justice_{i}.bdd'].point(encode('original', clear)):
            failures['all_clear_justice'].append(i)
    counts['released_both_helper_values'] = counts['released_helper_false'] + counts['released_helper_true']
    save('INITIAL_RESPONSE_FIBERS.json', first_initial)
    save('INPUT_PINS_VERIFIED.json', pins)
    save('FIELD_ALIGNMENT.json', {'source_field_order': NAMES, 'boolean_environment_mask_bit_order': ENV, 'state_id_rule': 'environment_mask*33 + lane_index*11 + integer_speed; lane_index First=0,Second=1,Third=2', 'source_to_saved_named_fields': {a: list(f.values()) for a, f in fields.items()}, 'unaccounted_fields': [], 'shared_source_values_equal': True, 'source_id': models['original']['input']})
    save('SOURCE_SEMANTIC_IDENTITY.json', {'manual_translation_of_pinned_source': True, 'canonical_exact_equivalence_including_invalid_encodings': semantic, 'rhoE_and_ENV_justices_independent_of_SYS': independent_env, 'canonical_nodes_allocated': len(c.nodes), 'raw_dags': {a: {n: {'nodes': len(d.nodes), 'root': d.root, 'support': d.support} for n, d in ds.items()} for a, ds in dags.items()}})
    output_bytes = sum(p.stat().st_size for p in HERE.iterdir() if p.is_file())
    usage = resource.getrusage(resource.RUSAGE_SELF)
    rss_bytes = usage.ru_maxrss if sys.platform == 'darwin' else usage.ru_maxrss * 1024
    result = {
        'schema': 'v66-vehicle188-independent-audit-v1',
        'status': 'PASS' if all(x['source_equals_saved_on_all_Boolean_assignments'] for x in semantic.values()) and independent_env and not any(failures.values()) else 'FAIL',
        'counts': counts, 'joint_membership_cells_original_false_true': cells,
        'failure_counts': {k: len(v) for k, v in failures.items()}, 'failures': failures,
        'fixed_predecessors': predecessors,
        'all_clear': {'valuation': clear, 'all_1024_environment_predecessors_pass': not failures['all_clear_env_edge'], 'all_3_ENV_justices_pass': not failures['all_clear_justice'], 'SYS_independent': independent_env},
        'initial_quantifier': {'statement': 'forall 1024 legal initial ENV valuations exists SYS response satisfying thetaS and original W', 'pass': not failures['initial_env_without_original_W_response'], 'minimum_winning_response_count': min(x['winning_initial_responses'] for x in first_initial), 'maximum_winning_response_count': max(x['winning_initial_responses'] for x in first_initial)},
        'source_semantic_checks_all_pass': all(x['source_equals_saved_on_all_Boolean_assignments'] for x in semantic.values()),
        'independence': {'producer_code_imported': False, 'producer_new_result_read': False, 'new_native_solver_runs': 0, 'new_source_searches': 0, 'known_counts': prereg['prior_knowledge'], 'implementation': 'New stdlib raw DAG evaluator and independently constructed canonical source predicates'},
        'budget': {'elapsed_seconds': time.monotonic() - START, 'peak_RSS_bytes': rss_bytes, 'output_bytes_before_summary': output_bytes, 'hard_wall_seconds': 180, 'RSS_limit_bytes': 1024**3, 'RSS_guard_interval_seconds': 0.02, 'output_limit_bytes': 32*1024**2},
    }
    assert rss_bytes <= 1024**3 and output_bytes < 32*1024**2
    save('AUDIT_RESULT.json', result)
    print(json.dumps({'status': result['status'], 'counts': counts, 'failure_counts': result['failure_counts'], 'source_semantic_checks_all_pass': result['source_semantic_checks_all_pass'], 'initial_quantifier': result['initial_quantifier'], 'budget': result['budget']}, ensure_ascii=False, indent=2))
