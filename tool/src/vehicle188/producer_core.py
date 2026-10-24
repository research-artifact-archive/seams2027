"""Exact mathematical bodies with portable input/output context."""
from pathlib import Path
from functools import lru_cache
from itertools import product
import csv, datetime, hashlib, json, math, resource, time
BUNDLE = BASE = HERE = PREREG = None
SOURCE_HASH = '0e6faaedcd2bf8ab7b80d239231973f4588922ae5ff85a95927894cf78531e3b'
LANES = ['First', 'Second', 'Third']
CHECKS = []
PINS = []
START = 0
def initialize(bundle, out):
    global BUNDLE, BASE, HERE, PREREG, CHECKS, PINS, START
    BUNDLE = Path(bundle).resolve()
    BASE = BUNDLE / 'data/native/arms'
    HERE = Path(out).resolve()
    PREREG = BUNDLE / 'records/PREREGISTRATION.json'
    CHECKS, PINS = [], []
    START = time.monotonic()
def pin(path):
    path = Path(path)
    data = path.read_bytes()
    if path.is_relative_to(BUNDLE):
        name = path.relative_to(BUNDLE).as_posix()
    elif path.is_relative_to(HERE):
        name = 'replay-output/producer/' + path.relative_to(HERE).as_posix()
    else:
        raise ValueError('input/output outside assigned roots')
    return dict(path=name, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

def require(ok, label, detail=None):
    CHECKS.append(dict(check=label, passed=bool(ok), detail=detail))
    if not ok:
        raise AssertionError(label)


class BDD:
    def __init__(self):
        self.nodes = [None, None]
        self.unique = {}

    def make(self, v, lo, hi):
        if lo == hi:
            return lo
        key = (v, lo, hi)
        if key not in self.unique:
            self.unique[key] = len(self.nodes)
            self.nodes.append(key)
        return self.unique[key]

    @lru_cache(None)
    def negate(self, u):
        if u < 2:
            return 1 - u
        v, lo, hi = self.nodes[u]
        return self.make(v, self.negate(lo), self.negate(hi))

    @lru_cache(None)
    def conjunction(self, a, b):
        if a == 0 or b == 0:
            return 0
        if a == 1:
            return b
        if b == 1 or a == b:
            return a
        va, al, ah = self.nodes[a]
        vb, bl, bh = self.nodes[b]
        if va < vb:
            return self.make(va, self.conjunction(al, b), self.conjunction(ah, b))
        if vb < va:
            return self.make(vb, self.conjunction(a, bl), self.conjunction(a, bh))
        return self.make(va, self.conjunction(al, bl), self.conjunction(ah, bh))

    def disjunction(self, a, b):
        return self.negate(self.conjunction(self.negate(a), self.negate(b)))

    def AND(self, *terms):
        root = 1
        for t in terms:
            root = self.conjunction(root, t)
        return root

    def OR(self, *terms):
        root = 0
        for t in terms:
            root = self.disjunction(root, t)
        return root

    def implies(self, a, b):
        return self.OR(self.negate(a), b)

    def cube(self, bits):
        root = 1
        for v, b in sorted(bits.items(), reverse=True):
            root = self.make(v, 0, root) if b else self.make(v, root, 0)
        return root

    def support(self, root):
        visited, todo, bits = set(), [root], set()
        while todo:
            u = todo.pop()
            if u < 2 or u in visited:
                continue
            visited.add(u)
            v, lo, hi = self.nodes[u]
            bits.add(v)
            todo.extend((lo, hi))
        return bits

    def evaluate(self, root, bits):
        while root > 1:
            v, lo, hi = self.nodes[root]
            root = hi if bits[v] else lo
        return bool(root)

    def read(self, path, nvars, ref=None):
        actual = pin(path)
        if ref is not None:
            require(all(actual[k] == ref[k] for k in ('bytes', 'sha256')), 'predicate pin ' + path.name)
        PINS.append(actual)
        rows = [list(map(int, row.split())) for row in path.read_text('ascii').splitlines() if row.strip()]
        if len(rows) == 1:
            require(rows[0] in [[0, 0], [0, 1]], 'constant BDD syntax ' + path.name)
            root = rows[0][1]
            support, count = set(), 0
        else:
            require(rows[0] == [nvars] and rows[1] == list(range(nvars)), 'saved BDD variable order ' + path.name)
            translate, raw, triples = {0: 0, 1: 1}, {}, set()
            for row in rows[2:]:
                if len(row) != 4:
                    raise AssertionError('BDD row width')
                u, v, lo, hi = row
                if not (u > 1 and u not in translate and 0 <= v < nvars and lo in translate and hi in translate and lo != hi):
                    raise AssertionError('BDD node syntax')
                if (v, lo, hi) in triples or any(c > 1 and raw[c][0] <= v for c in (lo, hi)):
                    raise AssertionError('BDD reduction/order')
                raw[u] = (v, lo, hi)
                triples.add((v, lo, hi))
                translate[u] = self.make(v, translate[lo], translate[hi])
            seen, todo = set(), [rows[-1][0]]
            while todo:
                u = todo.pop()
                if u > 1 and u not in seen:
                    seen.add(u)
                    todo.extend(raw[u][1:])
            require(seen == set(raw), 'saved nodes all root reachable ' + path.name)
            root = translate[rows[-1][0]]
            support, count = {raw[u][0] for u in seen}, len(raw)
        if ref is not None:
            require(sorted(support) == ref['support'] and count == ref['node_count'], 'predicate metadata ' + path.name)
            require(ref['zero'] == (root == 0) and ref['one'] == (root == 1), 'predicate terminal flags ' + path.name)
        return root


class Model:
    def __init__(self, arm):
        self.directory = BASE / arm / 'native_result'
        self.data = json.loads((self.directory / 'model.json').read_text())
        self.dag = BDD()
        self.fields = self.data['fields']
        self.byname = {f['name']: f for f in self.fields}
        self.enc = {}
        bit_owners = set()
        require(len(self.fields) == len(self.byname), arm + ' unique fields')
        for f in self.fields:
            require(f['owner'] == f['role'] and f['owner'] in ['ENV', 'SYS'], arm + ' field owner ' + f['name'])
            require(f['domain_size'] == len(f['values']) == len(set(f['values'])), arm + ' distinct value map ' + f['name'])
            for phase in ['current', 'next']:
                bits = f[phase + '_bits']
                require(not bit_owners.intersection(bits) and len(bits) == len(set(bits)), arm + ' disjoint bits ' + f['name'] + phase)
                bit_owners.update(bits)
                codes = set()
                for value in f['values']:
                    code = {int(k): v for k, v in f['encoding'][value][phase].items()}
                    require(set(code) == set(bits) and all(type(v) is bool for v in code.values()), arm + ' complete typed encoding ' + f['name'] + value + phase)
                    tup = tuple(code[b] for b in bits)
                    require(tup not in codes, arm + ' injective encoding ' + f['name'] + value + phase)
                    codes.add(tup)
                    self.enc[f['name'], value, phase] = code
            require(all(tuple(self.enc[f['name'], v, 'current'][b] for b in f['current_bits']) == tuple(self.enc[f['name'], v, 'next'][b] for b in f['next_bits']) for v in f['values']), arm + ' current next codes equal ' + f['name'])
        nv = self.data['bdd_variable_count']
        require(bit_owners == set(range(nv)) and self.data['bdd_variable_order'] == list(range(nv)), arm + ' complete bit roster natural order')
        self.env = [f for f in self.fields if f['owner'] == 'ENV']
        self.sys = [f for f in self.fields if f['owner'] == 'SYS']
        self.current_bits = {b for f in self.fields for b in f['current_bits']}
        self.next_bits = {b for f in self.fields for b in f['next_bits']}
        require(set(self.data['all_current_bits']) == self.current_bits and set(self.data['all_next_bits']) == self.next_bits, arm + ' declared phase unions')
        self.pred = {k: self.dag.read(self.directory / ref['file'], nv, ref) for k, ref in self.data['original_bdds'].items()}
        self.justices = {owner: [self.dag.read(self.directory / ref['file'], nv, ref) for ref in refs] for owner, refs in self.data['original_justices'].items()}
        self.W = self.dag.read(self.directory / 'native_strict_W_typed.bdd', nv)
        require(self.dag.support(self.W) <= self.current_bits, arm + ' W current support only')
        require(self.pred['domain'] == self.domain(self.fields, 'current'), arm + ' domain reconstructed by complete typed values')
        require(self.pred['domain_ENV_next'] == self.domain(self.env, 'next') and self.pred['domain_SYS_next'] == self.domain(self.sys, 'next'), arm + ' next domains reconstructed')
        require(self.dag.AND(self.W, self.pred['domain']) == self.W, arm + ' W is typed')
        require(self.data['input']['sha256'] == SOURCE_HASH and self.data['input']['bytes'] == 3924, arm + ' source input identity')

    def domain(self, fields, phase):
        return self.dag.AND(*(self.dag.OR(*(self.dag.cube(self.enc[f['name'], v, phase]) for v in f['values'])) for f in fields))

    def atom(self, name, value='true', phase='current'):
        return self.dag.cube(self.enc[name, value, phase])

    def bits(self, state, phase='current'):
        return {b: value for name, v in state.items() for b, value in self.enc[name, v, phase].items()}

    def ev(self, formula, state, next_state=None):
        bits = self.bits(state)
        if next_state is not None:
            bits.update(self.bits(next_state, 'next'))
        return self.dag.evaluate(formula, bits)


def qualify():
    d = BDD()
    x, y, z = [d.cube({b: True}) for b in range(3)]
    f = d.OR(d.AND(x, y), d.AND(d.negate(x), z))
    require(all(d.evaluate(f, dict(enumerate(v))) == ((v[0] and v[1]) or (not v[0] and v[2])) for v in product([False, True], repeat=3)), 'independent Boolean algebra qualification')
    require(d.AND(x, d.negate(x)) == 0 and d.OR(x, d.negate(x)) == 1, 'Boolean contradiction and tautology qualification')
    require(d.AND(x, y) == d.AND(y, x) and d.OR(x, y) == d.OR(y, x), 'canonical Boolean commutativity qualification')


def check_source_equations(m):
    d, a = m.dag, m.atom
    free = {lane: d.AND(a('greenLight' + lane + 'Lane'), d.negate(a('pedestrian' + lane + 'Lane')), d.negate(a('obstacle' + lane + 'Lane'))) for lane in LANES}
    stop = {lane: d.OR(a('pedestrian' + lane + 'Lane'), d.negate(a('greenLight' + lane + 'Lane'))) for lane in LANES}
    lane = {v: a('currentLane', v) for v in LANES}
    nxtlane = {v: a('currentLane', v, 'next') for v in LANES}
    obs = {v: a('obstacle' + v + 'Lane') for v in LANES}
    nxtobs = {v: a('obstacle' + v + 'Lane', phase='next') for v in LANES}
    drive = d.OR(*(a('speed', str(v)) for v in range(1, 11)))
    fast = d.OR(*(a('speed', str(v)) for v in range(5, 11)))
    e = d.AND(d.implies(obs['First'], d.negate(nxtobs['Second'])), d.implies(obs['Second'], d.OR(d.negate(nxtobs['First']), d.negate(nxtobs['Third']))), d.implies(obs['Third'], d.negate(nxtobs['Second'])))
    guarantees = [d.implies(d.AND(stop[v], lane[v]), d.negate(drive)) for v in LANES]
    guarantees += [
        d.implies(d.AND(lane['First'], obs['First']), nxtlane['Second']),
        d.implies(d.AND(lane['Second'], obs['Second'], nxtobs['First']), nxtlane['Third']),
        d.implies(d.AND(lane['Second'], obs['Second'], nxtobs['Third']), nxtlane['First']),
        d.implies(d.AND(lane['Second'], obs['Second'], d.negate(nxtobs['Third']), d.negate(nxtobs['First'])), d.negate(nxtlane['Second'])),
        d.implies(d.AND(lane['Third'], obs['Third']), nxtlane['Second']),
        d.implies(a('crosswalk'), d.negate(fast)),
    ]
    guarantees += [d.implies(d.AND(free[v], lane[v]), drive) for v in LANES]
    guarantees += [d.implies(lane['First'], d.negate(nxtlane['Third'])), d.implies(lane['Third'], d.negate(nxtlane['First']))]
    s = d.AND(m.domain(m.fields, 'current'), m.domain(m.sys, 'next'), *guarantees)
    require(m.pred['rhoE'] == e, 'source ENV safety equals saved BDD over every Boolean valuation')
    require(m.pred['rhoS'] == s, 'source SYS safety with current and next SYS domains equals saved BDD over every Boolean valuation')
    require(m.pred['thetaE'] == 1 and m.pred['thetaS'] == m.pred['domain'], 'source has unconstrained typed initializer')
    require(m.justices['ENV'] == [free[v] for v in LANES], 'source three ENV justices exactly equal saved BDDs')
    require(m.justices['SYS'] == [d.OR(*(d.AND(lane[v], free[v]) for v in LANES))], 'source SYS justice exactly equals saved BDD')
    env_current = {b for f in m.env for b in f['current_bits']}
    env_both = {b for f in m.env for phase in ['current_bits', 'next_bits'] for b in f[phase]}
    require(d.support(e) <= env_both and all(d.support(j) <= env_current for j in m.justices['ENV']), 'ENV safety and every ENV justice are SYS independent')


def source_env_edge(s, t):
    obs = lambda x, lane: x['obstacle' + lane + 'Lane'] == 'true'
    return ((not obs(s, 'First') or not obs(t, 'Second')) and
            (not obs(s, 'Second') or not obs(t, 'First') or not obs(t, 'Third')) and
            (not obs(s, 'Third') or not obs(t, 'Second')))


def source_sys_edge(s, t):
    lane, target, speed = s['currentLane'], t['currentLane'], int(s['speed'])
    b = lambda x, name: x[name] == 'true'
    free = b(s, 'greenLight' + lane + 'Lane') and not b(s, 'pedestrian' + lane + 'Lane') and not b(s, 'obstacle' + lane + 'Lane')
    stop = b(s, 'pedestrian' + lane + 'Lane') or not b(s, 'greenLight' + lane + 'Lane')
    return ((not stop or speed == 0) and (not b(s, 'crosswalk') or speed < 5) and (not free or speed > 0)
            and (not (lane == 'First' and b(s, 'obstacleFirstLane')) or target == 'Second')
            and (not (lane == 'Second' and b(s, 'obstacleSecondLane') and b(t, 'obstacleFirstLane')) or target == 'Third')
            and (not (lane == 'Second' and b(s, 'obstacleSecondLane') and b(t, 'obstacleThirdLane')) or target == 'First')
            and (not (lane == 'Second' and b(s, 'obstacleSecondLane') and not b(t, 'obstacleFirstLane') and not b(t, 'obstacleThirdLane')) or target != 'Second')
            and (not (lane == 'Third' and b(s, 'obstacleThirdLane')) or target == 'Second')
            and (lane != 'First' or target != 'Third') and (lane != 'Third' or target != 'First'))


def run():
    plan = json.loads(PREREG.read_text())
    qualify()
    original, released = Model('original'), Model('released')
    require(set(released.byname) == set(original.byname) | {'~envHelp'}, 'exact released extension by single helper')
    require(released.byname['~envHelp']['owner'] == 'ENV' and released.byname['~envHelp']['values'] == ['false', 'true'], 'helper is complete ENV Boolean')
    for name, f in original.byname.items():
        g = released.byname[name]
        require(all(f[k] == g[k] for k in ['owner', 'role', 'domain_size', 'values']), 'cross-arm typed field equality ' + name)
    require(len(original.env) == 10 and len(original.sys) == 2 and len(original.fields) == 12, 'exact source field ownership roster')
    require(math.prod(f['domain_size'] for f in original.fields) == 33792, 'complete source domain 33792')
    check_source_equations(original)
    clear = {f['name']: 'true' if f['name'].startswith('greenLight') else 'false' for f in original.env}
    env_names = [f['name'] for f in original.env]
    env_rows = []
    for values in product(*(f['values'] for f in original.env)):
        env = dict(zip(env_names, values))
        edge = original.ev(original.pred['rhoE'], env, clear)
        source_edge = source_env_edge(env, clear)
        fair = [original.ev(j, clear) for j in original.justices['ENV']]
        env_rows.append([*values, int(edge), int(source_edge), *(int(x) for x in fair)])
    require(len(env_rows) == 1024 and all(all(v == 1 for v in row[-5:]) for row in env_rows), 'all 1024 environment valuations have legal all-clear successor satisfying every justice')
    require(original.ev(original.pred['rhoE'], clear, clear), 'all-clear environment can repeat forever')
    with (HERE / 'environment_all_clear.tsv').open('w', newline='') as f:
        writer = csv.writer(f, delimiter='\t', lineterminator='\n')
        writer.writerow(env_names + ['rhoE_to_clear', 'source_rhoE_to_clear', 'justice0_at_clear', 'justice1_at_clear', 'justice2_at_clear'])
        writer.writerows(env_rows)
    names = [f['name'] for f in original.fields]
    counts = dict(domain=0, original_W=0, released_false_W=0, released_true_W=0, intersection=0, loss=0, gain=0, neither=0, original_initial_typed=0, positive_reachable_W=0, positive_reachable_loss=0)
    failures, examples = [], {}
    initial_response_envs, all_envs = set(), set()
    mask_hashers = {name: hashlib.sha256() for name in ['original_W', 'released_false_W', 'released_true_W', 'loss', 'gain']}
    predecessors = {lane: dict(clear, currentLane=lane, speed='1') for lane in LANES}
    with (HERE / 'state_table.tsv').open('w', newline='') as f:
        writer = csv.writer(f, delimiter='\t', lineterminator='\n')
        columns = ['state_id'] + names + ['W', 'WF', 'WT', 'loss', 'gain', 'thetaE', 'thetaS', 'pred_thetaE', 'pred_thetaS', 'pred_W', 'rhoE_pred_target', 'rhoS_pred_target', 'source_rhoE_pred_target', 'source_rhoS_pred_target']
        writer.writerow(columns)
        for idx, values in enumerate(product(*(field['values'] for field in original.fields))):
            state = dict(zip(names, values))
            ekey = tuple(state[name] for name in env_names)
            all_envs.add(ekey)
            w = original.ev(original.W, state)
            wf = released.ev(released.W, dict(state, **{'~envHelp': 'false'}))
            wt = released.ev(released.W, dict(state, **{'~envHelp': 'true'}))
            loss, gain = w and not wf, wf and not w
            theta = [original.ev(original.pred[k], state) for k in ['thetaE', 'thetaS']]
            if w and all(theta):
                initial_response_envs.add(ekey)
            p = predecessors[state['currentLane']]
            pred_checks = [original.ev(original.pred['thetaE'], p), original.ev(original.pred['thetaS'], p), original.ev(original.W, p), original.ev(original.pred['rhoE'], p, state), original.ev(original.pred['rhoS'], p, state)]
            source_checks = [source_env_edge(p, state), source_sys_edge(p, state)]
            if source_checks != pred_checks[-2:]:
                failures.append(dict(state_id=idx, kind='source_saved_edge_mismatch', state=state))
            if w and not all(pred_checks):
                failures.append(dict(state_id=idx, kind='fixed_predecessor_failed', state=state, checks=pred_checks))
            reached = w and all(pred_checks)
            row = [idx, *values, *(int(x) for x in [w, wf, wt, loss, gain, *theta, *pred_checks, *source_checks])]
            writer.writerow(row)
            increments = dict(domain=1, original_W=w, released_false_W=wf, released_true_W=wt, intersection=w and wf, loss=loss, gain=gain, neither=not w and not wf, original_initial_typed=all(theta), positive_reachable_W=reached, positive_reachable_loss=loss and reached)
            for name, value in increments.items():
                counts[name] += int(value)
            masks = dict(original_W=w, released_false_W=wf, released_true_W=wt, loss=loss, gain=gain)
            for name, value in masks.items():
                mask_hashers[name].update(bytes([int(value)]))
                if value and name not in examples:
                    examples[name] = dict(state_id=idx, state=state)
    require(counts['domain'] == 33792, 'enumeration exactly covers all typed states once')
    require(not failures, 'all fixed predecessor and source saved edge checks pass', failures)
    require(counts['original_W'] == plan['prior_knowledge']['original_native_W'], 'direct original W cardinality agrees with prior native record')
    require(counts['released_false_W'] + counts['released_true_W'] == plan['prior_knowledge']['released_total_native_W_both_helper_values'], 'direct helper split agrees with prior total native record')
    require(counts['intersection'] + counts['loss'] == counts['original_W'] and counts['intersection'] + counts['gain'] == counts['released_false_W'], 'set partition identities without assuming subset')
    missing = sorted(all_envs - initial_response_envs)
    require(len(all_envs) == 1024 and not missing, 'every admissible initial ENV valuation has a typed original W response', dict(total_env=len(all_envs), missing_count=len(missing)))
    return dict(schema='v66-vehicle188-whole-region-producer-v1', status='PASS_PRODUCER_PENDING_INDEPENDENT_AUDIT', created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), preregistration=pin(PREREG), selection_disclosure=plan['selection_disclosure'], counts=counts, original_initializer=dict(all_typed_states=counts['original_initial_typed'], admissible_environment_valuations=len(all_envs), environment_valuations_missing_W_response=len(missing), I_M_W=not missing), environment_certificate=dict(all_clear=clear, current_environment_valuations=1024, legal_successors=1024, repeated_all_clear_legal=True, all_three_justices_at_clear=True, safety_and_justice_system_independent=True), fixed_predecessors=predecessors, failed_checks=failures, mask_byte_sha256={k:v.hexdigest() for k,v in mask_hashers.items()}, enumeration_order=names, enumeration_values={f['name']:f['values'] for f in original.fields}, examples=examples, checks=CHECKS, input_pins=PINS, elapsed_seconds=time.monotonic()-START, peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, native_solver_invocations=0, game_fixed_point_invocations=0, new_source_searches=0, retries=0, output_files=[pin(HERE/'state_table.tsv'), pin(HERE/'environment_all_clear.tsv')], limitations=['One previously outcome-selected unchanged public case, not prevalence or deployment evidence.', 'The saved native W functions are evaluated, not recomputed by a second game solver.', 'Source equation identity and counts share the native exporter/field mapping inputs; independent audit remains required.', 'Positive reachability is an existential per-target initialized cooperative policy certificate, not one common policy or an observed execution.'])
