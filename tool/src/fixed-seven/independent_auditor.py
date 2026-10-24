#!/usr/bin/env python3
"""Independent saved-DAG/model auditor. No solver, subprocess, producer imports.

Functions are inert until called. Scientific callers require a separately pinned
root authorization; the artificial qualification is a distinct bounded caller.
"""
import csv
import gzip
import hashlib
import itertools
import json
from functools import lru_cache
from pathlib import Path


class AuditError(Exception):
    pass


def require(ok, label):
    if not ok:
        raise AuditError(label)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_pin(pin):
    p = Path(pin['path'])
    require(p.is_file(), 'pin file missing')
    require(p.stat().st_size == pin['bytes'] and sha(p) == pin['sha256'], 'pin bytes/hash mismatch')


def verify_authority(go, files, limits, reservation=None):
    require(go.get('status') == 'AUTHORIZED', 'GO absent or wrong status')
    require(go.get('limits') == limits, 'GO limits changed')
    require(go.get('files') == files, 'GO code/input pins changed')
    if reservation is not None:
        require(reservation not in go.get('consumed_reservations', []), 'duplicate arm reservation')


class DAG:
    def __init__(self, nodes, roots, variable_count, order):
        self.nvars = variable_count
        self.order = list(order)
        require(len(order) == variable_count and set(order) == set(range(variable_count)), 'DAG variable order')
        rank = {v: i for i, v in enumerate(order)}
        self.nodes = {}
        for row in nodes:
            require(len(row) == 4, 'DAG row width')
            n, v, lo, hi = row
            require(all(type(x) is int for x in row), 'DAG integer rows')
            require(n > 1 and n not in self.nodes and v in rank, 'DAG node identity')
            require(lo != hi, 'DAG unreduced node')
            for child in (lo, hi):
                require(child in (0, 1) or child in self.nodes, 'DAG forward/missing child')
                if child > 1:
                    require(rank[self.nodes[child][0]] > rank[v], 'DAG order violation')
            self.nodes[n] = (v, lo, hi)
        self.roots = dict(roots)
        require(bool(self.roots), 'DAG missing roots')
        require(all(r in (0, 1) or r in self.nodes for r in self.roots.values()), 'DAG invalid root')
        seen = set()
        todo = list(self.roots.values())
        while todo:
            n = todo.pop()
            if n < 2 or n in seen:
                continue
            seen.add(n)
            todo.extend(self.nodes[n][1:])
        require(seen == set(self.nodes), 'DAG disconnected nodes')

    @classmethod
    def raw(cls, text, nvars, order):
        rows = [list(map(int, x.split())) for x in text.splitlines() if x.strip()]
        if len(rows) == 1:
            require(len(rows[0]) == 2 and rows[0][0] == 0 and rows[0][1] in (0, 1), 'DAG constant syntax')
            return cls([], {'root': rows[0][1]}, nvars, order)
        require(len(rows) >= 3 and rows[0] == [nvars] and rows[1] == list(order), 'DAG header mismatch')
        return cls(rows[2:], {'root': rows[-1][0]}, nvars, order)

    def support(self, root='root'):
        todo = [self.roots[root]]
        seen, variables = set(), set()
        while todo:
            n = todo.pop()
            if n < 2 or n in seen:
                continue
            seen.add(n)
            v, lo, hi = self.nodes[n]
            variables.add(v)
            todo.extend((lo, hi))
        return variables

    def point(self, assignment, root='root'):
        n = self.roots[root]
        while n > 1:
            v, lo, hi = self.nodes[n]
            require(v in assignment, 'point assignment missing support bit')
            n = hi if assignment[v] else lo
        return bool(n)


class BooleanFunctions:
    """Canonical natural-order DAG; ITE reorders any incoming variable permutation."""
    def __init__(self):
        self.nodes = {0: (10**9, 0, 0), 1: (10**9, 1, 1)}
        self.unique = {}

    def node(self, variable, low, high):
        if low == high:
            return low
        require(variable < self.nodes[low][0] and variable < self.nodes[high][0], 'canonical order')
        key = (variable, low, high)
        if key not in self.unique:
            n = len(self.nodes)
            self.unique[key] = n
            self.nodes[n] = key
        return self.unique[key]

    def variable(self, bit):
        return self.node(bit, 0, 1)

    @lru_cache(None)
    def neg(self, x):
        if x < 2:
            return 1 - x
        v, lo, hi = self.nodes[x]
        return self.node(v, self.neg(lo), self.neg(hi))

    @lru_cache(None)
    def both(self, x, y):
        if x == 0 or y == 0:
            return 0
        if x == 1:
            return y
        if y == 1 or x == y:
            return x
        xv, xl, xh = self.nodes[x]
        yv, yl, yh = self.nodes[y]
        v = min(xv, yv)
        if xv != v:
            xl = xh = x
        if yv != v:
            yl = yh = y
        return self.node(v, self.both(xl, yl), self.both(xh, yh))

    def either(self, x, y):
        return self.neg(self.both(self.neg(x), self.neg(y)))

    def ite(self, bit, high, low):
        variable = self.variable(bit)
        return self.either(self.both(variable, high), self.both(self.neg(variable), low))

    def import_dag(self, dag, root='root', rename=None, fixed=None):
        rename = {i: i for i in range(dag.nvars)} if rename is None else rename
        fixed = {} if fixed is None else fixed
        values = {0: 0, 1: 1}
        for n, (v, lo, hi) in dag.nodes.items():
            if v in fixed:
                values[n] = values[hi if fixed[v] else lo]
            else:
                require(v in rename, 'unmapped function bit')
                values[n] = self.ite(rename[v], values[hi], values[lo])
        return values[dag.roots[root]]


def validate_model(model):
    fs = {}
    allbits, cur, nxt = [], [], []
    for f in model['fields']:
        name = f['name']
        require(name not in fs, 'duplicate field')
        require(f['owner'] in ('ENV', 'SYS'), 'field owner')
        require(f['role'] in ('ENV', 'SYS', 'AUX'), 'field role')
        require((f['role'] == 'ENV') == (f['owner'] == 'ENV'), 'field owner/role inconsistency')
        values = f['values']
        require(len(values) == len(set(values)) == f['domain_size'] and len(values) > 0, 'field domain values')
        require(set(f['encoding']) == set(values), 'encoding values missing/extra')
        for phase, bucket in [('current', cur), ('next', nxt)]:
            bits = f[phase + '_bits']
            require(len(bits) == len(set(bits)), 'duplicate field bit')
            require(all(type(v) is int and v >= 0 for v in bits), 'invalid field bit')
            bucket.extend(bits)
            allbits.extend(bits)
            codes = []
            for value in values:
                enc = f['encoding'][value][phase]
                require(set(enc) == {str(b) for b in bits}, 'encoding bit coverage')
                require(all(type(v) is bool for v in enc.values()), 'encoding value type')
                codes.append(tuple(enc[str(b)] for b in bits))
            require(len(codes) == len(set(codes)), 'encoding not injective')
        fs[name] = f
    n = model['bdd_variable_count']
    require(len(allbits) == len(set(allbits)) == n and set(allbits) == set(range(n)), 'full model bit coverage')
    require(sorted(cur) == sorted(model['all_current_bits']) and sorted(nxt) == sorted(model['all_next_bits']), 'model phase roster')
    require(len(model['bdd_variable_order']) == n and set(model['bdd_variable_order']) == set(range(n)), 'model BDD order')
    return fs


def named_alignment(old, fresh, helper=False):
    a, b = validate_model(old), validate_model(fresh)
    expected = set(a) | ({'~envHelp'} if helper else set())
    require('~envHelp' not in a and set(b) == expected, 'field roster or AUX name mismatch')
    mapping = {}
    for name, x in a.items():
        y = b[name]
        for key in ('owner', 'role', 'domain_size'):
            require(x[key] == y[key], 'field metadata changed: ' + name + '/' + key)
        require(set(x['values']) == set(y['values']), 'field values changed')
        values = sorted(x['values'])
        for phase in ('current', 'next'):
            xb, yb = x[phase + '_bits'], y[phase + '_bits']
            require(len(xb) == len(yb), 'field bit width changed')
            columns = {}
            for bit in yb:
                signature = tuple(y['encoding'][value][phase][str(bit)] for value in values)
                require(signature not in columns, 'ambiguous bit encoding columns')
                columns[signature] = bit
            for bit in xb:
                signature = tuple(x['encoding'][value][phase][str(bit)] for value in values)
                require(signature in columns, 'changed value encoding')
                require(bit not in mapping, 'old bit mapped twice')
                mapping[bit] = columns[signature]
    require(len(mapping) == old['bdd_variable_count'] and len(set(mapping.values())) == len(mapping), 'nonbijective source map')
    if helper:
        h = b['~envHelp']
        require(h['owner'] == h['role'] == 'ENV' and h['domain_size'] == 2 and set(h['values']) == {'false', 'true'}, 'helper type')
        for phase in ('current', 'next'):
            require(len(h[phase + '_bits']) == 1, 'helper bit width')
            bit = h[phase + '_bits'][0]
            require(h['encoding']['false'][phase][str(bit)] is False and h['encoding']['true'][phase][str(bit)] is True, 'helper Boolean encoding')
    return mapping


def encode(model, valuation, phase='current'):
    fs = {f['name']: f for f in model['fields']}
    out = {}
    for name, value in valuation.items():
        require(name in fs and value in fs[name]['encoding'], 'unknown typed value')
        for bit, flag in fs[name]['encoding'][value][phase].items():
            require(int(bit) not in out, 'overlapping assignment')
            out[int(bit)] = flag
    return out


def valuations(model, owner=None):
    fs = [f for f in model['fields'] if owner is None or f['owner'] == owner]
    for values in itertools.product(*(f['values'] for f in fs)):
        yield dict(zip((f['name'] for f in fs), values))


def load_ref(folder, ref, model):
    p = Path(folder) / ref['file']
    require(p.stat().st_size == ref['bytes'] and sha(p) == ref['sha256'], 'BDD reference hash')
    d = DAG.raw(p.read_text(), model['bdd_variable_count'], model['bdd_variable_order'])
    require(len(d.nodes) == ref['node_count'], 'BDD reference node count')
    require(sorted(d.support()) == ref['support'], 'BDD reference support')
    return d


def load_bundle(folder):
    folder = Path(folder)
    m = json.loads((folder / 'model.json').read_text())
    validate_model(m)
    ds = {k: load_ref(folder, r, m) for k, r in m['original_bdds'].items()}
    for owner in ('ENV', 'SYS'):
        for i, ref in enumerate(m['original_justices'][owner]):
            ds[owner + '_justice_' + str(i)] = load_ref(folder, ref, m)
    return m, ds


PREDICATES = ['thetaE', 'thetaS', 'rhoE', 'rhoS', 'domain', 'domain_ENV_next', 'domain_SYS_next']


def justice_keys(predicates, owner):
    keys = [k for k in predicates if k.startswith(owner + '_justice_')]
    keys.sort(key=lambda k: int(k.rsplit('_', 1)[1]))
    require(keys == [owner + '_justice_' + str(i) for i in range(len(keys))], 'justice indices')
    return keys


def correspondence(old, old_dags, fresh, fresh_dags, helper, exact_metadata=False):
    mapping = named_alignment(old, fresh, helper)
    if exact_metadata:
        for key in ('fields', 'public_fields', 'all_current_bits', 'all_next_bits', 'bdd_variable_count', 'bdd_variable_order'):
            require(old[key] == fresh[key], 'exact metadata mismatch: ' + key)
    inverse = {v: k for k, v in mapping.items()}
    c = BooleanFunctions()
    fixed0, fixed00 = {}, {}
    hcur = hnext = None
    if helper:
        hf = {f['name']: f for f in fresh['fields']}['~envHelp']
        hcur, hnext = hf['current_bits'][0], hf['next_bits'][0]
        inverse[hcur] = old['bdd_variable_count']
        inverse[hnext] = old['bdd_variable_count'] + 1
        fixed0 = {hcur: False}
        fixed00 = {hcur: False, hnext: False}
    checks = {}
    for key in PREDICATES:
        restriction = fixed00 if key in ('rhoE', 'rhoS', 'domain_ENV_next', 'domain_SYS_next') else fixed0
        lhs = c.import_dag(old_dags[key])
        rhs = c.import_dag(fresh_dags[key], rename=inverse, fixed=restriction)
        checks[key] = lhs == rhs
        require(checks[key], 'predicate correspondence: ' + key)
    removed = None
    for owner in ('ENV', 'SYS'):
        oldkeys, newkeys = justice_keys(old_dags, owner), justice_keys(fresh_dags, owner)
        require(len(newkeys) == len(oldkeys) + int(helper and owner == 'ENV'), 'ordered justice count')
        if helper and owner == 'ENV':
            hfalse = c.neg(c.variable(inverse[hcur]))
            matches = [k for k in newkeys if c.import_dag(fresh_dags[k], rename=inverse) == hfalse]
            require(len(matches) == 1, 'exact unique helper justice')
            removed = matches[0]
            newkeys = [k for k in newkeys if k != removed]
        for lhskey, rhskey in zip(oldkeys, newkeys):
            lhs = c.import_dag(old_dags[lhskey])
            rhs = c.import_dag(fresh_dags[rhskey], rename=inverse, fixed=fixed0)
            require(lhs == rhs, 'ordered justice correspondence: ' + lhskey)
            checks[lhskey] = True
    if helper:
        require(c.import_dag(fresh_dags['rhoE'], rename=inverse, fixed={hcur: True, hnext: False}) == 0, 'helper persistence E10')
        require(c.import_dag(fresh_dags['thetaE'], rename=inverse, fixed={hcur: True}) == 0, 'helper must initialize false')
    return {'checks': checks, 'old_to_fresh_bits': mapping, 'helper_removed_justice': removed, 'helper_slice': 'false' if helper else 'N/A'}


def full_unchanged(before, after):
    require(set(before) == set(after), 'full snapshot function roster')
    c = BooleanFunctions()
    for key in before:
        require(c.import_dag(before[key]) == c.import_dag(after[key]), 'full snapshot changed: ' + key)
    return True


def typed_region(model, dag, root='root'):
    require(dag.support(root) <= set(model['all_current_bits']), 'region has next-bit dependency')
    return [dag.point(encode(model, state), root) for state in valuations(model)]


def require_typed_region(model, region, domain):
    require(region.support() <= set(model['all_current_bits']), 'region has next-bit dependency')
    c = BooleanFunctions()
    require(c.both(c.import_dag(region), c.neg(c.import_dag(domain))) == 0, 'typed region admits invalid encoding')


def verify_w_exports(model, raw, typed, domain, source_view, helper):
    current = set(model['all_current_bits'])
    require(raw.support() <= current and typed.support() <= current, 'W export next-bit dependency')
    c = BooleanFunctions()
    require(c.both(c.import_dag(raw), c.import_dag(domain)) == c.import_dag(typed), 'typed W differs from raw W intersect domain')
    fixed = {}
    allowed = set(current)
    if helper:
        hf = {f['name']: f for f in model['fields']}['~envHelp']
        h = hf['current_bits'][0]
        fixed[h] = False
        allowed.remove(h)
    require(source_view.support() <= allowed, 'source view has helper or next dependency')
    require(c.import_dag(typed, fixed=fixed) == c.import_dag(source_view), 'source view differs from exact false restriction')
    return True


def initialization(model, thetaE, thetaS, region, root='root'):
    fields = validate_model(model)
    envbits = {b for f in fields.values() if f['owner'] == 'ENV' for b in f['current_bits']}
    require(thetaE.support() <= envbits, 'thetaE depends on SYS or next variables')
    require(thetaS.support() <= set(model['all_current_bits']), 'thetaS has next dependency')
    require(region.support(root) <= set(model['all_current_bits']), 'W has next dependency')
    sysvals = list(valuations(model, 'SYS'))
    missing, witnesses = [], []
    legal = 0
    for env in valuations(model, 'ENV'):
        if not thetaE.point(encode(model, env)):
            continue
        legal += 1
        witness = None
        for system in sysvals:
            a = encode(model, dict(env, **system))
            if thetaS.point(a) and region.point(a, root):
                witness = system
                break
        if witness is None:
            missing.append(env)
        else:
            witnesses.append({'ENV': env, 'SYS_including_AUX': witness})
    return {'value': not missing, 'legal_ENV_fibers': legal, 'missing_ENV_fibers': missing, 'witnesses': witnesses}


def mask_comparison(native, route, symbolic, cooperative):
    require(len(native) == len(route) == len(symbolic) == len(cooperative), 'mask lengths')
    cells = []
    for n, r, w, k in zip(native, route, symbolic, cooperative):
        cells.append({'native': int(n), 'route': int(r), 'symbolic_W': int(w), 'K': int(k), 'native_minus_symbolic': int(n and not w), 'symbolic_minus_native': int(w and not n), 'loss': int(n and not r), 'gain': int(r and not n), 'K_intersect_loss': int(k and n and not r), 'K_minus_route': int(k and not r)})
    counts = {key: sum(row[key] for row in cells) for key in cells[0]} if cells else {}
    return counts, cells


def load_derived(path, reference_model):
    obj = json.loads(gzip.decompress(Path(path).read_bytes()))
    require(obj['schema'] == 'independent-canonical-robdd-region-set-v1', 'derived region schema')
    m = {'fields': obj['fields'], 'bdd_variable_count': obj['variable_count'], 'bdd_variable_order': obj['canonical_variable_order'], 'all_current_bits': [b for f in obj['fields'] for b in f['current_bits']], 'all_next_bits': [b for f in obj['fields'] for b in f['next_bits']]}
    named_alignment(reference_model, m)
    require(obj['fields'] == reference_model['fields'], 'derived/source full field binding')
    require('W' in obj['roots'] and 'K' in obj['roots'], 'derived W/K roots')
    return DAG(obj['nodes'], obj['roots'], obj['variable_count'], obj['canonical_variable_order'])


def audit_saved_case(case, original_folder, route_folder, output_folder):
    """Scientific saved-data call; callers must validate separately frozen root GO."""
    old, oldds = load_bundle(case['saved_original_directory'])
    native, nds = load_bundle(original_folder)
    route, rds = load_bundle(route_folder)
    helper = case['expected_helper_introduced_on_route']
    native_gate = correspondence(old, oldds, native, nds, False, True)
    route_gate = correspondence(old, oldds, route, rds, helper, not helper)
    nr = json.loads((Path(original_folder) / 'RESULT.json').read_text())
    rr = json.loads((Path(route_folder) / 'RESULT.json').read_text())
    for folder, model, predicates, result in [(original_folder, native, nds, nr), (route_folder, route, rds, rr)]:
        require(result['status'] == 'PASS_COMPLETE' and result['strict_memory_complete'] is True, 'native result incomplete')
        require(result['native_strict_solver_calls'] == 1, 'native call count')
        snapshots = [{k: load_ref(folder, v, model) for k, v in result['full_model_' + phase].items()} for phase in ('before_constructor', 'after_constructor', 'after_solve')]
        fullkeys = ['thetaE', 'thetaS', 'rhoE', 'rhoS'] + justice_keys(predicates, 'ENV') + justice_keys(predicates, 'SYS')
        full_unchanged({k: predicates[k] for k in fullkeys}, snapshots[0])
        full_unchanged(snapshots[0], snapshots[1])
        full_unchanged(snapshots[0], snapshots[2])
    nw = load_ref(original_folder, nr['winning_region_typed'], native)
    rw = load_ref(route_folder, rr['winning_region_typed'], route)
    rv = load_ref(route_folder, rr['winning_region_source_view'], route)
    nraw = load_ref(original_folder, nr['winning_region_raw'], native)
    rraw = load_ref(route_folder, rr['winning_region_raw'], route)
    nv = load_ref(original_folder, nr['winning_region_source_view'], native)
    verify_w_exports(native, nraw, nw, nds['domain'], nv, False)
    verify_w_exports(route, rraw, rw, rds['domain'], rv, helper)
    require_typed_region(native, nw, nds['domain'])
    require_typed_region(route, rw, rds['domain'])
    symbolic = load_derived(case['derived_regions']['path'], old)
    original_mask, route_mask, symbolic_mask, k_mask = [], [], [], []
    state_rows = []
    for state in valuations(old):
        n = nw.point(encode(native, state))
        route_state = dict(state, **{'~envHelp': 'false'}) if helper else state
        r = rw.point(encode(route, route_state))
        require(r == rv.point(encode(route, route_state)), 'saved source view polarity/membership')
        a = encode(old, state)
        original_mask.append(n)
        route_mask.append(r)
        symbolic_mask.append(symbolic.point(a, 'W'))
        k_mask.append(symbolic.point(a, 'K'))
        state_rows.append(state)
    counts, cells = mask_comparison(original_mask, route_mask, symbolic_mask, k_mask)
    initial = {
        'native_original': initialization(native, nds['thetaE'], nds['thetaS'], nw),
        'native_route': initialization(route, rds['thetaE'], rds['thetaS'], rw),
        'saved_symbolic_W': initialization(old, oldds['thetaE'], oldds['thetaS'], symbolic, 'W'),
        'saved_symbolic_K': initialization(old, oldds['thetaE'], oldds['thetaS'], symbolic, 'K'),
    }
    require(initial['native_original']['value'] == nr['actual_initializer_realizable'], 'native original initializer disagreement')
    require(initial['native_route']['value'] == rr['actual_initializer_realizable'], 'native route initializer disagreement')
    out = Path(output_folder)
    out.mkdir(parents=True, exist_ok=False)
    with (out / 'ALL_TYPED_STATES.csv').open('w', newline='') as stream:
        keys = list(state_rows[0]) + list(cells[0])
        writer = csv.DictWriter(stream, fieldnames=['state_id'] + keys)
        writer.writeheader()
        for i, (state, cell) in enumerate(zip(state_rows, cells)):
            writer.writerow(dict(state, **cell, state_id=i))
    result = {'status': 'PASS' if counts['native_minus_symbolic'] == counts['symbolic_minus_native'] == 0 else 'CONTRADICTORY_NATIVE_ORIGINAL_W', 'case_id': case['id'], 'counts': counts, 'state_count': len(cells), 'original_correspondence': native_gate, 'route_correspondence': route_gate, 'helper_slice': 'false' if helper else 'N/A', 'initialization': initial, 'new_native_calls_by_auditor': 0, 'K_source': 'pre-existing independent symbolic certificate', 'reachability_claim': 'none'}
    (out / 'AUDIT_RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    return result
