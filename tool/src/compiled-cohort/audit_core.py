"""Independent compiled-helper audit from primitive exported BDDs.

Never imports producer verdicts, native code, or producer-derived regions as
an oracle. Native W is a comparison target only. No execution at import.
"""
import gzip
import hashlib
import json
import math
from functools import lru_cache
from pathlib import Path

import prior_binding as binding
from symbolic import BDD, Operations, count, fixed, gr1_three, initial_quantification, root_digest


class GateFailure(ValueError):
    pass


def require(test, message):
    if not test:
        raise GateFailure(message)


def read(path):
    def unique(pairs):
        result = {}
        for k, v in pairs:
            require(k not in result, 'duplicate JSON key: ' + k)
            result[k] = v
        return result
    return json.loads(Path(path).read_text(), object_pairs_hook=unique)


def pin(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def restrict(b, root, assignment):
    @lru_cache(None)
    def visit(u):
        if u < 2:
            return u
        v, lo, hi = b.nodes[u]
        if v in assignment:
            return visit(hi if assignment[v] else lo)
        return b.mk(v, visit(lo), visit(hi))
    return visit(root)


def alignment(source, model, helper_expected):
    a, z = binding.validate_model(source), binding.validate_model(model)
    extras = set(z) - set(a)
    require(set(a) <= set(z) and len(extras) == int(helper_expected), 'source/AUX field roster')
    helper = next(iter(extras)) if extras else None
    mapping = {}
    for name, old in a.items():
        new = z[name]
        require(all(old[k] == new[k] for k in ('owner', 'role', 'domain_size')), 'field metadata: ' + name)
        require(set(old['values']) == set(new['values']), 'typed values: ' + name)
        values = sorted(old['values'])
        for phase in ('current', 'next'):
            ob, nb = old[phase + '_bits'], new[phase + '_bits']
            require(len(ob) == len(nb), 'field width: ' + name)
            columns = {}
            for bit in ob:
                sig = tuple(old['encoding'][value][phase][str(bit)] for value in values)
                require(sig not in columns, 'ambiguous source bit encoding')
                columns[sig] = bit
            for bit in nb:
                sig = tuple(new['encoding'][value][phase][str(bit)] for value in values)
                require(sig in columns, 'field value encoding: ' + name)
                mapping[bit] = columns[sig]
    if helper:
        h = z[helper]
        require(h['owner'] == h['role'] == 'ENV' and set(h['values']) == {'false', 'true'} and h['domain_size'] == 2, 'helper owner/domain')
        for phase, bit in [('current', source['bdd_variable_count']), ('next', source['bdd_variable_count'] + 1)]:
            hb = h[phase + '_bits']
            require(len(hb) == 1 and h['encoding']['false'][phase][str(hb[0])] is False and h['encoding']['true'][phase][str(hb[0])] is True, 'helper Boolean encoding')
            mapping[hb[0]] = bit
    require(len(mapping) == model['bdd_variable_count'] and len(set(mapping.values())) == len(mapping), 'nonbijective model alignment')
    return mapping, helper


class Arena:
    def __init__(self, model):
        binding.validate_model(model)
        self.model = model
        self.n = model['bdd_variable_count']
        self.b = BDD(self.n + 2, node_limit=500000)
        self.h, self.hp = self.n, self.n + 1
        self.current, self.en, self.sn, self.ec, self.sc, self.prime = [], [], [], [], [], {}
        self.domains = {(o, p): 1 for o in ('ENV', 'SYS') for p in ('current', 'next')}
        for f in model['fields']:
            cb, nb = f['current_bits'], f['next_bits']
            require(len(cb) == len(nb), 'current/next bit widths')
            for value in f['values']:
                require([f['encoding'][value]['current'][str(x)] for x in cb] == [f['encoding'][value]['next'][str(x)] for x in nb], 'current/next encoding mismatch')
            self.current.extend(cb)
            self.prime.update(zip(cb, nb))
            (self.ec if f['owner'] == 'ENV' else self.sc).extend(cb)
            (self.en if f['owner'] == 'ENV' else self.sn).extend(nb)
            for phase in ('current', 'next'):
                d = self.b.disj(*(self.b.cube({int(k): v for k, v in f['encoding'][value][phase].items()}) for value in f['values']))
                key = (f['owner'], phase)
                self.domains[key] = self.b.conj(self.domains[key], d)
        self.current = sorted(self.current)
        self.de, self.ds = self.domains['ENV', 'current'], self.domains['SYS', 'current']
        self.den, self.dsn = self.domains['ENV', 'next'], self.domains['SYS', 'next']
        self.q = self.b.conj(self.de, self.ds)
        self.carrier = math.prod(f['domain_size'] for f in model['fields'])
        require(count(self.b, self.q, self.current) == self.carrier, 'typed cardinality')

    def ops(self, e, s, full=False):
        current = self.current + ([self.h] if full else [])
        en = self.en + ([self.hp] if full else [])
        prime = dict(self.prime, **{})
        if full:
            prime[self.h] = self.hp
        return Operations(self.b, self.q, e, s, self.den, self.dsn, current, en, self.sn, prime)

    def strict(self, e, s, aa, gg, full=False):
        log = {}
        ops = self.ops(e, s, full)
        result = gr1_three(self.b, self.q, aa, gg, ops.cpre, log)
        return result, log

    def initial(self, e, s, region, full=False):
        r = initial_quantification(self.b, self.de, e, s, region, self.sc)
        bits = self.ec + ([self.h] if full else [])
        return {'value': r['value'], 'missing_ENV_count': count(self.b, r['missing_environment_initials'], bits), 'missing_ENV_digest': root_digest(self.b, r['missing_environment_initials'])}

    def state(self, bits):
        out = {}
        for f in self.model['fields']:
            values = [v for v in f['values'] if all(bits[int(k)] == flag for k, flag in f['encoding'][v]['current'].items())]
            require(len(values) == 1, 'witness typed decoding')
            out[f['name']] = values[0]
        return out

    def describe(self, root, full=False):
        bits = self.current + ([self.h] if full else [])
        require(self.b.support(root) <= set(bits), 'state region depends on next variables')
        require(self.b.conj(root, self.b.neg(self.q)) == 0, 'state region outside typed domain')
        return {'count': count(self.b, root, bits), 'canonical_sha256': root_digest(self.b, root)}

    def compare(self, left, right, full=False):
        b = self.b
        loss, gain = b.conj(left, b.neg(right)), b.conj(right, b.neg(left))
        result = {'equal': left == right, 'left_minus_right': self.describe(loss, full), 'right_minus_left': self.describe(gain, full)}
        for key, root in [('left_minus_right', loss), ('right_minus_left', gain)]:
            if root:
                bits = b.satone(root, self.current + ([self.h] if full else []))
                result[key]['witness'] = self.state(bits)
                if full:
                    result[key]['witness']['@helper'] = bits[self.h]
        return result


class Bundle:
    def __init__(self, folder, arena, helper=False):
        self.folder, self.a = Path(folder), arena
        self.model = read(self.folder / 'model.json')
        require(self.model.get('schema') == 'k7-native-model-export-v1', 'model schema')
        require(self.model['public_fields'] == {o: [f['name'] for f in self.model['fields'] if f['role'] == o] for o in ('ENV', 'SYS')}, 'public/AUX field roster')
        self.mapping, self.helper = alignment(arena.model, self.model, helper)
        self.pins, self.cache = [pin(self.folder / 'model.json')], {}
        required = {'thetaE', 'thetaS', 'rhoE', 'rhoS', 'domain', 'domain_ENV_next', 'domain_SYS_next'}
        require(set(self.model['original_bdds']) == required, 'original BDD roster')
        self.forms = {k: self.load(v) for k, v in self.model['original_bdds'].items()}
        self.justices = {owner: [self.load(r) for r in self.model['original_justices'][owner]] for owner in ('ENV', 'SYS')}
        b, f, a = arena.b, self.forms, arena
        require((f['domain'], f['domain_ENV_next'], f['domain_SYS_next']) == (a.q, a.den, a.dsn), 'typed domains differ from source encodings')
        ec = set(a.ec) | ({a.h} if helper else set())
        current = set(a.current) | ({a.h} if helper else set())
        en = set(a.en) | ({a.hp} if helper else set())
        require(b.support(f['thetaE']) <= ec, 'ENV init response dependency')
        require(b.support(f['thetaS']) <= current, 'SYS init next dependency')
        require(b.support(f['rhoE']) <= current | en, 'ENV relation next SYS dependency')
        require(all(b.support(j) <= current for js in self.justices.values() for j in js), 'justice next dependency')
        # A complete post-translation reduction may OR true into raw relations
        # outside valid next encodings. Typed quantifiers impose den/dsn; this
        # is recorded and is not a theorem failure on the typed carrier.
        self.raw_initializer_domain_diagnostics = {k: b.conj(f[k], b.neg(domain)) == 0 for k, domain in [('thetaE', a.de), ('thetaS', a.ds)]}

    def load(self, ref):
        name = ref['file']
        require(Path(name).name == name and name.endswith('.bdd'), 'unsafe BDD reference')
        if name in self.cache:
            root, oldref = self.cache[name]
            require(ref == oldref, 'conflicting BDD reference')
            return root
        path = self.folder / name
        raw = path.read_bytes()
        require(len(raw) == ref['bytes'] and hashlib.sha256(raw).hexdigest() == ref['sha256'], 'BDD pin mismatch: ' + name)
        require(len(raw) <= 8 * 1024**2, 'BDD input size cap')
        dag = binding.DAG.raw(raw.decode('ascii'), self.model['bdd_variable_count'], self.model['bdd_variable_order'])
        require(len(dag.nodes) == ref['node_count'] and sorted(dag.support()) == ref['support'], 'BDD graph metadata')
        require(len(set(dag.nodes.values())) == len(dag.nodes), 'duplicate canonical native node')
        b, roots = self.a.b, {0: 0, 1: 1}
        for nid, (v, lo, hi) in dag.nodes.items():
            roots[nid] = b.ite(b.var(self.mapping[v]), roots[hi], roots[lo])
        root = roots[dag.roots['root']]
        require((root == 0) == ref.get('zero', root == 0) and (root == 1) == ref.get('one', root == 1), 'BDD constant metadata')
        self.cache[name] = root, ref
        self.pins.append(pin(path))
        return root

    def native(self):
        r = read(self.folder / 'RESULT.json')
        self.pins.append(pin(self.folder / 'RESULT.json'))
        require(r['status'] == 'PASS_COMPLETE' and r['strict_memory_complete'] is True, 'native result incomplete')
        require(r['native_strict_solver_calls'] == 1, 'native call count')
        originals = {k: v for k, v in self.forms.items() if k in ('thetaE', 'thetaS', 'rhoE', 'rhoS')}
        for owner in ('ENV', 'SYS'):
            originals.update({owner + '_justice_' + str(i): v for i, v in enumerate(self.justices[owner])})
        normalized = dict(originals)
        normalized_owners = []
        for owner in ('ENV', 'SYS'):
            if not self.justices[owner]:
                normalized[owner + '_justice_0'] = 1
                normalized_owners.append(owner)
        for phase in ('before_constructor', 'after_constructor', 'after_solve'):
            snap = {k: self.load(v) for k, v in r['full_model_' + phase].items()}
            expected = originals if phase == 'before_constructor' else normalized
            require(snap == expected, 'native relation/justice mutation beyond empty-list TRUE normalization: ' + phase)
        raw, typed, view = (self.load(r[k]) for k in ('winning_region_raw', 'winning_region_typed', 'winning_region_source_view'))
        b, a = self.a.b, self.a
        current = set(a.current) | ({a.h} if self.helper else set())
        require(b.support(raw) <= current, 'native W next dependency')
        require(b.conj(raw, a.q) == typed, 'native raw/typed W binding')
        expected_view = restrict(b, typed, {a.h: False}) if self.helper else typed
        require(view == expected_view, 'native helper-false view binding')
        init = a.initial(self.forms['thetaE'], self.forms['thetaS'], typed, bool(self.helper))
        require(init['value'] == r['actual_initializer_realizable'], 'native initializer quantification mismatch')
        return typed, {'initialization': init, 'snapshots_unchanged_except_empty_justice_TRUE_normalization': True, 'empty_justice_TRUE_normalized_owners': normalized_owners, 'raw_initializer_domain_diagnostics': self.raw_initializer_domain_diagnostics, 'native_calls': r['native_strict_solver_calls']}


def quadrants(bundle):
    a, b = bundle.a, bundle.a.b
    require(bundle.helper is not None, 'quadrants require helper')
    return {side + str(i) + str(j): restrict(b, bundle.forms[key], {a.h: bool(i), a.hp: bool(j)}) for side, key in [('E', 'rhoE'), ('S', 'rhoS')] for i in (0, 1) for j in (0, 1)}


def correspondence(source, arm):
    a, b = source.a, source.a.b
    qd = quadrants(arm)
    raw = {'E00_source': qd['E00'] == source.forms['rhoE'], 'S00_source': qd['S00'] == source.forms['rhoS'], 'E10_false': qd['E10'] == 0}
    def eq(left, right, mask):
        return b.conj(mask, left) == b.conj(mask, right)
    env_mask, edge_mask = b.conj(a.q, a.den), b.conj(a.q, a.den, a.dsn)
    checks = {'E00_source': eq(qd['E00'], source.forms['rhoE'], env_mask), 'S00_source': eq(qd['S00'], source.forms['rhoS'], edge_mask), 'E10_false': eq(qd['E10'], 0, env_mask)}
    h = b.var(a.h)
    raw['thetaE_source_and_not_helper'] = arm.forms['thetaE'] == b.conj(source.forms['thetaE'], b.neg(h))
    raw['thetaS_source_globally'] = arm.forms['thetaS'] == source.forms['thetaS']
    checks['thetaE_source_and_not_helper'] = eq(arm.forms['thetaE'], b.conj(source.forms['thetaE'], b.neg(h)), a.q)
    checks['thetaS_source_globally'] = eq(arm.forms['thetaS'], source.forms['thetaS'], a.q)
    candidates = [i for i, root in enumerate(arm.justices['ENV']) if eq(root, b.neg(h), a.q)]
    raw['one_exact_helper_justice'] = sum(root == b.neg(h) for root in arm.justices['ENV']) == 1
    checks['one_exact_helper_justice'] = len(candidates) == 1
    for owner in ('ENV', 'SYS'):
        js = list(arm.justices[owner])
        if owner == 'ENV' and len(candidates) == 1:
            js.pop(candidates[0])
        checks[owner + '_justice_count'] = len(js) == len(source.justices[owner])
        raw[owner + '_justice_source_at_0'] = len(js) == len(source.justices[owner]) and all(restrict(b, n, {a.h: False}) == old for n, old in zip(js, source.justices[owner]))
        checks[owner + '_justice_source_at_0'] = len(js) == len(source.justices[owner]) and all(eq(restrict(b, n, {a.h: False}), old, a.q) for n, old in zip(js, source.justices[owner]))
    arm.correspondence_raw_diagnostics = raw
    return checks, qd


def derive_retained(arena, source, qd):
    b, q = arena.b, arena.q
    logs = {'U': {}}
    postflip = arena.ops(qd['E11'], qd['S11'])
    u = fixed(b, q, postflip.cpre, True, 'nu_U', logs['U'])
    f = arena.ops(qd['E01'], qd['S01']).cpre(u)
    sf = b.conj(f, source.forms['rhoS'], b.rename(f, arena.prime))
    wfraw, logs['WF'] = arena.strict(source.forms['rhoE'], sf, source.justices['ENV'], source.justices['SYS'])
    wf = b.conj(f, wfraw)
    return {'U': u, 'F': f, 'W_F': wf, 'unintersected_strict_MF': wfraw}, logs


def export_regions(path, arena, roots):
    b, seen, order = arena.b, set(), []
    def visit(u):
        if u < 2 or u in seen:
            return
        seen.add(u)
        v, lo, hi = b.nodes[u]
        visit(lo); visit(hi)
        order.append([u, v, lo, hi])
    for root in roots.values():
        visit(root)
    obj = {'schema': 'v71-independent-canonical-regions-v1', 'variable_count': b.n, 'source_fields': arena.model['fields'], 'helper_current_bit': arena.h, 'helper_next_bit': arena.hp, 'roots': roots, 'nodes': order}
    Path(path).write_bytes(gzip.compress(json.dumps(obj, separators=(',', ':')).encode(), mtime=0))


def audit_arm(saved_source, original_folder, arm_folder, arm_name, output, syntactic_folder=None):
    """Caller must enforce authorization, one attempt and process budgets."""
    old = read(Path(saved_source) / 'model.json')
    arena = Arena(old)
    source = Bundle(saved_source, arena)
    native_source = Bundle(original_folder, arena)
    require(source.forms == native_source.forms and source.justices == native_source.justices, 'new source differs from pinned prior primitive model')
    nw, source_receipt = native_source.native()
    a, b = arena, arena.b
    w, wlog = a.strict(source.forms['rhoE'], source.forms['rhoS'], source.justices['ENV'], source.justices['SYS'])
    comparisons = {'source_native_vs_independent': a.compare(nw, w)}
    roots, logs = {'source_W': w, 'native_source_W': nw}, {'source_W': wlog}
    results = {'source': source_receipt}
    gates = {'source_exact_primitive_correspondence': True}
    loaded = [source, native_source]
    skipped_complete = False
    if arm_name == 'D':
        selected_model = read(Path(arm_folder) / 'model.json')
        skipped_complete = {f['name'] for f in selected_model['fields']} == {f['name'] for f in old['fields']}
    if skipped_complete:
        arm = Bundle(arm_folder, a, helper=False)
        loaded.append(arm)
        rw, native_receipt = arm.native()
        native_meta = read(Path(arm_folder) / 'RESULT.json')
        gates['D_skip_source_rhoE_raw_isOne'] = source.forms['rhoE'] == 1
        gates['D_skip_exact_source_primitive_identity'] = arm.forms == source.forms and arm.justices == source.justices
        gates['D_skip_metadata'] = native_meta.get('helper_introduced') is False and native_meta.get('conversion_skipped') is True and native_meta.get('complete_semantic_identity_skip') is True and native_meta.get('semantic_skip_precondition') is True
        comparisons['D_skipped_native_vs_source_W'] = a.compare(rw, w)
        roots['native_skipped_D_W'] = rw
        results.update(arm=native_receipt, complete_semantic_identity_skip=True, helper_slice='N/A', theorem_application='N/A_NO_HELPER_IDENTITY_BRANCH')
    elif arm_name != 'A':
        arm = Bundle(arm_folder, a, helper=True)
        loaded.append(arm)
        rw, native_receipt = arm.native()
        results['arm'] = native_receipt
        arm_gates, qd = correspondence(source, arm)
        gates.update(arm_gates)
        results['source_correspondence_raw_boolean_diagnostics'] = arm.correspondence_raw_diagnostics
        # Record all quadrants even when theorem preconditions fail.
        roots.update(qd)
        if arm_name == 'C':
            require(syntactic_folder is not None, 'C requires saved B primitive relations')
            prior = Bundle(syntactic_folder, a, helper=True)
            loaded.append(prior)
            bqd = quadrants(prior)
            gates['C_ENV_all_quadrants_unchanged'] = all(qd['E' + ij] == bqd['E' + ij] for ij in ('00', '01', '10', '11'))
            gates['C_SYS_other_quadrants_unchanged'] = all(qd['S' + ij] == bqd['S' + ij] for ij in ('00', '10', '11'))
            gates['C_SYS01_total_typed'] = b.conj(a.q, a.den, a.dsn, qd['S01']) == b.conj(a.q, a.den, a.dsn)
            gates['C_initializer_and_justice_unchanged'] = all(arm.forms[k] == prior.forms[k] for k in ('thetaE', 'thetaS')) and arm.justices == prior.justices
        if arm_name == 'D':
            gates['D_complete_ENV'] = all(b.conj(a.q, a.den, qd['E' + ij]) == b.conj(a.q, a.den) for ij in ('01', '11')) and qd['E10'] == 0
            gates['D_complete_SYS_release'] = all(b.conj(a.q, a.den, a.dsn, qd['S' + ij]) == b.conj(a.q, a.den, a.dsn) for ij in ('01', '10', '11'))
        independently_full, logs['full_transformed_W'] = a.strict(arm.forms['rhoE'], arm.forms['rhoS'], arm.justices['ENV'], arm.justices['SYS'], full=True)
        comparisons['native_full_vs_independent_strict'] = a.compare(rw, independently_full, True)
        rf, rt = restrict(b, rw, {a.h: False}), restrict(b, rw, {a.h: True})
        roots.update(native_full_W=rw, independent_full_W=independently_full, native_helper_false=rf, native_helper_true=rt, source_loss=b.conj(w, b.neg(rf)), source_gain=b.conj(rf, b.neg(w)))
        comparisons['source_vs_native_helper_false'] = a.compare(w, rf)
        if all(gates.values()):
            derived, retained_logs = derive_retained(a, source, qd)
            roots.update(derived); logs.update(retained_logs)
            comparisons['native_helper_true_vs_U'] = a.compare(rt, derived['U'])
            comparisons['native_helper_false_vs_WF'] = a.compare(rf, derived['W_F'])
            comparisons['U_vs_D'] = a.compare(derived['U'], a.q)
            comparisons['F_vs_D'] = a.compare(derived['F'], a.q)
            roots['source_W_outside_F'] = b.conj(w, b.neg(derived['F']))
            results['preservation_iff_W_subset_F'] = (w == rf) == (roots['source_W_outside_F'] == 0)
            results['predicted_initialization'] = a.initial(source.forms['thetaE'], source.forms['thetaS'], derived['W_F'])
            results['initialization_matches_prediction'] = results['predicted_initialization']['value'] == native_receipt['initialization']['value']
            if arm_name == 'D':
                comparisons['D_helper_false_vs_source_W'] = a.compare(rf, w)
        else:
            results['theorem_application'] = 'DECLINED_PRECONDITION_MISMATCH'
    observed_comparisons = ['source_native_vs_independent', 'native_full_vs_independent_strict', 'native_helper_true_vs_U', 'native_helper_false_vs_WF', 'D_helper_false_vs_source_W', 'D_skipped_native_vs_source_W']
    mismatch = any(not comparisons[k]['equal'] for k in observed_comparisons if k in comparisons)
    mismatch |= any(results.get(k) is False for k in ('preservation_iff_W_subset_F', 'initialization_matches_prediction'))
    status = 'THEOREM_PRECONDITION_MISMATCH' if not all(gates.values()) else ('MISMATCH' if mismatch else 'PASS')
    if status == 'PASS' and skipped_complete:
        status = 'PASS_CORRECTION_SKIPPED_SOURCE_IDENTITY'
    summaries = {k: a.describe(v, k in ('native_full_W', 'independent_full_W')) for k, v in roots.items() if not (k[0] in ('E', 'S') and len(k) == 3)}
    quadrants_info = {k: {'canonical_sha256': root_digest(b, v), 'support': sorted(b.support(v))} for k, v in roots.items() if k[0] in ('E', 'S') and len(k) == 3}
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    export_regions(output / 'REGIONS.json.gz', a, roots)
    receipt = {'schema': 'v71-independent-compiled-cohort-audit-v1', 'status': status, 'arm': arm_name, 'typed_source_states': a.carrier, 'gates': gates, 'regions': summaries, 'quadrants': quadrants_info, 'comparisons': comparisons, 'results': results, 'fixed_point_logs': logs, 'source_model_pin': pin(Path(saved_source) / 'model.json'), 'primitive_input_pins': [p for x in loaded for p in x.pins], 'independence': 'Compiler-shared symbolic check of native saved primitive relations; independent Boolean importer, quantification and fixed points; not independent compilation or external reproduction.', 'new_native_calls_by_auditor': 0, 'saved_producer_derived_verdict_used_as_oracle': False, 'canonical_nodes_created': len(b.nodes), 'regions_file': pin(output / 'REGIONS.json.gz')}
    save(output / 'AUDIT_RESULT.json', receipt)
    return receipt
