"""Unchanged independent I/O, saved-DAG, and finite-graph core blocks. No scientific side effects."""
from pathlib import Path
import hashlib
import json

class AuditError(ValueError):
    pass


def need(value, reason):
    if not value:
        raise AuditError(reason)


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        need(key not in out, 'Duplicate JSON key: ' + key)
        out[key] = value
    return out


def decode_json(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def pin(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def read_pin(ref):
    path = Path(ref['path'])
    need(path.is_absolute() and not path.is_symlink(), 'Absolute regular pinned input required')
    raw = path.read_bytes()
    need(len(raw) == ref['bytes'] and hashlib.sha256(raw).hexdigest() == ref['sha256'],
         'Input pin mismatch: ' + path.name)
    return raw


def save_new(path, value):
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    need(len(raw) < 16 * 1024 * 1024, 'Output file cap')
    with Path(path).open('xb') as stream:
        stream.write(raw)


class SavedDag:
    """Read the saved decision DAG and follow branches; never rebuild/apply BDDs."""
    def __init__(self, raw, variable_count, expected_order):
        need(len(raw) <= 8 * 1024 * 1024, 'Saved DAG input cap')
        rows = [line.split() for line in raw.decode('ascii').splitlines() if line.strip()]
        self.nodes = {}
        self.support = set()
        if rows == [['0', '0']] or rows == [['0', '1']]:
            self.root = int(rows[0][1])
            self.order = None
            return
        need(len(rows) >= 3 and rows[0] == [str(variable_count)], 'Saved DAG header')
        self.order = tuple(map(int, rows[1]))
        need(self.order == tuple(expected_order), 'Saved DAG/model variable order mismatch')
        need(len(self.order) == variable_count and set(self.order) == set(range(variable_count)),
             'Saved DAG variable permutation')
        levels = {var: level for level, var in enumerate(self.order)}
        seen_triples = set()
        for row in rows[2:]:
            need(len(row) == 4, 'Saved DAG node width')
            identity, variable, low, high = map(int, row)
            need(identity > 1 and identity not in self.nodes and variable in levels,
                 'Saved DAG node identity')
            need(low != high and all(child in (0, 1) or child in self.nodes for child in (low, high)),
                 'Saved DAG acyclic child order/reduction')
            triple = (variable, low, high)
            need(triple not in seen_triples, 'Saved DAG duplicate node')
            seen_triples.add(triple)
            for child in (low, high):
                need(child in (0, 1) or levels[self.nodes[child][0]] > levels[variable],
                     'Saved DAG ordered variables')
            self.nodes[identity] = triple
            self.support.add(variable)
            self.root = identity
        reachable = set()
        stack = [self.root]
        while stack:
            identity = stack.pop()
            if identity in (0, 1) or identity in reachable:
                continue
            reachable.add(identity)
            stack.extend(self.nodes[identity][1:])
        need(reachable == set(self.nodes), 'Saved DAG unreachable data')

    def value(self, assignment):
        identity = self.root
        while identity not in (0, 1):
            variable, low, high = self.nodes[identity]
            need(variable in assignment and type(assignment[variable]) is bool,
                 'Missing/non-Boolean DAG assignment')
            identity = high if assignment[variable] else low
        return identity == 1


def closure(vertices, edges):
    """Reflexive transitive closure by integer bitset Warshall, not a DFS SCC library."""
    ordered = sorted(vertices, key=lambda x: int(x))
    position = {vertex: i for i, vertex in enumerate(ordered)}
    rows = [1 << i for i in range(len(ordered))]
    for source, target in edges:
        if source in position and target in position:
            rows[position[source]] |= 1 << position[target]
    for pivot in range(len(ordered)):
        bit, suffix = 1 << pivot, rows[pivot]
        for i in range(len(ordered)):
            if rows[i] & bit:
                rows[i] |= suffix
    return ordered, position, rows


def reachable_from(starts, result):
    ordered, position, rows = result
    bits = 0
    for start in starts:
        bits |= rows[position[start]]
    return {vertex for i, vertex in enumerate(ordered) if bits & (1 << i)}


def components(result):
    ordered, position, rows = result
    remaining = set(ordered)
    answer = []
    while remaining:
        root = min(remaining, key=int)
        ri = position[root]
        group = {vertex for vertex in remaining
                 if rows[ri] & (1 << position[vertex]) and rows[position[vertex]] & (1 << ri)}
        need(group, 'Reflexive component missing root')
        remaining -= group
        answer.append(sorted(group, key=int))
    return answer


def finite_fairness(vertices, edges, starts, env_justice, sys_justice):
    """Exact properties of this finite fixed-memory controller graph only."""
    vertices, edges = set(vertices), {tuple(edge) for edge in edges}
    need(set(starts) <= vertices and all(a in vertices and b in vertices for a, b in edges),
         'Fairness graph IDs')
    full = closure(vertices, edges)
    reachable = reachable_from(starts, full)
    need(reachable == vertices, 'Fairness input must be the reachable view')

    def accepting(group):
        members = set(group)
        cyclic = len(group) > 1 or (group[0], group[0]) in edges
        return cyclic and all(members & set(justice) for justice in env_justice)

    groups = components(full)
    fair_groups = [group for group in groups if accepting(group)]
    fair_vertices = {vertex for group in fair_groups for vertex in group}
    ordered, position, rows = full
    fair_bits = sum(1 << position[v] for v in fair_vertices)
    bad = [v for v in ordered if not rows[position[v]] & fair_bits]
    counterexamples = []
    for ji, justice in enumerate(sys_justice):
        reduced = closure(vertices - set(justice), edges)
        for group in components(reduced):
            if accepting(group):
                counterexamples.append({'SYS_justice_index': ji, 'SCC': group})
    return {'method': 'Direct finite-set truth labels and bitset Warshall transitive closure',
            'reachable_states': ordered, 'SCCs': groups, 'ENV_accepting_SCCs': fair_groups,
            'strict_liveness': {'pass': not counterexamples, 'counterexamples': counterexamples},
            'nonconflicting': {'pass': not bad, 'failing_states': bad,
                               'can_reach_ENV_accepting_SCC': [v for v in ordered if v not in set(bad)]}}


