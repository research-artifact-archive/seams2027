"""Small independent canonical ROBDD engine; no native solver/library imports.

The native text reader validates byte pins separately in admission_checker.py.
Resource limits are explicit technical refusals, never semantic negatives.
"""
from functools import lru_cache


class Invalid(ValueError):
    pass


class ResourceRefusal(RuntimeError):
    pass


def require(test, message):
    if not test:
        raise Invalid(message)


class BDD:
    def __init__(self, variable_count, node_limit=500000):
        require(type(variable_count) is int and 0 <= variable_count <= 64,
                "BDD variable count outside supported range")
        self.n = variable_count
        self.limit = node_limit
        self.nodes = [None, None]
        self.unique = {}
        # Per-manager caches avoid retaining every prior arm through shared
        # method-cache keys during a population-level consumer invocation.
        self.neg = lru_cache(maxsize=1000000)(self.neg)
        self.apply = lru_cache(maxsize=1000000)(self.apply)

    def mk(self, var, lo, hi):
        if lo == hi:
            return lo
        require(type(var) is int and 0 <= var < self.n, "Unknown BDD variable")
        require(all(c in (0, 1) or self.nodes[c][0] > var for c in (lo, hi)),
                "Internal canonical BDD order")
        key = (var, lo, hi)
        if key not in self.unique:
            if len(self.nodes) >= self.limit:
                raise ResourceRefusal("Independent BDD node budget exceeded")
            self.unique[key] = len(self.nodes)
            self.nodes.append(key)
        return self.unique[key]

    def var(self, v):
        return self.mk(v, 0, 1)

    def neg(self, a):
        if a < 2:
            return 1-a
        v, lo, hi = self.nodes[a]
        return self.mk(v, self.neg(lo), self.neg(hi))

    def apply(self, op, a, b):
        require(op in ("and", "or", "xor"), "Unknown BDD operation")
        if a > b:
            return self.apply(op, b, a)
        if op == "and":
            if a == 0 or a == b: return a
            if a == 1: return b
        if op == "or":
            if a == 0: return b
            if a == 1 or a == b: return a
        if op == "xor":
            if a == 0: return b
            if a == b: return 0
            if a == 1: return self.neg(b)
        av, al, ah = self.nodes[a]
        bv, bl, bh = self.nodes[b]
        v = min(av, bv)
        if av != v: al = ah = a
        if bv != v: bl = bh = b
        return self.mk(v, self.apply(op, al, bl), self.apply(op, ah, bh))

    def conj(self, *args):
        out = 1
        for a in args: out = self.apply("and", out, a)
        return out

    def disj(self, *args):
        out = 0
        for a in args: out = self.apply("or", out, a)
        return out

    def implies(self, a, b):
        return self.disj(self.neg(a), b)

    def iff(self, a, b):
        return self.neg(self.apply("xor", a, b))

    def ite(self, cond, yes, no):
        return self.disj(self.conj(cond, yes), self.conj(self.neg(cond), no))

    def cube(self, bits):
        out = 1
        for v in sorted(bits, reverse=True):
            require(type(v) is int and type(bits[v]) is bool, "Cube bit type")
            out = self.mk(v, 0 if bits[v] else out, out if bits[v] else 0)
        return out

    def exists(self, a, variables):
        vs = frozenset(variables)
        @lru_cache(None)
        def visit(u):
            if u < 2: return u
            v, lo, hi = self.nodes[u]
            lo, hi = visit(lo), visit(hi)
            return self.disj(lo, hi) if v in vs else self.mk(v, lo, hi)
        return visit(a)

    def forall(self, a, variables):
        return self.neg(self.exists(self.neg(a), variables))

    def rename(self, a, mapping):
        @lru_cache(None)
        def visit(u):
            if u < 2: return u
            v, lo, hi = self.nodes[u]
            return self.ite(self.var(mapping.get(v, v)), visit(hi), visit(lo))
        return visit(a)

    def support(self, a):
        seen, variables, stack = set(), set(), [a]
        while stack:
            u = stack.pop()
            if u < 2 or u in seen: continue
            seen.add(u)
            v, lo, hi = self.nodes[u]
            variables.add(v)
            stack.extend((lo, hi))
        return variables

    def evaluate(self, a, bits):
        while a > 1:
            v, lo, hi = self.nodes[a]
            require(v in bits and type(bits[v]) is bool, "Incomplete BDD evaluation")
            a = hi if bits[v] else lo
        return bool(a)

    def satone(self, a, variables):
        require(a != 0, "No satisfying assignment")
        bits = {v: False for v in variables}
        while a > 1:
            v, lo, hi = self.nodes[a]
            bits[v] = lo == 0
            a = hi if lo == 0 else lo
        return bits

    def read_native(self, raw):
        """Parse JTLV saved BDD; independently canonicalize its declared order."""
        if len(raw) > 8*1024*1024:
            raise ResourceRefusal("Saved BDD byte budget exceeded")
        rows = [line.split() for line in raw.decode("ascii").splitlines() if line.strip()]
        if len(rows) == 1 and rows[0] in (["0", "0"], ["0", "1"]):
            return int(rows[0][1]), {"node_count": 0, "order": None}
        require(len(rows) >= 3 and rows[0] == [str(self.n)], "Saved BDD variable count")
        order = [int(x) for x in rows[1]]
        require(len(order) == self.n and set(order) == set(range(self.n)), "Saved BDD order")
        level = {v: i for i, v in enumerate(order)}
        imported, native_nodes, triples = {0: 0, 1: 1}, {}, set()
        for row in rows[2:]:
            require(len(row) == 4, "Saved BDD row width")
            nid, v, lo, hi = map(int, row)
            require(nid > 1 and nid not in imported and v in level, "Saved BDD node identity")
            require(lo in imported and hi in imported and lo != hi, "Saved BDD child/reduction")
            require((v, lo, hi) not in triples, "Duplicate saved BDD canonical node")
            triples.add((v, lo, hi))
            for child in (lo, hi):
                require(child < 2 or level[native_nodes[child][0]] > level[v], "Saved BDD variable order")
            native_nodes[nid] = (v, lo, hi)
            imported[nid] = self.ite(self.var(v), imported[hi], imported[lo])
        seen, stack = set(), [nid]
        while stack:
            u = stack.pop()
            if u < 2 or u in seen: continue
            seen.add(u)
            stack.extend(native_nodes[u][1:])
        require(seen == set(native_nodes), "Unreachable saved BDD nodes")
        return imported[nid], {"node_count": len(seen), "order": order}
