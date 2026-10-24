#!/usr/bin/env python3
"""Guard-only saved-arena audit. Standard library; no native/BDD solver imports.

The native BDD text is read only as a decision DAG and evaluated on every typed
assignment. A separate finite-set greatest fixed point solves strict safety.
The native 4FP result is compared as saved data, never declared a strict oracle.
Execution requires a root-owner freeze pinning this script and its input manifest.
"""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import re
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def pinned(root, ref):
    path = (root / ref.get("path", ref.get("file", ""))).resolve()
    require(path.is_relative_to(root.resolve()), "Input path escapes root")
    require(path.stat().st_size == ref["bytes"] and digest(path) == ref["sha256"],
            "Input pin mismatch: " + str(path))
    return path


class DecisionDAG:
    """Reader/evaluator only: no Boolean operations or fixpoint machinery."""
    def __init__(self, path, n, allowed, ref):
        rows = [line.split() for line in path.read_text("ascii").splitlines() if line.strip()]
        self.nodes = {}
        if len(rows) == 1 and rows[0] in (["0", "0"], ["0", "1"]):
            self.root = int(rows[0][1])
        else:
            require(len(rows) >= 3 and rows[0] == [str(n)], "BDD header")
            order = [int(x) for x in rows[1]]
            require(sorted(order) == list(range(n)), "BDD variable order")
            level = {v: i for i, v in enumerate(order)}
            triples = set()
            for row in rows[2:]:
                require(len(row) == 4, "BDD row width")
                node, var, lo, hi = map(int, row)
                require(node > 1 and node not in self.nodes and var in allowed, "BDD node/support")
                require(lo != hi and (var, lo, hi) not in triples, "BDD reduced uniqueness")
                for child in (lo, hi):
                    require(child in (0, 1) or child in self.nodes, "BDD topological order")
                    require(child < 2 or level[self.nodes[child][0]] > level[var], "BDD child order")
                self.nodes[node] = (var, lo, hi)
                triples.add((var, lo, hi))
            self.root = node
        seen, todo = set(), [self.root]
        while todo:
            node = todo.pop()
            if node > 1 and node not in seen:
                seen.add(node)
                todo.extend(self.nodes[node][1:])
        require(seen == set(self.nodes), "BDD unreachable payload")
        require(len(seen) == ref["node_count"], "BDD node count metadata")
        require(sorted({v for v, _, _ in self.nodes.values()}) == ref["support"], "BDD support metadata")
        require((self.root == 0) == ref["zero"] and (self.root == 1) == ref["one"], "BDD terminal metadata")

    def value(self, bits):
        node = self.root
        while node > 1:
            var, lo, hi = self.nodes[node]
            node = hi if bits[var] else lo
        return bool(node)


class Arena:
    def __init__(self, directory, expected_fields, source_pin):
        self.directory, self.m = directory, read_json(directory / "model.json")
        m = self.m
        require(m["schema"] == "k7-native-model-export-v1", "Model schema")
        require(all(m["input"][k] == source_pin[k] for k in ("bytes", "sha256")), "Model/source binding")
        fields = m["fields"]
        require([(f["name"], f["owner"]) for f in fields] == expected_fields, "Exact field/owner roster")
        self.names = [f["name"] for f in fields]
        self.env = [i for i, f in enumerate(fields) if f["owner"] == "ENV"]
        current, future = [], []
        for f in fields:
            require(f["role"] == f["owner"] and f["domain_size"] == 2 and f["values"] == ["false", "true"], "Boolean field")
            require(len(f["current_bits"]) == len(f["next_bits"]) == 1, "One bit per Boolean")
            current += f["current_bits"]
            future += f["next_bits"]
            for val in (False, True):
                enc = f["encoding"][str(val).lower()]
                require(enc == {"current": {str(current[-1]): val}, "next": {str(future[-1]): val}}, "Boolean encoding")
        require(current == m["all_current_bits"] and future == m["all_next_bits"], "Complete bit roster")
        n = m["bdd_variable_count"]
        require(sorted(current + future) == list(range(n)) and n == 2 * len(fields) <= 6, "Complete small typed domain")
        require(m["bdd_variable_order"] == list(range(n)), "Expected declared native order")
        self.current, self.future = current, future
        self.states = list(itertools.product((False, True), repeat=len(fields)))
        env_current = [current[i] for i in self.env]
        env_future = [future[i] for i in self.env]
        sys_future = [x for x in future if x not in env_future]
        allowed = {"thetaE": env_current, "thetaS": current, "rhoE": current + env_future,
                   "rhoS": current + future, "domain": current,
                   "domain_ENV_next": env_future, "domain_SYS_next": sys_future}
        self.formulas = {key: self.load(ref, allowed[key]) for key, ref in m["original_bdds"].items()}
        require(set(self.formulas) == set(allowed), "Complete formula roster")
        self.justices = {owner: [self.load(ref, current) for ref in m["original_justices"][owner]] for owner in ("ENV", "SYS")}
        self.initial = {k: {s: self.formulas[k].value(self.bits(s)) for s in self.states} for k in ("thetaE", "thetaS")}
        self.edges = {k: {(s, t): self.formulas[k].value(self.bits(s, t)) for s in self.states for t in self.states} for k in ("rhoE", "rhoS")}
        require(all(self.formulas["domain"].value(self.bits(s)) for s in self.states), "Full typed current coverage")
        for s in self.states:
            require(all(self.formulas[k].value(self.bits(s, s)) for k in ("domain_ENV_next", "domain_SYS_next")), "Full typed next coverage")
        self.groups = {}
        for t in self.states:
            self.groups.setdefault(tuple(t[i] for i in self.env), []).append(t)

    def load(self, ref, allowed):
        return DecisionDAG(pinned(self.directory, ref), self.m["bdd_variable_count"], set(allowed), ref)

    def bits(self, state, target=None):
        return dict(zip(self.current, state)) | (dict(zip(self.future, target)) if target is not None else {})

    def valuation(self, state):
        return dict(zip(self.names, state))

    def initial_verdict(self, winning):
        rows = []
        for env, states in self.groups.items():
            legal = self.initial["thetaE"][states[0]]
            witnesses = [self.valuation(s) for s in states if self.initial["thetaS"][s] and s in winning]
            rows.append({"ENV": dict(zip([self.names[i] for i in self.env], env)), "thetaE": legal, "SYS_winning_responses": witnesses})
        return {"quantifiers": "forall ENV: thetaE implies exists SYS: thetaS and W", "verdict": all(not r["thetaE"] or r["SYS_winning_responses"] for r in rows), "rows": rows}

    def strict_safety(self):
        # CPre(Z): every rhoE-legal next ENV valuation admits a rhoS-safe SYS
        # response in Z. A legal ENV move without a SYS response loses now,
        # even if every infinite extension violates an ENV justice later.
        winning, rounds = set(self.states), [len(self.states)]
        while True:
            new = {s for s in self.states if all(
                not self.edges["rhoE"][s, group[0]] or any(
                    self.edges["rhoS"][s, t] and t in winning for t in group)
                for group in self.groups.values())}
            require(new <= winning, "Descending greatest fixpoint")
            rounds.append(len(new))
            if new == winning:
                return winning, rounds
            winning = new


def audit(root, manifest):
    for pin in manifest["inputs"]:
        pinned(root, pin)
    source = manifest["source"]
    text = pinned(root, source).read_text("utf-8")
    require(re.fullmatch(r"\s*module\s+TransitionGuard\s+env\s+boolean\s+x;\s*sys\s+boolean\s+p;\s*asm\s+keep_x:\s*G\s+next\(x\);\s*gar\s+same_transition:\s*G\s+next\(x\);\s*", text), "Exact source grammar")
    original = Arena(root / manifest["original_directory"], [("x", "ENV"), ("p", "SYS")], source)
    helper = Arena(root / manifest["helper_directory"], [("x", "ENV"), ("~envHelp", "ENV"), ("p", "SYS")], source)
    ro = read_json(original.directory / "result.json")
    rh = read_json(helper.directory / "result.json")
    for arena, receipt in ((original, ro), (helper, rh)):
        require(pinned(arena.directory, receipt["model_export"]) == arena.directory / "model.json", "Receipt/model binding")
        require(receipt["input_sha256"] == source["sha256"] and receipt["teardown"] == "COMPLETED", "Receipt/source/completion")
        require(receipt["initializers_replaced"] is False and receipt["semantic_reduction_used"] is False and receipt["ENV_justice_normalization_used"] is False, "No alternative setup")
    require(ro["mode"] == "original" and ro["helper_added"] is False and ro["native_solver_calls"] == 0, "Original transform-only identity")
    require(rh["helper_added"] is True and rh["helper_is_native_nonaux_ENV"] is True and rh["native_solver_calls"] == 1, "Actual helper identity")
    require(not original.justices["ENV"] and not original.justices["SYS"] and not helper.justices["SYS"] and len(helper.justices["ENV"]) == 1, "Guard justice roster")
    require(all(original.initial[k][s] for k in ("thetaE", "thetaS") for s in original.states), "Source initializer equivalence")
    require(all(original.edges[k][s, t] == t[0] for k in ("rhoE", "rhoS") for s in original.states for t in original.states), "Original full-domain source equivalence")
    for s in helper.states:
        require(helper.initial["thetaE"][s] == (not s[1]) and helper.initial["thetaS"][s], "Helper initializer equations")
        require(helper.justices["ENV"][0].value(helper.bits(s)) == (not s[1]), "GF not-b helper justice")
    for key in ("preconstructor_justices", "solver_justices"):
        for owner in ("ENV", "SYS"):
            refs = rh[key][owner]
            expected = helper.justices[owner] or ([None] if key == "solver_justices" else [])
            require(len(refs) == len(expected), "Justice padding count")
            for ref, formula in zip(refs, expected):
                actual = helper.load(ref, helper.current)
                require(all(actual.value(helper.bits(s)) == (True if formula is None else formula.value(helper.bits(s))) for s in helper.states), "Justice identity/padding")
    quadrants = {str(int(b)) + str(int(bp)): [] for b, bp in itertools.product((False, True), repeat=2)}
    bad = []
    for s, t in itertools.product(helper.states, repeat=2):
        oe, os = (original.edges[k][(s[0], s[2]), (t[0], t[2])] for k in ("rhoE", "rhoS"))
        expected_e, expected_s = (oe or t[1]) and (not s[1] or t[1]), os or s[1]
        actual_e, actual_s = (helper.edges[k][s, t] for k in ("rhoE", "rhoS"))
        require(actual_e == expected_e and actual_s == expected_s, "Full helper equation mismatch")
        quadrants[str(int(s[1])) + str(int(t[1]))].append({"current": helper.valuation(s), "next": helper.valuation(t), "rhoE": actual_e, "rhoS": actual_s})
    for s in helper.states:
        for env, group in helper.groups.items():
            if helper.edges["rhoE"][s, group[0]] and not any(helper.edges["rhoS"][s, t] for t in group):
                bad.append({"current": helper.valuation(s), "next_ENV": dict(zip([helper.names[i] for i in helper.env], env)), "all_SYS_responses_checked": len(group), "all_violate_rhoS": True})
    ow, otr = original.strict_safety()
    hw, htr = helper.strict_safety()
    raw = helper.load(rh["final_region"], helper.current)
    rw = {s for s in helper.states if raw.value(helper.bits(s))}
    projection = lambda w, b: [original.valuation((s[0], s[2])) for s in sorted(w) if s[1] == b]
    verdicts = {"original_strict": original.initial_verdict(ow), "helper_strict": helper.initial_verdict(hw), "native_saved_region": helper.initial_verdict(rw)}
    hypotheses = {
        "original_all_strict_winning": ow == set(original.states),
        "helper_b0_empty": not any(not s[1] for s in hw),
        "helper_b1_all_original_states": len(projection(hw, True)) == len(original.states),
        "immediate_loss_exactly_b0_to_b1_with_xprime_false":
            len(bad) == len(original.states) and all(
                not row["current"]["~envHelp"] and
                row["next_ENV"] == {"x": False, "~envHelp": True} for row in bad),
        "native_region_equals_independent_strict_safety_on_this_arena": rw == hw,
        "native_verdict_agrees_with_saved_region_quantification":
            rh["native_initial_verdict"] == verdicts["native_saved_region"]["verdict"],
        "native_declined_before_extraction":
            rh["status"] == "JOB_UNREALIZABLE_NO_CONTROLLER" and
            rh["native_initial_verdict"] is False and rh["memory_empty_guard_called"] is False and
            rh["controller_extraction_calls"] == rh["native_printer_calls"] == 0}
    return {
        "status": "COMPLETE_EXPECTED_CAUSE" if all(hypotheses.values()) else "COMPLETE_COUNTEREVIDENCE",
        "input_binding": "PASS", "full_source_and_helper_equivalence": "PASS",
        "coverage": {"original_current": len(original.states),
                     "original_current_x_next": len(original.states)**2,
                     "helper_current": len(helper.states),
                     "helper_current_x_next": len(helper.states)**2,
                     "quadrant_counts": {k: len(v) for k, v in quadrants.items()}},
        "quadrants": quadrants,
        "strict_safety": {
            "objective": "SYS safety on every ENV-safety-legal finite prefix; SYS justice list empty, so liveness consequent TRUE",
            "original_W": [original.valuation(s) for s in sorted(ow)],
            "helper_W_b0": projection(hw, False), "helper_W_b1": projection(hw, True),
            "descending_size_traces": {"original": otr, "helper": htr}},
        "fairness_distinction": {
            "ENV_justice": "GF not b",
            "helper_monotonicity": "rhoE entails b implies b-prime, checked by full equation",
            "interpretation": "Every fair infinite helper play from b=0 keeps b=0, but strict safety still checks legal b=0 to b=1 prefixes. Later ENV unfairness does not excuse an immediate SYS safety violation.",
            "fair_path_only_semantics_solved": False},
        "immediate_no_SYS_response_witnesses": bad, "initialization": verdicts,
        "native_comparison": {
            "raw_saved_W": [helper.valuation(s) for s in sorted(rw)],
            "status": rh["status"], "native_initial_verdict": rh["native_initial_verdict"],
            "raw_objective": "Saved released GR1SeparatedGame 4FP sysWinningStates; only extensional agreement on this instance is tested",
            "general_native_strict_equivalence_claimed": False},
        "hypotheses": hypotheses}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "manifest", "freeze", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    require(output.is_relative_to(Path(__file__).resolve().parent) and not output.exists(), "New output inside guard_audit required")
    report = {"schema": "v58-guard-saved-arena-audit-v1", "checker_sha256": digest(Path(__file__)), "manifest_sha256": digest(args.manifest), "scientific_native_calls": 0}
    try:
        freeze = read_json(args.freeze)
        require(freeze["schema"] == "v58-guard-execution-freeze-v1" and freeze["execution_owner"] == "root_main_scientific_owner", "Root-owner freeze required")
        require(freeze["checker_sha256"] == report["checker_sha256"] and freeze["manifest_sha256"] == report["manifest_sha256"], "Freeze pins")
        report.update(audit(args.root.resolve(), read_json(args.manifest)))
    except (ValueError, KeyError, TypeError, OSError, AssertionError) as error:
        report.update(status="UNKNOWN_INPUT_OR_CHECK_ERROR", error=type(error).__name__ + ": " + str(error))
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "output": str(output)}))
    return 0 if report["status"].startswith("COMPLETE_") else 2


if __name__ == "__main__":
    sys.exit(main())
