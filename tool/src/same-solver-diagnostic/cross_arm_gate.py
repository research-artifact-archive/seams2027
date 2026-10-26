#!/usr/bin/env python3
"""Independent, bounded saved-data gate. Import checks its runtime envelope only.

Only JSON and exported Boolean node tables are read. No native library, model
builder, translator, predecessor, solver or fixed-point routine is imported.
Preparation may AST-parse this file; execution requires exact root gate GO.
"""
from __future__ import annotations

# Set the cache prefix at interpreter startup; -B alone does not disable reads.
# os source and the sys builtin are pinned runtime inputs. Check before other imports.
import os
import sys
_EXPECTED_CACHE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "empty_python_cache")
if not (sys.flags.no_site and sys.dont_write_bytecode
        and sys.pycache_prefix == _EXPECTED_CACHE
        and sys._xoptions.get("pycache_prefix") == _EXPECTED_CACHE
        and os.path.isdir(_EXPECTED_CACHE) and not os.path.islink(_EXPECTED_CACHE)
        and os.path.realpath(_EXPECTED_CACHE) == _EXPECTED_CACHE
        and not os.listdir(_EXPECTED_CACHE)):
    raise RuntimeError("Exact startup -B -S -X pycache_prefix with frozen-empty cache directory required")

import argparse
import base64
import datetime as dt
import hashlib
import json
from pathlib import Path
import stat
import path_identity as identity
import prior_gate_evidence as evidence

P = Path(__file__).resolve().parent
STAGE = "cross_arm_gate_revalidation"
ARMS = ("unchanged", "S01_release")
CAP = 64 * 1024 * 1024
NODE_CAP = 500000
APPLY_CAP = 1000000
PREDICATES = ("thetaE", "thetaS", "rhoE", "rhoS", "domain", "domain_ENV_next", "domain_SYS_next")
POINT = {"obstacle[0]": "3", "obstacle[1]": "5", "obsWait": "true", "~envHelp": "false", "robot[0]": "5", "robot[1]": "5"}


def strict_equal(a, b):
    return json.dumps(a, sort_keys=True, ensure_ascii=False, allow_nan=False) == json.dumps(b, sort_keys=True, ensure_ascii=False, allow_nan=False)


def json_value(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key: " + key)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Nonfinite JSON number")))


class Gate:
    def __init__(self):
        self.checks = {}
        self.pins = {}
        self.path_observations = {}
        self.nodes = {0: None, 1: None}
        self.unique = {}
        self.apply_cache = {}
        self.not_cache = {0: 1, 1: 0}
        self.frozen = {}
        self.variable_count = 28
        self.bundle = None
        self.source_root = None
        self.source_plan = None
        self.stderr_classifications = {}

    def need(self, ok, label):
        self.checks[label] = bool(ok)
        if not ok:
            raise RuntimeError(label)

    def invariant(self, ok, label):
        if not ok:
            raise RuntimeError(label)

    def regular(self, path):
        return identity.canonical_file(path)

    def pin(self, path, limit=CAP):
        path = self.regular(path)
        size = path.stat().st_size
        key = identity.file_key(path)
        self.invariant(size <= limit, "Input read bound exceeded: " + str(path))
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while data := stream.read(1024 * 1024):
                digest.update(data)
        value = {"path": str(path), "bytes": size, "sha256": digest.hexdigest()}
        self.invariant(path.stat().st_size == size and identity.file_key(path) == key, "File changed during pin")
        previous = self.pins.setdefault(key, value)
        self.invariant(identity.same_file_pin(previous, value), "Previously read physical input changed: " + str(path))
        self.path_observations.setdefault(key, set()).add(str(path))
        return value

    def checked_pin(self, value, limit=CAP):
        self.invariant(isinstance(value, dict) and set(value) == {"path", "bytes", "sha256"}, "Exact pin fields required")
        self.invariant(type(value["bytes"]) is int and value["bytes"] >= 0, "Integer pin size required")
        self.invariant(isinstance(value["sha256"], str) and len(value["sha256"]) == 64 and all(c in "0123456789abcdef" for c in value["sha256"]), "Lowercase SHA256 required")
        self.invariant(identity.same_file_pin(self.pin(value["path"], limit), value), "Pin mismatch: " + str(value["path"]))
        return Path(value["path"])

    def read(self, path, limit=16 * 1024 * 1024):
        value = self.pin(path, limit)
        raw = Path(path).read_bytes()
        self.invariant(len(raw) == value["bytes"] and hashlib.sha256(raw).hexdigest() == value["sha256"], "Read changed after pin")
        return json_value(raw)

    def roster(self, folder):
        folder = identity.canonical_directory(folder)
        files = []
        for base, dirs, names in os.walk(folder, followlinks=False):
            for name in dirs:
                item = Path(base) / name
                self.invariant(not item.is_symlink() and stat.S_ISDIR(item.stat().st_mode), "Unsafe directory member")
            for name in names:
                item = Path(base) / name
                self.regular(item)
                self.invariant(not name.endswith(".tmp"), "Incomplete temporary output")
                files.append(item)
        self.invariant(len({identity.file_key(path) for path in files}) == len(files), "Duplicate physical file in directory roster")
        self.invariant(len(files) <= 4096, "Artifact file count bound exceeded")
        self.invariant(sum(path.stat().st_size for path in files) <= 256 * 1024 * 1024, "Artifact size bound exceeded")
        return sorted(files)

    def authorization(self, path, expected):
        actual = self.pin(path)
        self.need(actual["sha256"] == expected and len(expected) == 64, "exact_authorization_sha256")
        auth = self.read(path)
        self.need(auth.get("schema") == "v71-r7-v5-root-authorization-v1" and auth.get("status") == "GO_SAVED_CROSS_ONLY", "saved_cross_only_GO")
        stages = auth.get("authorized_stages")
        self.need(stages == [STAGE], "authorized_stage_roster")
        self.need(identity.same_file(self.checked_pin(auth["plan"]), P / "PLAN.json") and identity.same_file(self.checked_pin(auth["input_freeze"]), P / "INPUT_FREEZE.json"), "fixed_plan_and_freeze_paths")
        plan = self.read(P / "PLAN.json")
        self.need(plan.get("schema") == "v71-r7-v5-three-stage-plan-v1" and set(plan["stages"]) == {STAGE, "solve_unchanged", "solve_S01_release"}, "fixed_three_stage_plan")
        freeze = self.read(P / "INPUT_FREEZE.json")
        self.need(freeze.get("schema") == "v71-r7-v5-input-freeze-v1", "input_freeze_schema")
        for pin in freeze["files"]:
            item = self.checked_pin(pin, 1024 ** 3)
            key = identity.file_key(item)
            self.invariant(key not in self.frozen, "Duplicate physical frozen input")
            self.frozen[key] = pin
        for directory in freeze["directories"]:
            folder = Path(directory["path"])
            expected_files = set()
            for member in directory["files"]:
                rel = member["relative_path"]
                self.invariant(isinstance(rel, str) and rel and not rel.startswith("/") and all(x not in ("", ".", "..") for x in rel.split("/")), "Safe frozen relative path required")
                item = folder / rel
                pin = {"path": str(item), "bytes": member["bytes"], "sha256": member["sha256"]}
                self.checked_pin(pin, 1024 ** 3)
                key = identity.file_key(item)
                self.invariant(key not in self.frozen and key not in expected_files, "Duplicate physical frozen input")
                self.frozen[key] = pin
                expected_files.add(key)
            self.need({identity.file_key(path) for path in self.roster(folder)} == expected_files, "frozen_directory_roster_" + str(folder))
        aliases = freeze.get("runtime_aliases")
        self.need(isinstance(aliases, list) and len(aliases) == 3, "three_known_runtime_loader_aliases")
        seen_aliases = set()
        for row in aliases:
            self.invariant(isinstance(row, dict) and set(row) == {"path", "resolved_path"}, "Exact runtime alias binding required")
            alias, target = Path(row["path"]), Path(row["resolved_path"])
            self.invariant(alias.is_absolute() and target.is_absolute() and str(alias) not in seen_aliases, "Distinct absolute runtime aliases required")
            self.need(identity.same_file(alias.resolve(strict=True), target) and identity.file_key(target) in self.frozen, "runtime_alias_target_" + str(alias))
            seen_aliases.add(str(alias))
        self.need(all(identity.file_key(path) in self.frozen for path in (Path(__file__).resolve(), Path(sys.executable).resolve(), P / "B_CONFIG.json", P / "path_identity.py", P / "prior_gate_evidence.py")), "checker_runtime_config_frozen")
        evidence.match(auth["prior_gate_bundle"], plan["prior_gate_bundle"], self.checked_pin, self.need, "new_GO_reviewed_prior_bundle")
        self.bundle = evidence.prior_bundle(auth["prior_gate_bundle"], P, self.pin(P / "B_CONFIG.json"), self.frozen, self.read, self.checked_pin, self.need, self.roster)
        self.source_root = identity.canonical_directory(self.bundle["source_root"])
        self.source_plan = self.read(self.checked_pin(self.bundle["source_plan"]))
        self.need(strict_equal(plan["stages"][STAGE]["limits"], self.source_plan["stages"]["cross_arm_gate"]["limits"]), "saved_cross_original_limits_unchanged")
        return auth, plan

    def manifest(self, pin, stage):
        folder = self.source_root / "runs" / stage
        self.need(identity.same_file(self.checked_pin(pin), folder / "OUTPUT_MANIFEST.json"), stage + "_manifest_path")
        manifest = self.read(folder / "OUTPUT_MANIFEST.json")
        self.need(manifest.get("schema") == "v71-r7-stage-output-manifest-v1" and manifest.get("stage") == stage, stage + "_manifest_schema")
        expected = set()
        for row in manifest["files"]:
            path = self.checked_pin(row)
            key = identity.file_key(path)
            self.invariant(identity.file_within(path, folder) and path.name not in ("SUPERVISOR_RESULT.json", "OUTPUT_MANIFEST.json") and key not in expected, "Invalid or physically duplicated manifest member")
            expected.add(key)
        excluded = {identity.file_key(folder / name) for name in ("SUPERVISOR_RESULT.json", "OUTPUT_MANIFEST.json")}
        actual = {identity.file_key(path) for path in self.roster(folder)} - excluded
        self.need(expected == actual and bool(expected), stage + "_exact_output_manifest_roster")

    def capture(self, stage, result):
        folder = self.source_root / "runs" / stage
        receipt_path = folder / "native_result/CAPTURE_RECEIPT.json"
        self.need(identity.same_file(self.checked_pin(result["capture_receipt"]), receipt_path), stage + "_capture_path")
        receipt = self.read(receipt_path)
        self.need(receipt.get("schema") == "bounded-exact-println-dictionary-rle-v1", stage + "_bounded_capture_schema")
        self.need(receipt.get("capture_complete") is True and receipt.get("cap_reached") is False and receipt.get("capture_error") is None and receipt.get("unflushed_repeated_lines") == 0, stage + "_capture_complete")
        encoded = self.pin(folder / "stdout.txt")
        self.need(receipt["encoded_bytes"] == encoded["bytes"] <= CAP and receipt["encoded_sha256"] == encoded["sha256"], stage + "_encoded_capture_pin")
        self.need(receipt["raw_cap_bytes"] == CAP and receipt["encoded_cap_bytes"] == CAP, stage + "_capture_caps")
        self.stderr_classifications[stage] = evidence.stderr_classification(stage, self.bundle["gates"][stage]["stderr"], self.bundle["gc_diagnostic"], self.checked_pin, self.need)
        self.need(identity.same_file_pin(self.pin(folder / "stderr.txt"), self.bundle["gates"][stage]["stderr"]), stage + "_original_stderr_file_pin")
        dictionary = None
        raw_digest = hashlib.sha256()
        expanded = repeated = records = 0
        end = None
        with (folder / "stdout.txt").open("rb") as stream:
            for line in stream:
                self.invariant(len(line) <= 131072 and line.endswith(b"\n"), "Bounded complete RLE record required")
                row = json_value(line)
                self.invariant(end is None, "Record after RLE end")
                kind = row.get("kind")
                if kind == "dictionary":
                    self.invariant(records == 0 and dictionary is None and row["id"] == "cache_lookup", "Unique initial dictionary required")
                    dictionary = base64.b64decode(row["data"], validate=True)
                    self.invariant(dictionary == b"lookup, class net.sf.javabdd.JTLVJavaFactory$BddCache\n", "Exact diagnostic dictionary required")
                elif kind == "bytes":
                    self.invariant(dictionary is not None, "Missing capture dictionary")
                    data = base64.b64decode(row["data"], validate=True)
                    self.invariant(0 < len(data) <= 65536 and expanded + len(data) <= CAP, "Raw byte record bound")
                    raw_digest.update(data)
                    expanded += len(data)
                elif kind == "repeat":
                    count = row["count"]
                    self.invariant(dictionary is not None and row["id"] == "cache_lookup" and type(count) is int and count > 0, "Valid repeat run required")
                    self.invariant(expanded + len(dictionary) * count <= CAP, "Expanded stdout bound exceeded")
                    # Bounded chunks avoid constructing an unbounded expansion.
                    remaining = count
                    while remaining:
                        chunk_count = min(remaining, 16384)
                        raw_digest.update(dictionary * chunk_count)
                        remaining -= chunk_count
                    expanded += len(dictionary) * count
                    repeated += count
                else:
                    self.invariant(kind == "end" and dictionary is not None, "One final RLE end required")
                    end = row
                records += 1
        self.need(end is not None and expanded == receipt["raw_bytes"] == end["raw_bytes"] <= CAP and repeated == receipt["repeated_lines"] == end["repeated_lines"] and records == receipt["records"], stage + "_capture_counts")
        self.need(raw_digest.hexdigest() == receipt["raw_sha256"], stage + "_reconstructed_raw_capture_sha256")
        return {"raw_bytes": expanded, "raw_sha256": raw_digest.hexdigest(), "encoded_bytes": encoded["bytes"], "encoded_sha256": encoded["sha256"], "records": records}

    def prerequisite(self, arm, plan, auth):
        plan = self.source_plan
        stage = "gate_" + arm
        folder = self.source_root / "runs" / stage
        state = self.read(folder / "SUPERVISOR_RESULT.json")
        self.need(state.get("schema") == "v71-r7-bounded-stage-result-v1" and state.get("stage") == stage and state.get("status") == "COMPLETE_STAGE", stage + "_supervisor_complete")
        self.need(type(state.get("return_code")) is int and state["return_code"] == 0 and state.get("limit_reason") is None and state.get("capture_complete") is True and state.get("signals") == [], stage + "_real_zero_exit_no_limits_no_signals")
        result_path = self.checked_pin(state["native_result"])
        self.need(identity.same_file(result_path, folder / "native_result/RESULT.json") and identity.same_file(result_path, self.source_root / plan["stages"][stage]["result_file"]), stage + "_native_result_path")
        self.manifest(state["output_manifest"], stage)
        result = self.read(result_path)
        self.need(result.get("schema") == "v71-r7-exact-B-same-solver-result-v1" and result.get("status") == "PASS_ARM_GATE_NO_SOLVE" and result.get("requested_stage") == stage and result.get("arm") == arm and result.get("stage") == "PROCESS_FINISHED" and result.get("teardown") == "COMPLETED", stage + "_native_completed_gate")
        self.need(type(result.get("model_generations")) is int and result["model_generations"] == 1 and type(result.get("syntactic_reduction_calls")) is int and result["syntactic_reduction_calls"] == 1 and all(type(result.get(key)) is int and result[key] == 0 for key in ("semantic_reduction_calls", "solver_constructions", "raw_four_fixed_point_calls", "native_strict_solver_calls", "winning_region_computations", "controller_extraction_calls")), stage + "_one_model_zero_solver")
        self.need(result.get("source_or_monitor_reset") is False and result.get("G_and_A_normalization") is False and result.get("GUI_execution") is False and result.get("baseline_matches_old_adopted_B") is True and result.get("all_preserved_parts_equal") is True, stage + "_scope_flags")
        self.need(identity.same_file(self.checked_pin(result["config"]), self.source_root / "B_CONFIG.json"), stage + "_config_pin")
        stage_auth = self.read(self.checked_pin(result["authorization"]))
        self.need(stage_auth.get("schema") == "v71-r7-two-arm-root-authorization-v1" and stage_auth.get("status") == "GO_GATE_STAGES_ONLY" and stage in stage_auth.get("authorized_stages", []) and identity.same_file_pin(stage_auth.get("plan"), self.bundle["source_plan"]) and identity.same_file_pin(stage_auth.get("input_freeze"), self.bundle["source_input_freeze"]), stage + "_authorization_same_plan_freeze")
        for label in ("dispatch_after_generation", "dispatch_before_intervention", "dispatch_before_completion_or_solve"):
            dispatch = result[label]
            self.need(dispatch["ENV_transFunc"] == dispatch["SYS_transFunc"] == "SINGLE_FUNC" and dispatch["ENV_simConjunctAbs"] is False and dispatch["SYS_simConjunctAbs"] is False, stage + "_" + label)
        models = {}
        for label in ("baseline", "arm"):
            path = self.checked_pin(result[label + "_model"])
            self.need(identity.same_file(path, folder / "native_result" / label / "model.json"), stage + "_" + label + "_path")
            models[label] = (self.read(path), path.parent)
        return result, models, self.capture(stage, result)

    def mk(self, var, lo, hi):
        if lo == hi:
            return lo
        self.invariant(type(var) is int and 0 <= var < self.variable_count, "Node variable outside exact universe")
        for child in (lo, hi):
            self.invariant(child in self.nodes and (child <= 1 or self.nodes[child][0] > var), "Canonical node order violated")
        key = (var, lo, hi)
        if key not in self.unique:
            self.invariant(len(self.nodes) - 2 < NODE_CAP, "Canonical Boolean node cap exceeded")
            node = len(self.nodes)
            self.nodes[node] = key
            self.unique[key] = node
        return self.unique[key]

    def negate(self, node):
        if node not in self.not_cache:
            var, lo, hi = self.nodes[node]
            self.not_cache[node] = self.mk(var, self.negate(lo), self.negate(hi))
        return self.not_cache[node]

    def combine(self, op, left, right):
        self.invariant(op in ("and", "or", "xor"), "Only propositional saved-predicate operations allowed")
        if left > right:
            left, right = right, left
        if left <= 1 and right <= 1:
            return int((bool(left) and bool(right)) if op == "and" else (bool(left) or bool(right)) if op == "or" else bool(left) != bool(right))
        if left == right:
            return 0 if op == "xor" else left
        if left == 0:
            return 0 if op == "and" else right
        if left == 1:
            return right if op == "and" else 1 if op == "or" else self.negate(right)
        key = (op, left, right)
        if key not in self.apply_cache:
            self.invariant(len(self.apply_cache) < APPLY_CAP, "Propositional apply cache cap exceeded")
            lv, ll, lh = self.nodes[left]
            rv, rl, rh = self.nodes[right]
            top = min(lv, rv)
            lo = self.combine(op, ll if lv == top else left, rl if rv == top else right)
            hi = self.combine(op, lh if lv == top else left, rh if rv == top else right)
            self.invariant(len(self.apply_cache) < APPLY_CAP, "Propositional apply cache cap exceeded")
            self.apply_cache[key] = self.mk(top, lo, hi)
        return self.apply_cache[key]

    def restrict(self, root, assignments, memo=None):
        memo = {} if memo is None else memo
        if root <= 1:
            return root
        if root not in memo:
            var, lo, hi = self.nodes[root]
            memo[root] = self.restrict(hi if assignments[var] else lo, assignments, memo) if var in assignments else self.mk(var, self.restrict(lo, assignments, memo), self.restrict(hi, assignments, memo))
        return memo[root]

    def cube(self, assignments):
        root = 1
        for var, value in sorted(assignments.items(), reverse=True):
            self.invariant(type(value) is bool, "Boolean cube value required")
            root = self.mk(var, 0, root) if value else self.mk(var, root, 0)
        return root

    def support(self, root):
        seen, bits, todo = set(), set(), [root]
        while todo:
            node = todo.pop()
            if node > 1 and node not in seen:
                seen.add(node)
                var, lo, hi = self.nodes[node]
                bits.add(var)
                todo.extend((lo, hi))
        return sorted(bits)

    def load_predicate(self, ref, folder):
        name = ref["file"]
        self.invariant(isinstance(name, str) and name and Path(name).name == name, "Predicate basename required")
        path = folder / name
        self.checked_pin({"path": str(path), "bytes": ref["bytes"], "sha256": ref["sha256"]})
        rows = [list(map(int, line.split())) for line in path.read_text(encoding="ascii").splitlines() if line.strip()]
        self.invariant(type(ref["node_count"]) is int and 0 <= ref["node_count"] <= NODE_CAP, "Predicate node count bound")
        if len(rows) == 1:
            self.invariant(rows[0] in ([0, 0], [0, 1]) and ref["node_count"] == 0, "Constant predicate syntax")
            root = rows[0][1]
        else:
            self.invariant(rows[0] == [self.variable_count] and rows[1] == list(range(self.variable_count)) and len(rows) - 2 == ref["node_count"], "Predicate exact variable header/count")
            cache = {0: 0, 1: 1}
            last = None
            for row in rows[2:]:
                self.invariant(len(row) == 4, "Predicate node width")
                node, var, lo, hi = row
                self.invariant(node > 1 and node not in cache and lo in cache and hi in cache, "Predicate node topology")
                cache[node] = self.mk(var, cache[lo], cache[hi])
                last = node
            self.invariant(last is not None, "Predicate root missing")
            root = cache[last]
        self.invariant(ref["zero"] is (root == 0) and ref["one"] is (root == 1) and ref["support"] == self.support(root), "Predicate descriptive metadata does not match content")
        return root

    def metadata(self, model, label):
        self.need(model.get("schema") == "k7-native-model-export-v1" and model["bdd_variable_count"] == 28 and model["bdd_variable_order"] == list(range(28)), label + "_exact_28_bit_order")
        fields = {field["name"]: field for field in model["fields"]}
        self.need(len(fields) == len(model["fields"]) == 6 and set(fields) == set(POINT), label + "_six_fields_no_AUX")
        allbits, current, nxt = [], [], []
        for name, field in fields.items():
            expected_owner = "SYS" if name.startswith("robot[") else "ENV"
            self.invariant(field["owner"] == field["role"] == expected_owner, "Exact field ownership/role")
            values = field["values"]
            self.invariant(len(set(values)) == len(values) == field["domain_size"] and set(values) == set(field["encoding"]), "Exact field value roster")
            codes = []
            for phase in ("current", "next"):
                bits = field[phase + "_bits"]
                self.invariant(all(type(bit) is int and 0 <= bit < 28 for bit in bits), "Integer field bits required")
                allbits.extend(bits)
                (current if phase == "current" else nxt).extend(bits)
                phasecodes = []
                for value in values:
                    encoding = field["encoding"][value][phase]
                    self.invariant(set(encoding) == {str(bit) for bit in bits} and all(type(v) is bool for v in encoding.values()), "Complete Boolean value encoding")
                    phasecodes.append(tuple(encoding[str(bit)] for bit in bits))
                self.invariant(len(set(phasecodes)) == len(values), "Injective field encoding")
                codes.append(phasecodes)
            self.invariant(codes[0] == codes[1], "Current/next codes differ")
        self.need(sorted(allbits) == list(range(28)) and sorted(model["all_current_bits"]) == sorted(current) and sorted(model["all_next_bits"]) == sorted(nxt), label + "_complete_disjoint_bit_partition")
        helper = fields["~envHelp"]
        self.need(helper["values"] == ["false", "true"] and len(helper["current_bits"]) == len(helper["next_bits"]) == 1, label + "_Boolean_ENV_helper")
        for phase in ("current", "next"):
            bit = str(helper[phase + "_bits"][0])
            self.invariant(helper["encoding"]["false"][phase][bit] is False and helper["encoding"]["true"][phase][bit] is True, "Exact helper Boolean encoding")
        self.need(model["public_fields"] == {"ENV": ["obstacle[0]", "obstacle[1]", "obsWait", "~envHelp"], "SYS": ["robot[0]", "robot[1]"]}, label + "_public_roster")
        return fields

    def semantic_inventory(self, model):
        def clean(value):
            if isinstance(value, list):
                return [clean(v) for v in value]
            if isinstance(value, dict):
                return {k: clean(v) for k, v in value.items() if k != "trace_id"}
            return value
        result = {}
        for phase in ("parsed", "translated"):
            inventory = model["source_inventory"][phase]
            self.invariant(set(inventory) == {"ENV", "SYS", "AUX"}, "Exact source owners")
            result[phase] = {}
            for owner, item in inventory.items():
                self.invariant(item["patterns"] == item["triggers"] == [] and item["existential_count"] == 0, "No pattern, trigger or existential additions")
                if owner == "AUX":
                    self.invariant(item["variables"] == item["constraints"] == [], "No AUX variables or constraints")
                result[phase][owner] = {"variables": clean(item["variables"]), "constraints": [{key: clean(c[key]) for key in ("name", "kind", "spec_ast")} for c in item["constraints"]]}
        return result

    def model_functions(self, model, folder, label):
        self.need(set(model["original_bdds"]) == set(PREDICATES), label + "_complete_predicate_roster")
        functions = {name: self.load_predicate(model["original_bdds"][name], folder) for name in PREDICATES}
        self.need(set(model["original_justices"]) == {"ENV", "SYS"}, label + "_justice_owners")
        for owner, count in (("ENV", 1), ("SYS", 2)):
            refs = model["original_justices"][owner]
            self.need(len(refs) == count, label + "_ordered_justice_count_" + owner)
            functions[owner + "_justices"] = [self.load_predicate(ref, folder) for ref in refs]
        return functions

    def run(self, auth_path, auth_hash):
        auth, plan = self.authorization(auth_path, auth_hash)
        config = self.read(P / "B_CONFIG.json")
        self.need(config.get("schema") == "v71-r7-two-arm-B-config-v1" and config.get("id") == "B_NEW_POINT_R2404", "fixed_exact_B_config")
        exact_path = self.checked_pin(config["prior_exact_model"])
        self.checked_pin(config["prior_exact_gate_adoption"])
        input_path = self.checked_pin(config["input"])
        self.need(config["input"]["bytes"] == 2026 and config["input"]["sha256"] == "212309df489c3ddc7bf7ec6a750aed2d0da4fb7e26995e5ee3a0405c9897e1d5", "fixed_exact_B_source_bytes")
        exact = self.read(exact_path)
        fields = self.metadata(exact, "old_exact_B")
        old = self.model_functions(exact, exact_path.parent, "old_exact_B")
        old_inventory = self.semantic_inventory(exact)
        helper = fields["~envHelp"]
        h, hp = helper["current_bits"][0], helper["next_bits"][0]
        self.need(old["ENV_justices"] == [self.cube({h: False})], "sole_ENV_justice_exact_not_helper")
        point_bits, env_bits, sys_bits = {}, {}, {}
        for name, value in POINT.items():
            assignments = {int(k): v for k, v in fields[name]["encoding"][value]["current"].items()}
            point_bits.update(assignments)
            (env_bits if fields[name]["owner"] == "ENV" else sys_bits).update(assignments)
        self.need(set(point_bits) == set(exact["all_current_bits"]) and old["thetaE"] == self.cube(env_bits) != 0 and old["thetaS"] == self.cube(sys_bits) != 0, "exact_full_nonempty_point_initializers")
        # Reconstruct each type domain from the complete value encodings; the
        # typed intervention must not rely only on a declared domain label.
        encoded_domains = {"domain": 1, "domain_ENV_next": 1, "domain_SYS_next": 1}
        carrier = 1
        for field in fields.values():
            carrier *= field["domain_size"]
            for phase in ("current", "next"):
                allowed_values = 0
                for value in field["values"]:
                    assignments = {int(k): v for k, v in field["encoding"][value][phase].items()}
                    allowed_values = self.combine("or", allowed_values, self.cube(assignments))
                name = "domain" if phase == "current" else "domain_" + field["owner"] + "_next"
                encoded_domains[name] = self.combine("and", encoded_domains[name], allowed_values)
        self.need(carrier == 12544 and all(encoded_domains[name] == old[name] for name in encoded_domains), "all_type_domains_equal_declared_value_encodings")
        edge = self.combine("and", self.combine("and", old["domain"], old["domain_ENV_next"]), old["domain_SYS_next"])
        q01 = self.cube({h: False, hp: True})
        expected_release = self.combine("or", old["rhoS"], self.combine("and", edge, q01))
        self.need(expected_release != old["rhoS"], "predicted_intervention_strictly_nonempty")
        self.need(not (set(self.support(old["rhoE"])) & {bit for name, field in fields.items() if field["owner"] == "SYS" for bit in field["next_bits"]}), "ENV_relation_independent_of_next_SYS")
        captures, arm_roots = {}, {}
        for arm in ARMS:
            result, models, captures[arm] = self.prerequisite(arm, plan, auth)
            self.checked_pin(result["input"])
            self.need(identity.same_file_pin(result["input"], config["input"]) and result["point_singleton"] == POINT and result["point_joint_nonempty"] is True, arm + "_exact_source_and_point_receipt")
            functions = {}
            for label, (model, folder) in models.items():
                tag = arm + "_" + label
                self.metadata(model, tag)
                self.need(all(strict_equal(model[key], exact[key]) for key in ("fields", "public_fields", "all_current_bits", "all_next_bits", "bdd_variable_count", "bdd_variable_order")), tag + "_identical_metadata_no_remapping")
                self.need(model["input"]["bytes"] == config["input"]["bytes"] and model["input"]["sha256"] == config["input"]["sha256"], tag + "_input_bytes_identity")
                self.need(strict_equal(self.semantic_inventory(model), old_inventory), tag + "_source_and_translated_inventory_unchanged")
                functions[label] = self.model_functions(model, folder, tag)
                for name in (*PREDICATES, "ENV_justices", "SYS_justices"):
                    expected = expected_release if label == "arm" and arm == "S01_release" and name == "rhoS" else old[name]
                    self.need(functions[label][name] == expected, tag + "_raw_exact_" + name)
            base, changed = functions["baseline"]["rhoS"], functions["arm"]["rhoS"]
            delta = self.combine("xor", base, changed)
            self.need(self.combine("and", base, self.negate(changed)) == 0 and self.combine("and", delta, self.negate(q01)) == 0 and self.combine("and", delta, self.negate(edge)) == 0, arm + "_only_typed_S01_relaxation")
            self.need((delta != 0) is (arm == "S01_release"), arm + "_correct_nonempty_delta")
            for cur in (False, True):
                for nxt in (False, True):
                    quadrant = str(int(cur)) + str(int(nxt))
                    assignment = {h: cur, hp: nxt}
                    before, after = self.restrict(base, assignment), self.restrict(changed, assignment)
                    if quadrant != "01" or arm == "unchanged":
                        self.need(before == after, arm + "_S" + quadrant + "_unchanged")
                    if quadrant == "01" and arm == "S01_release":
                        mask = self.restrict(edge, assignment)
                        self.need(self.combine("and", after, mask) == mask, arm + "_S01_typed_complete")
                    if quadrant == "11":
                        self.need(before == after == 1, arm + "_S11_literal_true_no_safety_or_AUX_duty")
                    self.need(self.load_predicate(result["intervention"]["SYS_quadrants"][quadrant]["after"], models["arm"][1]) == after, arm + "_reported_S" + quadrant + "_matches_saved_full_relation")
            self.need(self.load_predicate(result["intervention"]["delta"], models["arm"][1]) == delta, arm + "_reported_delta_matches_saved_relations")
            self.need(self.load_predicate(result["point_joint"], models["arm"][1]) == self.cube(point_bits), arm + "_reported_joint_point_exact")
            arm_roots[arm] = functions["arm"]
        self.need(all(arm_roots["unchanged"][name] == arm_roots["S01_release"][name] for name in (*PREDICATES, "ENV_justices", "SYS_justices") if name != "rhoS"), "cross_arm_all_other_raw_predicates_identical")
        # Original gates, old GO/launches and the failed cross are frozen
        # inputs. Only this new GO and its own plan/freeze are explicit pins.
        allowed = {identity.file_key(path) for path in (auth_path, P / "PLAN.json", P / "INPUT_FREEZE.json")}
        for key, pin in list(self.pins.items()):
            path = Path(pin["path"])
            if key not in allowed:
                self.need(key in self.frozen and identity.same_file_pin(pin, self.frozen[key]), "used_input_frozen_" + str(path))
        # Re-read every observed spelling while preserving its physical identity,
        # then recheck both complete gate rosters. No strings are normalized.
        for key, pin in list(self.pins.items()):
            for spelling in sorted(self.path_observations[key]):
                self.invariant(identity.file_key(spelling) == key, "Previously observed spelling changed physical identity")
                self.checked_pin({**pin, "path": spelling}, 1024 ** 3)
        for arm in ARMS:
            stage = "gate_" + arm
            state = self.read(self.source_root / "runs" / stage / "SUPERVISOR_RESULT.json")
            self.manifest(state["output_manifest"], stage)
        return {"schema": "v71-r7-saved-cross-arm-revalidation-v2", "status": "PASS_CROSS_ARM_SAVED_PREDICATE_GATE", "stage": STAGE, "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "authorization": self.pin(auth_path), "plan": auth["plan"], "input_freeze": auth["input_freeze"], "checks": self.checks, "checks_count": len(self.checks), "canonical_saved_predicate_nodes": len(self.nodes) - 2, "propositional_apply_cache_entries": len(self.apply_cache), "limits": {"canonical_nodes": NODE_CAP, "apply_cache_entries": APPLY_CAP, "raw_stdout_bytes": CAP, "encoded_stdout_bytes": CAP}, "point": POINT, "captures": captures, "prior_gate_bundle": auth["prior_gate_bundle"], "verified_prior_gate_evidence": self.bundle, "original_failed_cross_preserved": True, "stderr_classifications": self.stderr_classifications, "activity": {"model_generations": 0, "model_builds": 0, "Java_runs": 0, "solver_calls": 0, "fixed_point_calls": 0, "CPre_calls": 0, "signals": 0, "GUI_actions": 0}, "interpretation": "Independent saved-predicate gate only. Both baseline exports equal the previously adopted exact B. The only arm difference is raw rhoS := old rhoS OR (typed full edge domain AND helper 01). This neither predicts nor records a solver verdict or historical GUI identity.", "input_pins": list(self.pins.values()), "observed_path_spellings": [{"device": key[0], "inode": key[1], "paths": sorted(paths)} for key, paths in self.path_observations.items()]}


def main():
    cache_root = P / "empty_python_cache"
    if not (sys.flags.no_site and sys.dont_write_bytecode and sys.pycache_prefix == str(cache_root)
            and cache_root.is_dir() and cache_root == cache_root.resolve() and not cache_root.is_symlink()
            and not any(cache_root.iterdir())):
        raise RuntimeError("Python -B -S and exact dedicated empty -X pycache_prefix are required")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorization", required=True)
    parser.add_argument("--authorization-sha256", required=True)
    args = parser.parse_args()
    output = P / "runs" / STAGE / "RESULT.json"
    if output.exists() or output.is_symlink() or not output.parent.is_dir() or not identity.same_directory(output.parent, output.parent.resolve()):
        raise RuntimeError("Fresh bounded stage output directory required; never overwrite a result")
    gate = Gate()
    code = 0
    try:
        report = gate.run(Path(args.authorization), args.authorization_sha256)
    except Exception as error:
        code = 2
        report = {"schema": "v71-r7-saved-cross-arm-revalidation-v2", "status": "UNKNOWN_CROSS_ARM_GATE", "stage": STAGE, "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "exception": repr(error), "checks": gate.checks, "input_pins": list(gate.pins.values()), "activity": {"model_generations": 0, "model_builds": 0, "Java_runs": 0, "solver_calls": 0, "fixed_point_calls": 0, "CPre_calls": 0, "signals": 0, "GUI_actions": 0}}
    raw = (json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
    with output.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({"status": report["status"], "stage": STAGE, "checks_count": len(gate.checks)}, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
