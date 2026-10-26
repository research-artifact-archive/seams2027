#!/usr/bin/env python3
"""Independent, positive-only checker for two SHA-bound Spectra sources.

No solver, saved graph, candidate-W evaluator, or fixed-point implementation is
imported.  All predicates below are direct transcriptions of the pinned source
equations; the accompanying RATIONALE.md explains the proof obligation.
"""

import argparse
import hashlib
import itertools
import json
from pathlib import Path
import resource
import signal
import sys
import time


SCHEMA = "v71-obstacle-source-winning-certificate-v1"
SOURCE_DIR = (
    "experiment/v71_acceptance_cycle_20261025/research_strategy_after_r3/"
    "resumed_2333/frontend_workspace/FixedObstacleR4/"
)
CASES = {
    "A_OLD_PUBLIC_INITIAL": {
        "source_path": SOURCE_DIR + "MovingObstacleEvasion.spectra",
        "source_sha256": "19c71d970b05fec41f0fa60fce155bf136b33836ffd785a65c2c436a712c3ac1",
        "source_bytes": 2097,
        "env_init": (7, 7, False),
        "sys_init": (1, 1),
        "forbidden": ((3, 5), (4, 5)),
        "goals": ((5, 2), (2, 3)),
    },
    "B_NEW_POINT_R2404": {
        "source_path": SOURCE_DIR + "MovingObstacleEvasionUpdate_retained_r2404.spectra",
        "source_sha256": "212309df489c3ddc7bf7ec6a750aed2d0da4fb7e26995e5ee3a0405c9897e1d5",
        "source_bytes": 2026,
        "env_init": (3, 5, True),
        "sys_init": (5, 5),
        "forbidden": ((6, 4), (8, 7)),
        "goals": ((3, 7), (4, 8)),
    },
}
COMPLETION = {
    "after_env_violation": "sys_1_1_phase_0_forever",
    "invalid_env_initial": "sys_1_1_phase_0_forever",
    "unreachable_history": "sys_1_1_phase_0_forever",
}
MAX_CERTIFICATE_BYTES = 64 * 1024 * 1024
MAX_STATES = 7 * 7 * 2 * 8 * 8
DEFAULT_SECONDS = 180
MEMORY_BYTES = 1024 * 1024 * 1024
MAX_OUTPUT_FILE_BYTES = 64 * 1024 * 1024
PUBLIC_DIR = "experiment/v71_acceptance_cycle_20261025/positioning/provenance_sources/Specifications/Obstacle Evasion/"
BINDING_PINS = {
    "published_old": {"source_path": PUBLIC_DIR + "MovingObstacleEvasion.spectra", "source_bytes": 2097,
                      "source_sha256": "19c71d970b05fec41f0fa60fce155bf136b33836ffd785a65c2c436a712c3ac1"},
    "published_new": {"source_path": PUBLIC_DIR + "MovingObstacleEvasionUpdate.spectra", "source_bytes": 1947,
                      "source_sha256": "bf2836d68e9a7b019b8f2c9499ccf1ad8dccdc56f5c31ff78ea7d80e45b1a228"},
    "ordinary_projection": {"source_path": "experiment/v71_acceptance_cycle_20261025/published_update/native_preparation/sources/MovingObstacleEvasionUpdate.spectra", "source_bytes": 1902,
                            "source_sha256": "be0eaddf7b165df254d417dcb8cfcd962307f859f1ac3d26514c4a26c4b3954b"},
}
PUBLISHED_SWITCH_SUFFIX = b"switch robotLoc:\nrobot[0] = 5 & robot[1] = 5;"
RETAINED_INITIAL_SUFFIX = (
    b"asm retainedBoundaryEnv:\nobstacle[0] = 3 & obstacle[1] = 5 & obsWait;\n"
    b"gar retainedBoundarySys:\nrobot[0] = 5 & robot[1] = 5;\n"
)


class Rejection(Exception):
    def __init__(self, code, detail):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def require(condition, code, detail):
    if not condition:
        raise Rejection(code, detail)


def exact_keys(value, keys, where):
    require(type(value) is dict, "SCHEMA", where + " must be an object")
    require(set(value) == set(keys), "SCHEMA", where + " has missing or extra keys")


def typed_int(value, low, high, where):
    # isinstance(True, int) is true in Python; that coercion is forbidden here.
    require(type(value) is int and low <= value <= high, "TYPE", where)
    return value


def typed_env(value, where):
    require(type(value) is list and len(value) == 3, "TYPE", where)
    typed_int(value[0], 1, 7, where + ".obstacle0")
    typed_int(value[1], 1, 7, where + ".obstacle1")
    require(type(value[2]) is bool, "TYPE", where + ".obsWait")
    return tuple(value)


def typed_sys(value, where):
    require(type(value) is list and len(value) == 2, "TYPE", where)
    typed_int(value[0], 1, 8, where + ".robot0")
    typed_int(value[1], 1, 8, where + ".robot1")
    return tuple(value)


def typed_state(value, where):
    require(type(value) is list and len(value) == 5, "TYPE", where)
    return typed_env(value[:3], where + ".env") + typed_sys(value[3:], where + ".sys")


def all_typed_env():
    # This is the complete source-declared ENV domain, never a saved graph.
    return itertools.product(range(1, 8), range(1, 8), (False, True))


def all_typed_sys():
    return itertools.product(range(1, 9), range(1, 9))


def environment_initial(case, env):
    # A: initiallyObstacleAtLowerRightCorner & initiallyObsWaitFalse.
    # B: retainedBoundaryEnv (an unqualified, hence initial, assumption).
    return env == case["env_init"]


def system_initial(case, robot):
    # A: initiallyRobotAtZero; B: retainedBoundarySys.
    return robot == case["sys_init"]


def environment_step(state, env_next):
    ox, oy, wait, rx, ry = state
    nx, ny, wait_next = env_next
    # obsWaitSwitches: next wait is the Boolean complement.
    if wait_next != (not wait):
        return False
    # obstacleDoesNotMoveWhenObsWait.
    if wait and (nx != ox or ny != oy):
        return False
    # obstacleMovesAtMostOne / moveObstacle, separately on each coordinate.
    if nx not in (ox - 1, ox, ox + 1) or ny not in (oy - 1, oy, oy + 1):
        return False
    # obstacleIsSmart: four separate implications, not a distance heuristic.
    if not wait:
        if ox > rx and nx != ox - 1:
            return False
        if ox < rx - 1 and nx != ox + 1:
            return False
        if oy > ry and ny != oy - 1:
            return False
        if oy < ry - 1 and ny != oy + 1:
            return False
    return True


def outside_obstacle(robot, obstacle):
    rx, ry = robot
    ox, oy = obstacle
    # Preserve the source's four clauses, including both +1 offsets.
    return (
        (rx != ox or ry != oy)
        and (rx != ox + 1 or ry != oy)
        and (rx != ox or ry != oy + 1)
        and (rx != ox + 1 or ry != oy + 1)
    )


def state_safety(case, state):
    # robotNotOnObstacle and the two AvoidInfinitely safety guarantees.
    robot = state[3:]
    return outside_obstacle(robot, state[:2]) and robot not in case["forbidden"]


def system_step(case, state, env_next, sys_next):
    # robotMovesAtMostOne checks next robot, but robotAvoidsObstacle checks
    # CURRENT robot against NEXT obstacle.  Neither can replace the other.
    rx, ry = state[3:]
    ux, uy = sys_next
    return (
        state_safety(case, state)
        and ux in (rx - 1, rx, rx + 1)
        and uy in (ry - 1, ry, ry + 1)
        and outside_obstacle((rx, ry), env_next[:2])
    )


def on_goal(case, state, phase):
    return state[3:] == case["goals"][phase]


def no_duplicate_json_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY", "duplicate JSON key: " + key)
        result[key] = value
    return result


def reject_nonfinite(value):
    raise Rejection("JSON_NONFINITE", "non-finite JSON number: " + value)


def read_certificate(path):
    require(path.stat().st_size <= MAX_CERTIFICATE_BYTES, "RESOURCE", "certificate exceeds 64 MiB")
    raw = path.read_bytes()
    require(len(raw) <= MAX_CERTIFICATE_BYTES, "RESOURCE", "certificate exceeds 64 MiB")
    parsed = json.loads(raw, object_pairs_hook=no_duplicate_json_keys, parse_constant=reject_nonfinite)
    return parsed, hashlib.sha256(raw).hexdigest()


def source_location(repo_root, case, explicit_source=None):
    require(explicit_source is not None or repo_root is not None, "SOURCE_LOCATION", "provide explicit source bytecopy or repository root")
    return explicit_source if explicit_source is not None else repo_root / case["source_path"]


def source_binding(repo_root, case, explicit_source=None):
    source = source_location(repo_root, case, explicit_source)
    raw = source.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    require(len(raw) == case["source_bytes"], "SOURCE_BYTES", "pinned source length changed")
    require(actual == case["source_sha256"], "SOURCE_HASH", "pinned source content changed")
    return {"path": case["source_path"], "sha256": actual, "bytes": len(raw)}


def verify_certificate(certificate, expected_case, repo_root=None, tick=lambda: None, explicit_source=None):
    exact_keys(certificate, (
        "schema", "case_id", "source_path", "source_sha256", "query",
        "initial", "completion", "states", "provenance",
    ), "certificate")
    require(certificate["schema"] == SCHEMA, "SCHEMA", "wrong certificate version")
    require(expected_case in CASES, "CASE", "checker was not given a pinned case")
    require(certificate["case_id"] == expected_case, "QUERY_MISMATCH", "case_id differs from requested case")
    case = CASES[expected_case]
    require(certificate["source_path"] == case["source_path"], "SOURCE_PIN", "source path differs from pin")
    require(certificate["source_sha256"] == case["source_sha256"], "SOURCE_PIN", "source hash differs from pin")
    source_receipt = source_binding(repo_root, case, explicit_source)
    exact_keys(certificate["query"], ("kind", "env", "sys"), "query")
    query = certificate["query"]
    query_env = typed_env(query["env"], "query.env")
    query_sys = typed_sys(query["sys"], "query.sys")
    require(query["kind"] == "source_initial", "QUERY_MISMATCH", "query kind is not source_initial")
    require(query_env == case["env_init"] and query_sys == case["sys_init"], "QUERY_MISMATCH", "query coordinates differ from pinned source")
    exact_keys(certificate["initial"], ("state", "phase"), "initial")
    initial = typed_state(certificate["initial"]["state"], "initial.state")
    typed_int(certificate["initial"]["phase"], 0, 0, "initial.phase")
    require(initial == query_env + query_sys, "QUERY_MISMATCH", "initial differs from query")
    require(certificate["completion"] == COMPLETION, "COMPLETION", "typed-total completion differs from protocol")
    require(type(certificate["provenance"]) is dict, "SCHEMA", "provenance must be informational object")
    records = certificate["states"]
    require(type(records) is list and 1 <= len(records) <= MAX_STATES, "STATE_COUNT", "candidate R must contain 1..6272 states")

    by_state = {}
    for index, record in enumerate(records):
        tick()
        where = "states[" + str(index) + "]"
        exact_keys(record, ("state", "rank", "policy"), where)
        state = typed_state(record["state"], where + ".state")
        require(state not in by_state, "DUPLICATE_STATE", where)
        require(state_safety(case, state), "UNSAFE_STATE", where + " violates current-state source safety")
        rank = record["rank"]
        require(type(rank) is list and len(rank) == 2, "TYPE", where + ".rank")
        for phase in (0, 1):
            require(type(rank[phase]) is int and 0 <= rank[phase] < MAX_STATES, "RANK_TYPE", where + ".rank must be an integer in 0..6271")
            require((rank[phase] == 0) == on_goal(case, state, phase), "RANK_ZERO_GOAL", where + " rank zero iff goal failed")
        require(type(record["policy"]) is list and len(record["policy"]) == 2, "TYPE", where + ".policy")
        by_state[state] = record

    require(initial in by_state, "INITIAL_MISSING", "pinned source initializer absent from candidate R")

    # Actual source initializer quantification, independently over the full
    # 98 ENV and 64 SYS typed initial domains.  Each pinned source has one
    # admissible ENV initial; its required SYS initializer is also unique.
    initial_envs = 0
    initial_pairs = 0
    for env in all_typed_env():
        tick()
        if environment_initial(case, env):
            initial_envs += 1
            witnesses = [robot for robot in all_typed_sys()
                         if system_initial(case, robot) and env + robot in by_state]
            require(bool(witnesses), "INITIAL_QUANTIFICATION", "legal ENV initial lacks SYS initial in R")
            initial_pairs += len(witnesses)
    require(initial_envs == 1 and initial_pairs == 1, "INITIAL_QUANTIFICATION", "initializer did not match unique pinned source pair")

    policy_count = 0
    legal_input_count = 0
    for state, record in by_state.items():
        tick()
        # Re-enumerate ALL 98 source-typed inputs even if R uses only a subset.
        legal = {env for env in all_typed_env() if environment_step(state, env)}
        require(bool(legal), "ENV_DEADEND", "candidate R state has no legal ENV successor")
        legal_input_count += len(legal)
        for phase in (0, 1):
            policy = record["policy"][phase]
            require(type(policy) is list and len(policy) <= 98, "TYPE", "phase policy must be a list of at most 98 entries")
            edges = {}
            for edge in policy:
                exact_keys(edge, ("env", "sys", "next_phase"), "edge")
                env = typed_env(edge["env"], "edge.env")
                response = typed_sys(edge["sys"], "edge.sys")
                next_phase = typed_int(edge["next_phase"], 0, 1, "edge.next_phase")
                require(env not in edges, "DUPLICATE_ENV", "phase policy repeats an ENV input")
                edges[env] = (response, next_phase)
            require(set(edges) == legal, "ENV_COVERAGE", "phase policy missing or adding legal ENV inputs: missing=" + str(len(legal - set(edges))) + ", extra=" + str(len(set(edges) - legal)))
            for env, (response, next_phase) in edges.items():
                tick()
                require(system_step(case, state, env, response), "UNSAFE_EDGE", "source SYS safety fails at " + str(state) + " -> " + str(env + response))
                successor = env + response
                require(successor in by_state, "R_CLOSURE", "safe response leaves candidate R")
                # R's state checks imply next-state safety; keep explicit
                # assertion so that this obligation remains visible.
                require(state_safety(case, successor), "UNSAFE_SUCCESSOR", "successor violates source state safety")
                if on_goal(case, state, phase):
                    require(next_phase == 1 - phase, "WRONG_PHASE", "goal hit must alternate phase")
                else:
                    require(next_phase == phase, "WRONG_PHASE", "off-goal phase must remain unchanged")
                    require(by_state[successor]["rank"][phase] < record["rank"][phase], "RANK_NONDECREASE", "off-goal edge does not strictly decrease active rank")
                policy_count += 1

    return {
        "verdict": "ACCEPT_POSITIVE_EXISTENCE",
        "claim_scope": "two pinned source-initial positive winning queries only; no maximality or negative-query conclusion",
        "case_id": expected_case,
        "source": source_receipt,
        "query": query,
        "initial_phase": 0,
        "states_checked": len(by_state),
        "legal_env_inputs_per_state_total": legal_input_count,
        "policy_edges_checked": policy_count,
        "initializer_quantification": {"typed_env_enumerated": 98, "typed_sys_per_legal_env": 64, "legal_env_initials": initial_envs, "sys_initial_witnesses": initial_pairs},
        "completion": COMPLETION,
        "provenance_used_as_premise": False,
        "global_env_totality": "NOT_CHECKED_IN_WINNING_PROOF",
    }


def verify_projection_binding(repo_root, explicit_sources, binding_sources):
    receipts = {name: source_binding(repo_root, pin, binding_sources.get(name)) for name, pin in BINDING_PINS.items()}
    data = {name: source_location(repo_root, pin, binding_sources.get(name)).read_bytes() for name, pin in BINDING_PINS.items()}
    old = source_location(repo_root, CASES["A_OLD_PUBLIC_INITIAL"], explicit_sources.get("A_OLD_PUBLIC_INITIAL")).read_bytes()
    retained = source_location(repo_root, CASES["B_NEW_POINT_R2404"], explicit_sources.get("B_NEW_POINT_R2404")).read_bytes()
    require(old == data["published_old"], "SOURCE_RELATION", "A is not byte-identical to published old")
    require(len(PUBLISHED_SWITCH_SUFFIX) == 45 and data["published_new"] == data["ordinary_projection"] + PUBLISHED_SWITCH_SUFFIX, "SOURCE_RELATION", "published new differs from projection by more than exact 45-byte switch suffix")
    require(len(RETAINED_INITIAL_SUFFIX) == 124 and retained == data["ordinary_projection"] + RETAINED_INITIAL_SUFFIX, "SOURCE_RELATION", "retained B differs from projection by more than exact 124-byte initializer")
    return {"pins": receipts, "A_identical_to_published_old": True,
            "B_projection_bytes": 1902, "B_point_initializer_bytes": 124,
            "published_new_switch_suffix_bytes": 45,
            "ordinary_projection_plus_initializer_equals_retained_B": True,
            "ordinary_projection_plus_switch_equals_published_new": True,
            "claim_scope": "byte identities only; not a handoff or dynamic-update proof"}


def verify_environment_totality(expected_case, repo_root=None, tick=lambda: None, explicit_sources=None, binding_sources=None):
    """Optional, separate source-model bridge; not the winning proof itself."""
    # The direct source reads establish that all ENV transition equations are
    # identical in A and B. Bind both original files, not a producer claim.
    explicit_sources = explicit_sources or {}
    source_pair = {name: source_binding(repo_root, item, explicit_sources.get(name)) for name, item in CASES.items()}
    source_receipt = source_pair[expected_case]
    projection_binding = verify_projection_binding(repo_root, explicit_sources, binding_sources or {})
    states = 0
    legal_edges = 0
    minimum = 98
    maximum = 0
    for env in all_typed_env():
        for robot in all_typed_sys():
            tick()
            state = env + robot
            count = sum(environment_step(state, env_next) for env_next in all_typed_env())
            require(count > 0, "GLOBAL_ENV_DEADEND", "typed state lacks legal ENV successor: " + str(state))
            states += 1
            legal_edges += count
            minimum = min(minimum, count)
            maximum = max(maximum, count)
    require(states == MAX_STATES, "INTERNAL", "typed state domain count mismatch")
    return {
        "verdict": "ACCEPT_SOURCE_ENV_TOTALITY_ONLY",
        "case_id": expected_case,
        "source": source_receipt,
        "both_source_bindings": source_pair,
        "projection_and_point_binding": projection_binding,
        "typed_states_checked": states,
        "typed_env_candidates_per_state": 98,
        "legal_env_edges": legal_edges,
        "min_legal_env_outdegree": minimum,
        "max_legal_env_outdegree": maximum,
        "claim_scope": "source-specific ENV-totality bridge only; no general K=Kind claim and no winning-set claim",
    }


def install_limits(seconds):
    require(1 <= seconds <= DEFAULT_SECONDS, "RESOURCE", "time bound must be 1..180 seconds")
    # RSS enforcement belongs to the required owned-process-tree supervisor.
    # Virtual address space is deliberately not used as a proxy for RSS.
    # Fail closed if these additional CPU/file/core limits cannot be installed.
    resource.setrlimit(resource.RLIMIT_CPU, (seconds, seconds))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT_FILE_BYTES, MAX_OUTPUT_FILE_BYTES))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    started = time.monotonic()

    def deadline(_signum, _frame):
        raise Rejection("TIMEOUT", "wall time budget exceeded")

    signal.signal(signal.SIGALRM, deadline)
    signal.setitimer(signal.ITIMER_REAL, seconds)

    def tick():
        require(time.monotonic() - started < seconds, "TIMEOUT", "wall time budget exceeded")
    return tick


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, help="optional repository root when explicit source bytecopies are not supplied")
    parser.add_argument("--source", type=Path, help="exact source bytecopy for --certificate; provenance path stays pinned")
    parser.add_argument("--source-a", type=Path, help="exact A source bytecopy for --env-totality-only")
    parser.add_argument("--source-b", type=Path, help="exact B source bytecopy for --env-totality-only")
    parser.add_argument("--published-old", type=Path, help="exact published old source bytecopy for totality/binding mode")
    parser.add_argument("--published-new", type=Path, help="exact published new source bytecopy for totality/binding mode")
    parser.add_argument("--ordinary-projection", type=Path, help="exact ordinary projection bytecopy for totality/binding mode")
    parser.add_argument("--case", choices=tuple(CASES), required=True)
    parser.add_argument("--certificate", type=Path)
    parser.add_argument("--env-totality-only", action="store_true")
    parser.add_argument("--seconds", type=int, default=DEFAULT_SECONDS)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if bool(args.certificate) == args.env_totality_only:
        parser.error("choose exactly one of --certificate and --env-totality-only")
    if args.env_totality_only and args.source:
        parser.error("totality mode uses --source-a and --source-b, not --source")
    if args.certificate and (args.source_a or args.source_b or args.published_old or args.published_new or args.ordinary_projection):
        parser.error("certificate mode uses --source, not totality/binding source options")
    started = time.monotonic()
    certificate_sha = None
    exit_code = 0
    try:
        tick = install_limits(args.seconds)
        if args.env_totality_only:
            source_overrides = {name: path for name, path in (("A_OLD_PUBLIC_INITIAL", args.source_a), ("B_NEW_POINT_R2404", args.source_b)) if path is not None}
            binding_overrides = {name: path for name, path in (("published_old", args.published_old), ("published_new", args.published_new), ("ordinary_projection", args.ordinary_projection)) if path is not None}
            result = verify_environment_totality(args.case, args.repo_root, tick, source_overrides, binding_overrides)
        else:
            certificate, certificate_sha = read_certificate(args.certificate)
            result = verify_certificate(certificate, args.case, args.repo_root, tick, args.source)
    except Rejection as exc:
        result = {"verdict": "REJECT", "code": exc.code, "detail": exc.detail, "case_id": args.case}
        exit_code = 1
    except (OSError, ValueError, TypeError, RecursionError, MemoryError) as exc:
        result = {"verdict": "ERROR_NO_CONCLUSION", "code": type(exc).__name__, "detail": str(exc), "case_id": args.case}
        exit_code = 2
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    result.update({
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "certificate_sha256": certificate_sha,
        "elapsed_seconds": time.monotonic() - started,
        "resource_limits": {"wall_seconds": args.seconds, "cpu_seconds": args.seconds,
                            "single_output_file_bytes": MAX_OUTPUT_FILE_BYTES, "core_dump_bytes": 0,
                            "required_external_process_tree_rss_bytes": MEMORY_BYTES,
                            "rss_enforcement": "separate owned-supervisor receipt required; standalone acceptance does not establish RSS compliance"},
        "python_version": sys.version,
    })
    # Exclusive creation prevents replacing an earlier evidence receipt.
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
