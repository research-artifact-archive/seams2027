#!/usr/bin/env python3
"""Mutation qualifications; run only after root GO, on accepted A/B inputs.

This driver deliberately does not import the checker or any scientific module.
Each isolated subprocess must accept its unmodified case before any mutation
result is counted. A REJECT proves rejection only, never source unrealizability.
"""

import argparse
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import shutil
import subprocess
import sys
import time


SCHEMA = "v71-obstacle-source-winning-certificate-v1"
MEMORY_BYTES = 1024 * 1024 * 1024
MAX_OUTPUT_FILE_BYTES = 64 * 1024 * 1024
CASE_NAMES = ("A_OLD_PUBLIC_INITIAL", "B_NEW_POINT_R2404")


def target_edge(certificate):
    for record in certificate["states"]:
        for phase in (0, 1):
            for edge in record["policy"][phase]:
                return record, phase, edge
    raise RuntimeError("no policy edge for mutation")


def mutate(certificate, name):
    value = copy.deepcopy(certificate)
    record, phase, edge = target_edge(value)
    if name == "missing_env":
        record["policy"][phase].pop(0)
        return value, "ENV_COVERAGE"
    if name == "extra_illegal_env":
        extra = copy.deepcopy(edge)
        # Shared source obsWaitSwitches makes current wait illegal as next wait.
        extra["env"][2] = record["state"][2]
        record["policy"][phase].append(extra)
        return value, "ENV_COVERAGE"
    if name == "duplicate_env":
        record["policy"][phase].append(copy.deepcopy(edge))
        return value, "DUPLICATE_ENV"
    if name == "unsafe_robot_step":
        edge["sys"][0] = 8 if record["state"][3] <= 4 else 1
        return value, "UNSAFE_EDGE"
    if name == "rank_nondecrease":
        by_state = {tuple(item["state"]): item for item in value["states"]}
        for item in value["states"]:
            for q in (0, 1):
                if item["rank"][q] == 0:
                    continue
                for transition in item["policy"][q]:
                    successor = by_state[tuple(transition["env"] + transition["sys"])]
                    if successor["rank"][q] > 0:
                        # Keep both states off-goal/ranks positive, then make
                        # this edge equal-rank. No rank-zero violation masks it.
                        item["rank"][q] = successor["rank"][q]
                        return value, "RANK_NONDECREASE"
        raise RuntimeError("no off-goal to off-goal edge; rank mutation unavailable")
    if name == "wrong_phase":
        edge["next_phase"] = 1 - edge["next_phase"]
        return value, "WRONG_PHASE"
    if name == "stuck_phase_on_goal":
        for item in value["states"]:
            for q in (0, 1):
                if item["rank"][q] == 0:
                    item["policy"][q][0]["next_phase"] = q
                    return value, "WRONG_PHASE"
        raise RuntimeError("no goal-state phase for mutation")
    if name == "query_mismatch":
        value["query"]["env"][0] = 2 if value["query"]["env"][0] != 2 else 1
        return value, "QUERY_MISMATCH"
    if name == "wrong_source_hash":
        value["source_sha256"] = "0" * 64
        return value, "SOURCE_PIN"
    if name == "wrong_source_path":
        value["source_path"] = value["source_path"] + ".different"
        return value, "SOURCE_PIN"
    if name == "initial_missing":
        value["states"] = [item for item in value["states"] if item["state"] != value["initial"]["state"]]
        return value, "INITIAL_MISSING"
    if name == "wait_integer":
        record["state"][2] = int(record["state"][2])
        return value, "TYPE"
    if name == "unsafe_current_state":
        record["state"][3:] = record["state"][:2]
        return value, "UNSAFE_STATE"
    if name == "sys_boolean":
        edge["sys"][0] = True
        return value, "TYPE"
    if name == "negative_rank":
        record["rank"][phase] = -1
        return value, "RANK_TYPE"
    if name == "oversized_rank":
        record["rank"][phase] = 6272
        return value, "RANK_TYPE"
    if name == "boolean_rank":
        record["rank"][phase] = True
        return value, "RANK_TYPE"
    if name == "zero_off_goal":
        for item in value["states"]:
            for q in (0, 1):
                if item["rank"][q] > 0:
                    item["rank"][q] = 0
                    return value, "RANK_ZERO_GOAL"
        raise RuntimeError("no positive rank for mutation")
    if name == "duplicate_state":
        # Replace instead of append so a full-domain certificate does not
        # accidentally hit STATE_COUNT before the intended duplicate check.
        value["states"][-1] = copy.deepcopy(value["states"][0])
        return value, "DUPLICATE_STATE"
    if name == "missing_successor":
        for item in value["states"]:
            for q in (0, 1):
                for transition in item["policy"][q]:
                    state = transition["env"] + transition["sys"]
                    if state != value["initial"]["state"]:
                        value["states"] = [candidate for candidate in value["states"] if candidate["state"] != state]
                        return value, "R_CLOSURE"
        raise RuntimeError("no noninitial successor for mutation")
    if name == "wrong_completion":
        value["completion"]["after_env_violation"] = "resume_on_next_legal_env"
        return value, "COMPLETION"
    if name == "wrong_case_id":
        value["case_id"] = CASE_NAMES[1] if value["case_id"] == CASE_NAMES[0] else CASE_NAMES[0]
        return value, "QUERY_MISMATCH"
    if name == "missing_phase_policy":
        record["policy"].pop()
        return value, "TYPE"
    if name == "extra_metadata_key":
        value["trust_saved_graph"] = True
        return value, "SCHEMA"
    raise RuntimeError("unknown mutation " + name)


MUTATIONS = (
    "missing_env", "extra_illegal_env", "duplicate_env", "unsafe_robot_step",
    "rank_nondecrease", "wrong_phase", "stuck_phase_on_goal", "query_mismatch", "wrong_source_hash",
    "wrong_source_path", "initial_missing", "wait_integer", "unsafe_current_state", "sys_boolean",
    "negative_rank", "oversized_rank", "boolean_rank", "zero_off_goal", "duplicate_state",
    "missing_successor", "wrong_completion", "wrong_case_id",
    "missing_phase_policy", "extra_metadata_key",
)


def current_rss_bytes(child_pid):
    # ps reports KiB on the supported macOS/Linux hosts. Include the driver
    # and its one active checker, rather than monitoring only the child.
    output = subprocess.check_output(
        ["ps", "-o", "rss=", "-p", str(child_pid) + "," + str(os.getpid())],
        text=True, timeout=5,
    )
    return sum(int(line) * 1024 for line in output.splitlines() if line.strip())


def run_checker(checker, repo_root, explicit_source, case, certificate, output_dir, name, deadline):
    remaining = deadline - time.monotonic()
    if remaining < 2:
        raise TimeoutError("combined qualification deadline exhausted")
    seconds = min(180, int(remaining))
    receipt_path = output_dir / (name + ".receipt.json")
    command = [sys.executable, str(checker), "--case", case,
               "--certificate", str(certificate), "--seconds", str(seconds),
               "--output", str(receipt_path)]
    if repo_root is not None:
        command.extend(["--repo-root", str(repo_root)])
    if explicit_source is not None:
        command.extend(["--source", str(explicit_source)])
    peak_rss = 0
    started = time.monotonic()
    with (output_dir / (name + ".stdout.txt")).open("x") as stdout:
        with (output_dir / (name + ".stderr.txt")).open("x") as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
            try:
                while process.poll() is None:
                    if time.monotonic() >= deadline or time.monotonic() - started > seconds + 1:
                        raise TimeoutError("qualification subprocess deadline exceeded")
                    rss = current_rss_bytes(process.pid)
                    peak_rss = max(peak_rss, rss)
                    if rss > MEMORY_BYTES:
                        raise MemoryError("driver plus checker RSS exceeded 1 GiB")
                    time.sleep(0.05)
            except BaseException:
                if process.poll() is None:
                    process.kill()
                process.wait()
                raise
    if not receipt_path.exists():
        raise RuntimeError("checker produced no receipt; exit=" + str(process.returncode))
    receipt = json.loads(receipt_path.read_text())
    return receipt, process.returncode, peak_rss


def write_json_exclusive(path, value, compact=False):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=None if compact else 2, separators=(",", ":") if compact else None, sort_keys=True, allow_nan=False)
        stream.write("\n")


def lossless_archive_mutation(path):
    """Keep every actual test input, compressed to respect stage output cap."""
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    archive = path.with_suffix(path.suffix + ".gz")
    with path.open("rb") as source:
        with archive.open("xb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
                shutil.copyfileobj(source, zipped)
    with gzip.open(archive, "rb") as stream:
        restored = hashlib.sha256(stream.read()).hexdigest()
    if restored != digest:
        raise RuntimeError("lossless archive hash mismatch")
    path.unlink()
    return {"archive": archive.name, "uncompressed_sha256": digest}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path)
    parser.add_argument("--source-a", type=Path)
    parser.add_argument("--source-b", type=Path)
    parser.add_argument("--a", type=Path, required=True)
    parser.add_argument("--b", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=300)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 300:
        parser.error("combined wall budget must be 1..300 seconds")
    args.output_dir.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    deadline = started + args.seconds
    def deadline_alarm(_signal, _frame):
        raise TimeoutError("combined qualification wall deadline exceeded")
    signal.signal(signal.SIGALRM, deadline_alarm)
    signal.setitimer(signal.ITIMER_REAL, args.seconds)
    checker = Path(__file__).with_name("check_certificate.py")
    report = {"status": "INCOMPLETE_NO_QUALIFICATION_CONCLUSION", "cases": [],
              "checker_sha256": hashlib.sha256(checker.read_bytes()).hexdigest(),
              "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "resource_caps": {"combined_wall_seconds": args.seconds, "combined_active_rss_bytes": MEMORY_BYTES},
              "claim_scope": "checker rejection sensitivity only; no negative realizability result"}
    exit_code = 0
    try:
        # The required external supervisor samples the complete owned tree;
        # this driver's own dynamic RSS check includes its active checker.
        resource.setrlimit(resource.RLIMIT_CPU, (args.seconds, args.seconds))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT_FILE_BYTES, MAX_OUTPUT_FILE_BYTES))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        for case, path, source in ((CASE_NAMES[0], args.a, args.source_a), (CASE_NAMES[1], args.b, args.source_b)):
            case_dir = args.output_dir / case
            case_dir.mkdir()
            baseline, code, peak = run_checker(checker, args.repo_root, source, case, path, case_dir, "baseline", deadline)
            if code != 0 or baseline.get("verdict") != "ACCEPT_POSITIVE_EXISTENCE":
                raise RuntimeError(case + " baseline was not independently accepted")
            raw = path.read_bytes()
            # Actual baseline acceptance above validates parser/schema before
            # this standard JSON decode is used solely to generate mutations.
            certificate = json.loads(raw)
            case_report = {"case_id": case, "certificate_sha256": hashlib.sha256(raw).hexdigest(),
                           "baseline": "ACCEPT_POSITIVE_EXISTENCE", "mutations": [], "peak_combined_rss_bytes": peak}
            report["cases"].append(case_report)
            for name in MUTATIONS:
                changed, expected = mutate(certificate, name)
                changed_path = case_dir / (name + ".json")
                write_json_exclusive(changed_path, changed, compact=True)
                del changed
                receipt, code, peak = run_checker(checker, args.repo_root, source, case, changed_path, case_dir, name, deadline)
                observed = receipt.get("code")
                passed = code == 1 and receipt.get("verdict") == "REJECT" and observed == expected
                archive = lossless_archive_mutation(changed_path)
                case_report["mutations"].append({"name": name, "expected_code": expected, "observed_code": observed, "passed": passed, "input": archive})
                case_report["peak_combined_rss_bytes"] = max(case_report["peak_combined_rss_bytes"], peak)
                if not passed:
                    raise RuntimeError(case + ": mutation " + name + " did not produce expected rejection")
            # Raw duplicate-key case cannot be represented as a Python dict.
            duplicate_path = case_dir / "duplicate_json_key.json"
            with duplicate_path.open("x", encoding="utf-8") as stream:
                stream.write('{"schema":' + json.dumps(SCHEMA) + ',')
                stream.write(raw.decode("utf-8").lstrip()[1:])
            receipt, code, peak = run_checker(checker, args.repo_root, source, case, duplicate_path, case_dir, "duplicate_json_key", deadline)
            passed = code == 1 and receipt.get("verdict") == "REJECT" and receipt.get("code") == "DUPLICATE_JSON_KEY"
            archive = lossless_archive_mutation(duplicate_path)
            case_report["mutations"].append({"name": "duplicate_json_key", "expected_code": "DUPLICATE_JSON_KEY", "observed_code": receipt.get("code"), "passed": passed, "input": archive})
            case_report["peak_combined_rss_bytes"] = max(case_report["peak_combined_rss_bytes"], peak)
            if not passed:
                raise RuntimeError(case + ": duplicate JSON key was not rejected as expected")
        report["status"] = "PASS_REJECTION_QUALIFICATION"
    except (OSError, ValueError, RuntimeError, TimeoutError, MemoryError, subprocess.SubprocessError) as exc:
        report["failure"] = {"type": type(exc).__name__, "detail": str(exc)}
        exit_code = 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    report["elapsed_seconds"] = time.monotonic() - started
    write_json_exclusive(args.output_dir / "qualification_summary.json", report)
    print(json.dumps(report, sort_keys=True, allow_nan=False))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
