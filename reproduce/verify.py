#!/usr/bin/env python3
"""Verify this public distribution; no scientific checker or solver is executed.

Python 3.9+ standard library. Run from any directory with:
    python3 -I -S -B /path/to/seams2027/reproduce/verify.py
The adjacent MANIFEST.json is the declared inventory, not a signature. Verify a
trusted Git tag/commit separately when authenticity, rather than consistency,
is required. Archive preservation is also checked against embedded v69 pins.
"""

from datetime import datetime, timezone
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import unicodedata
from urllib.parse import unquote, urlsplit
import zipfile

BASELINE_COMMIT = "11a828f65f91a9b4950a18d189a702fb18ec8ed5"
BASELINE_ARCHIVES = {
  "continuation-evidence-20261024-v1.zip": {
    "bytes": 14634992,
    "sha256": "db81f7ea6703ae885d69b04f9705755078776bf747876005bb75c93dfc46d74e"
  },
  "fixed-seven-native-evidence-20261024-v1.zip": {
    "bytes": 1536588,
    "sha256": "33d33874d0c4dd7c6c095456387b51147959aa001b258ffbe6490f18bf648fe3"
  },
  "intruder-bounded-evidence-20261021.zip": {
    "bytes": 8218871,
    "sha256": "3de085e5a441c408fdeac370a87c58c9f2c1d6e432cba5dd4043b3b19a7401f1"
  },
  "intruder-certificate-evidence-20261023-v1.zip": {
    "bytes": 3337041,
    "sha256": "bc1f35b49b65217780d27c0d5a84891ea7692882317cd56ae1ee6dc27cc048d6"
  },
  "lift-causal-extension-public-20261021-v1.zip": {
    "bytes": 2986678,
    "sha256": "64ba40d58edd2b5b04a7583c4e5ee32fe184b9d5c264026201fcfa5b4b747d07"
  },
  "lift-direct-static-public-20261020-v1.zip": {
    "bytes": 629842,
    "sha256": "e9f4db132e200d0cfb0d4a17941bf9a74f98399060164106a154d6ccd5ec7b18"
  },
  "lift-native-regeneration-public-20261021-v1.zip": {
    "bytes": 164041,
    "sha256": "6f66808cfd27c49385306eea6eab089a0fd09981f6517a1257077e56178273a0"
  },
  "noninitial-handoff-evidence-20261021-v1.zip": {
    "bytes": 1421188,
    "sha256": "91173cacf4375f097865a673fee5b297979d75a755a5181ceaaac7669f565fe3"
  },
  "normalized-eleven-public-20261021-v1.zip": {
    "bytes": 10958466,
    "sha256": "4964794a933d6369400e364ecc417b9ff6c6ae8ea867c02ef57a9a3bb8adb252"
  },
  "pending-native-handoff-evidence-20261023-v1.zip": {
    "bytes": 1086212,
    "sha256": "a2143be83a241b2d24b78049741bed7b8c2ad8d3529a3fd928cb363c8445c2c9"
  },
  "residual-census-evidence-20261021-v1.zip": {
    "bytes": 2416876,
    "sha256": "bbc9ac7969bc0d65485b79b2c61be93cfd0a65a030fc926124b22921111cc08e"
  },
  "saved-evidence-public-20261020-v1.zip": {
    "bytes": 54966104,
    "sha256": "27a069fd31a5f534a4b0a370d70d3077ed338070b632e007d08ea66966bf6f61"
  },
  "seams2027-20261023-pending-diagnostic-evidence-v1.zip": {
    "bytes": 525798,
    "sha256": "151a8d04517d853aff771c2eb338fb72aba11ab21cfc2f43eb9c1e09ed7a398d"
  },
  "three-study-evidence-20261023-v2.zip": {
    "bytes": 3054446,
    "sha256": "54e6afe29c0289ba982d14056e2a5002cee5d9e32b6dff93d33f6421646dd0a9"
  },
  "vehicle188-native-evidence-20261024-v1.zip": {
    "bytes": 331833,
    "sha256": "f73a52304e2d8ec48e97670a2d99d58c442a0f6644faa1badcaaaa709cd89e16"
  },
  "vehicle188-whole-region-evidence-20261024-v1.zip": {
    "bytes": 487481,
    "sha256": "e13fcdaac9344d7ec314f35a14ff88deeafa8f87858704ccd53127ea15db1c47"
  },
  "verification-addendum-public-20261020-v1.zip": {
    "bytes": 2154161,
    "sha256": "41932536fc544197bc0868cfd3bd8e85342b5e268c437d18b1ee4903443bd177"
  }
}
MANIFEST_PATH = "reproduce/MANIFEST.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_path(root, value):
    require(isinstance(value, str) and value, "Empty or invalid path")
    relative = PurePosixPath(value)
    require(not relative.is_absolute() and ".." not in relative.parts
            and "\\" not in value and relative.as_posix() == value,
            "Unsafe/noncanonical path: " + value)
    target = root.joinpath(*relative.parts)
    require(target.resolve().is_relative_to(root), "Escaping path: " + value)
    require(not target.is_symlink(), "Symlink: " + value)
    return target


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def verify_record(root, row):
    path = safe_path(root, row["path"])
    require(path.is_file(), "Missing file: " + row["path"])
    require(path.stat().st_size == row["bytes"], "Changed size: " + row["path"])
    require(sha256(path) == row["sha256"], "Changed SHA-256: " + row["path"])
    return path


def markdown_body(text):
    # Exclude fenced and inline code, where link-like strings are examples.
    lines = []
    fence = None
    for line in text.splitlines():
        match = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if match:
            token = match.group(1)
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            continue
        if fence is None:
            lines.append(line)
    return "\n".join(lines)


def anchors(text):
    found = set(re.findall(r"(?:id|name)=[\"']([^\"']+)[\"']", text))
    counts = {}
    lines = markdown_body(text).splitlines()
    headings = []
    for index, line in enumerate(lines):
        match = re.match(r"^\s{0,3}#{1,6}\s+(.+?)(?:\s+#+\s*)?$", line)
        if match:
            headings.append(match.group(1))
        elif index + 1 < len(lines) and re.match(r"^\s{0,3}(?:=+|-+)\s*$", lines[index + 1]):
            headings.append(line.strip())
    for heading in headings:
        heading = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", heading)
        heading = re.sub(r"<[^>]+>", "", heading).lower()
        # GitHub keeps letters/numbers/marks, spaces, underscore and hyphen.
        slug = "".join(c for c in heading if c in " _-" or
                       unicodedata.category(c)[0] in "LNM")
        slug = slug.replace(" ", "-")
        index = counts.get(slug, 0)
        counts[slug] = index + 1
        found.add(slug if not index else slug + "-" + str(index))
    return found


def markdown_links(text):
    body = re.sub(r"(`+)(.*?)\1", "", markdown_body(text))
    links = re.findall(r"!?\[[^\]\n]*\]\(\s*(<[^>]+>|[^\s)]+)(?:\s+[\"'][^\n]*?[\"'])?\s*\)", body)
    links.extend(re.findall(r"^\s*\[[^\]]+\]:\s*(<[^>]+>|\S+)", body, re.M))
    links.extend(re.findall(r"(?:href|src)=[\"']([^\"']+)[\"']", body))
    return [link[1:-1] if link.startswith("<") else link for link in links]


def verify_links(root, file_paths):
    checked = 0
    remote = 0
    anchor_checks = 0
    for relative in file_paths:
        if not relative.lower().endswith(".md"):
            continue
        page = root / relative
        for link in markdown_links(page.read_text(encoding="utf-8")):
            parsed = urlsplit(link)
            if parsed.scheme or parsed.netloc:
                remote += 1
                continue
            destination = unquote(parsed.path)
            require(not destination.startswith("/") and "\\" not in destination,
                    "Nonportable local link in " + relative + ": " + link)
            target = (page.parent / destination).resolve() if destination else page
            require(target.is_relative_to(root) and target.exists(),
                    "Broken/escaping local link in " + relative + ": " + link)
            require(not target.is_symlink(), "Symlink link target: " + link)
            if target.is_dir():
                candidates = [target / name for name in ("README.md", "readme.md")]
                if parsed.fragment:
                    target = next((p for p in candidates if p.is_file()), target)
            if parsed.fragment and target.suffix.lower() == ".md":
                require(unquote(parsed.fragment) in anchors(target.read_text(encoding="utf-8")),
                        "Broken local anchor in " + relative + ": " + link)
                anchor_checks += 1
            checked += 1
    return {"local_links_checked": checked, "local_markdown_anchors_checked": anchor_checks,
            "external_links_not_requested": remote}


def verify_paper_source_tree(root, paper):
    tree = paper["source_tree"]
    require(tree["directory"] == "paper/source", "Wrong paper source directory")
    directory = safe_path(root, tree["directory"])
    require(directory.is_dir(), "Missing paper source directory")
    prefix = tree["archive_prefix"]
    require(isinstance(prefix, str) and prefix.endswith("/") and prefix != "/",
            "Invalid paper archive prefix")
    safe_path(root, prefix[:-1])
    expected = set()
    total_bytes = 0
    with zipfile.ZipFile(root / "paper/source.zip") as archive:
        infos = archive.infolist()
        require(len(infos) == len({info.filename for info in infos}),
                "Duplicate paper source ZIP member")
        for info in infos:
            require(info.filename.startswith(prefix), "Paper source member outside prefix: " + info.filename)
            require(not stat.S_ISLNK(info.external_attr >> 16), "Symlink in paper source ZIP")
            relative = info.filename[len(prefix):]
            if info.is_dir():
                if relative:
                    safe_path(directory, relative.rstrip("/"))
                continue
            target = safe_path(directory, relative)
            require(target.is_file(), "Missing paper source mirror: " + relative)
            require(target.stat().st_size == info.file_size,
                    "Changed paper source mirror size: " + relative)
            require(target.read_bytes() == archive.read(info),
                    "Paper source mirror differs from ZIP: " + relative)
            expected.add(relative)
            total_bytes += info.file_size
    require(len(expected) == tree["files"] and len(expected) > 0,
            "Paper source mirror count differs")
    actual = set()
    for path in directory.rglob("*"):
        require(not path.is_symlink(), "Symlink in paper source mirror")
        if path.is_file():
            actual.add(path.relative_to(directory).as_posix())
    require(actual == expected, "Paper source mirror roster differs")
    return {"paper_source_files_verified": len(expected),
            "paper_source_bytes_verified": total_bytes}




# V71 extension: historical preservation checks above remain exact.
V71_ARCHIVES = {'AA-COMPILED44': {'archive': 'v71-compiled-cohort-evidence-20261026.zip', 'prefix': 'aa_compiled44/', 'siblings': [], 'counts': {'sources': 11, 'registered_arms': 44, 'native_candidates': 43, 'accepted_arms': 40, 'unknown_arms': 4}}, 'AC-OBSTACLE8CERT98': {'archive': 'v71-obstacle-evidence-20261026.zip', 'prefix': 'ac_obstacle8cert98/', 'siblings': [], 'counts': {'saved_certificates': 8, 'switch_states_per_arm': 98, 'prior_fixed_point_unknown': 8, 'prior_certificate_unknown': 1, 'prior_certificate_not_attempted': 7}}, 'Z-HISTORICAL-PATROL': {'archive': 'v71-historical-patrol-source-20261026.zip', 'prefix': 'z_historical_patrol/', 'siblings': [], 'counts': {'new_executions': 0}}, 'AD-PUBLIC-KIND-GUI': {'archive': 'v71-public-kind-gui-evidence-20261026.zip', 'prefix': 'ad_gui_kind_ab/', 'siblings': ['AC-OBSTACLE8CERT98'], 'counts': {'gui_actions': 2, 'A_actions': 1, 'B_actions': 1, 'preparation_supervisor_unknown': 1}}}
V71_LEGACY_ROOT_IDS = ['Core', 'Verification', 'Lift', 'LiftCausal', 'LiftRegeneration', 'NormalizedEleven', 'ResidualCensus', 'NoninitialHandoff', 'IntruderBounded', 'IntruderCertificate', 'FiniteStudies', 'PendingNativeHandoff', 'PendingDiagnostic', 'Continuation', 'Vehicle188Native', 'Vehicle188Whole', 'FixedSevenNative']
V71_LEGACY_ROW_IDS = ['C59', 'C14', 'R11', 'GUARD-CONSTRUCTED', 'LIFT-T-SELECTED-POLICY', 'V188-P1', 'V188-P2', 'V188-P3', 'LIFT-P-DIRECT', 'LIFT-T-CAUSAL', 'SIX-DORMANT-CONTROLS', 'LIFT-MODELED-ADAPTATION', 'LIFT-PUBLIC-NATIVE-REGENERATION', 'LIFT-NODE680-STRICT-STATE-CERTIFICATE', 'NORMALIZED-ELEVEN-ORIGINAL-INITIALIZER', 'RESIDUAL-ELEVATOR-11-STATE-CENSUS', 'LIFT-NONINITIAL-HANDOFF-10-BOUNDARY-CENSUS', 'INTRUDER-BOUNDED-UNKNOWN-ORIGINAL-SOURCE', 'INTRUDER-SAVED-SOURCE-CERTIFICATES', 'FINITE-REQUEST-PROTOCOL-SIX-CELLS', 'HUMANOID-EIGHT-ARM-GUARD-CENSUS', 'GUARD-SAVED-ARENA-CAUSAL-AUDIT', 'pending-native-handoff-all-three-obligations', 'pending-diagnostic-patrol-saved-audit', 'pending-diagnostic-extended-lift-continuation', 'continuation-evidence-current-entrypoint', 'vehicle188-native-strict-selected-state', 'vehicle188-whole-region', 'fixed-seven-native']
V71_LEGACY_SOURCE_PATHS = ['tool/src/vehicle188/independent_core.py', 'tool/src/vehicle188/producer_core.py', 'tool/src/vehicle188/replay.py', 'tool/src/fixed-seven/independent_auditor.py', 'tool/src/fixed-seven/replay.py', 'tool/src/continuation/lasso/replay/code/independent_core.py', 'tool/src/continuation/lasso/replay/code/source_contracts.py', 'tool/src/continuation/lasso/replay/replay_lasso.py', 'tool/src/continuation/records/guard/check_guard_saved_arena.py', 'tool/src/continuation/replay/manager_semantics.py', 'tool/src/continuation/replay/reduced_semantics.py', 'tool/src/continuation/replay/replay.py', 'tool/src/graph-admission/initial_graph_checker.py', 'tool/src/graph-admission/vendor/bdd_core.py', 'tool/src/graph-admission/vendor/graph_fairness.py']
V71_LEGACY_ROOTS_SHA = '077fe4f166528789591dcbca292ff6e4408db86fb2da70d74159b6d8c6e2b177'
V71_LEGACY_ROWS_SHA = '7c9efbb6e6c6ca86aa8b1366ed1a93c14e7e55d49e14d53e6b48bf1def89a86f'
V71_LEGACY_FETCH_SHA = 'b5b9c6e78a1f272d6912d227ca773ae6658eea14ccba122b8a534360fc83d93a'
V71_LEGACY_SOURCES_SHA = '59347178103a2815c6df1e8987f382f54500d0b5df279764405f0f7cd0e6f6b7'


# R6 additions preserve the complete adopted r5 records below.
PUBLIC_ADOPTION_PATH = 'results/POSITIVE_CERTIFICATES_PUBLICATION_ADOPTION.json'
PACKAGE_FREEZE_UTC = '2026-10-25T19:15:58.993443+00:00'
REPLAYED_V1_ZIP = {'bytes': 2347279, 'sha256': 'e1359c08454430ff19c8af2a8322a426d089b8a1c0cd180a2c631f267782ac8b'}
PUBLIC_ADOPTION_SCOPE = {'adoption_kind': 'exact_public_v2_package_candidate', 'replayed_scientific_inputs': 'exact_public_v1_existing_host', 'v2_container_scientifically_replayed': False, 'fresh_host_or_external_reproduction': False, 'fully_hermetic_execution': False, 'external_publication_asserted': False, 'push_release_or_conference_status': 'not_attested_by_this_record'}
R6_ARCHIVE_ID = 'AE-R6-POSITIVE-CONTROLS'
R6_ARCHIVE_RECORD = {'id': 'AE-R6-POSITIVE-CONTROLS', 'path': 'results/archives/v71-r6-positive-certificates-and-controls-20261026.zip', 'archive_prefix': 'r6_positive_certificates_and_controls/', 'sibling_dependencies': [], 'bytes': 2729454, 'sha256': '7a71e382afb1bca414b107545c8b410ff5b8b9437a6b76aaf67f119937f218a3', 'package_manifest': {'member': 'r6_positive_certificates_and_controls/MANIFEST.json', 'bytes': 116230, 'sha256': '20e045f1f3d7dfc44322f0f72eb34abd285a976d40a8533e5aefe912518cc32d'}, 'files_including_manifest': 548, 'uncompressed_bytes': 6673455}
R6_PRIOR_ARCHIVE_IDS = ['AA-COMPILED44', 'AC-OBSTACLE8CERT98', 'Z-HISTORICAL-PATROL', 'AD-PUBLIC-KIND-GUI']
R6_PRIOR_ROOT_IDS = ['Core', 'Verification', 'Lift', 'LiftCausal', 'LiftRegeneration', 'NormalizedEleven', 'ResidualCensus', 'NoninitialHandoff', 'IntruderBounded', 'IntruderCertificate', 'FiniteStudies', 'PendingNativeHandoff', 'PendingDiagnostic', 'Continuation', 'Vehicle188Native', 'Vehicle188Whole', 'FixedSevenNative', 'AA-COMPILED44', 'AC-OBSTACLE8CERT98', 'Z-HISTORICAL-PATROL', 'AD-PUBLIC-KIND-GUI']
R6_PRIOR_ROW_IDS = ['C59', 'C14', 'R11', 'GUARD-CONSTRUCTED', 'LIFT-T-SELECTED-POLICY', 'V188-P1', 'V188-P2', 'V188-P3', 'LIFT-P-DIRECT', 'LIFT-T-CAUSAL', 'SIX-DORMANT-CONTROLS', 'LIFT-MODELED-ADAPTATION', 'LIFT-PUBLIC-NATIVE-REGENERATION', 'LIFT-NODE680-STRICT-STATE-CERTIFICATE', 'NORMALIZED-ELEVEN-ORIGINAL-INITIALIZER', 'RESIDUAL-ELEVATOR-11-STATE-CENSUS', 'LIFT-NONINITIAL-HANDOFF-10-BOUNDARY-CENSUS', 'INTRUDER-BOUNDED-UNKNOWN-ORIGINAL-SOURCE', 'INTRUDER-SAVED-SOURCE-CERTIFICATES', 'FINITE-REQUEST-PROTOCOL-SIX-CELLS', 'HUMANOID-EIGHT-ARM-GUARD-CENSUS', 'GUARD-SAVED-ARENA-CAUSAL-AUDIT', 'pending-native-handoff-all-three-obligations', 'pending-diagnostic-patrol-saved-audit', 'pending-diagnostic-extended-lift-continuation', 'continuation-evidence-current-entrypoint', 'vehicle188-native-strict-selected-state', 'vehicle188-whole-region', 'fixed-seven-native', 'AA-COMPILED44', 'AC-OBSTACLE8CERT98', 'Z-HISTORICAL-PATROL', 'AD-PUBLIC-KIND-GUI']
R6_PRIOR_SOURCE_PATHS = ['tool/src/vehicle188/independent_core.py', 'tool/src/vehicle188/producer_core.py', 'tool/src/vehicle188/replay.py', 'tool/src/fixed-seven/independent_auditor.py', 'tool/src/fixed-seven/replay.py', 'tool/src/continuation/lasso/replay/code/independent_core.py', 'tool/src/continuation/lasso/replay/code/source_contracts.py', 'tool/src/continuation/lasso/replay/replay_lasso.py', 'tool/src/continuation/records/guard/check_guard_saved_arena.py', 'tool/src/continuation/replay/manager_semantics.py', 'tool/src/continuation/replay/reduced_semantics.py', 'tool/src/continuation/replay/replay.py', 'tool/src/graph-admission/initial_graph_checker.py', 'tool/src/graph-admission/vendor/bdd_core.py', 'tool/src/graph-admission/vendor/graph_fairness.py', 'tool/src/compiled-cohort/audit_core.py', 'tool/src/obstacle/check_saved.py']
R6_PRIOR_FINGERPRINTS = {'evidence_rows': '35857095da96d329ab29ea1ce74de9ab7740702e8e3ead54ff1467b752ae296f', 'archive_roots': 'ae73057373aefd7663357a50969b68a386deaaed7a1ab65fe331136f2c48898b', 'source_rows': 'b00e165e34ac934e760e6d95d5de2f06f48c18d61dae0978328c7db69a010eb7', 'archive_addition_rows': 'bc38dfbb193e81bcafe3adac1f850dfeee5370f7a8dbda617646234ab1f2563d'}
R6_NEW_ROW_SHA = '77bf9fdf8103aeb797bbe3dde63db811e9481e9db2a6b7c0e4a06f8592a9434d'
R6_NEW_SOURCES_SHA = '9d676b1226085fb60a72b0376bc82c56e5c17eadd4996244beb020b94855d05e'
V71_ARCHIVES[R6_ARCHIVE_ID] = {'archive': 'v71-r6-positive-certificates-and-controls-20261026.zip', 'prefix': 'r6_positive_certificates_and_controls/', 'siblings': [], 'counts': {'positive_certificates': 2, 'A_states': 5016, 'A_policy_edges': 12656, 'B_states': 5015, 'B_policy_edges': 12672, 'rank_maximum_each_phase': 17, 'all_domain_states': 6272, 'typed_ENV_candidates_each': 98, 'legal_ENV_edges': 9536, 'malformed_expected_rejections': 50, 'qualification_positive_controls': 2, 'ordinary_GUI_actions': 2, 'ordinary_TRUE': 2, 'prior_Kind_FALSE': 2, 'direct_rejection_input_hashes': 48, 'duplicate_key_null_input_hashes': 2, 'prior_fixed_point_UNKNOWN': 8}}


# R8 control revision; historical AF-R7 science identity is retained.
DIAGNOSTIC_PUBLIC_ADOPTION_PATH = 'results/SAME_SOLVER_DIAGNOSTIC_PUBLICATION_ADOPTION.json'
DIAGNOSTIC_FREEZE_UTC = '2026-10-25T22:04:05.077925+00:00'
DIAGNOSTIC_PUBLIC_SCOPE = {'adoption_kind': 'exact_AF_diagnostic_public_package_candidate', 'unchanged_outcome': False, 'S01_outcome': 'UNKNOWN', 'S01_Boolean_present': False, 'S01_capture_complete': False, 'S01_immediate_observed_failure': 'RAW_STDOUT_CAP', 'intervention_effect': 'UNRESOLVED', 'executed_history_events': 7, 'prior_v4_cross_status': 'UNKNOWN', 'prior_v4_never_entered_solve_slots': 2, 'scientific_execution_during_packaging_or_integration': False, 'portable_execution_adapter_supplied': False, 'relocated_scientific_replay': False, 'fresh_host_validation': False, 'historical_GUI_cause_resolved': False, 'external_publication_asserted': False}
DIAGNOSTIC_STATUS_INTERPRETATION = 'Pending/unadopted labels inside the frozen AF archive describe its freeze-time state. This outer record records subsequent root candidate adoption only; it does not assert publication or scientific replay.'
DIAGNOSTIC_ARCHIVE_RECORD = {'id': 'AF-R7-SAME-SOLVER-DIAGNOSTIC', 'path': 'results/archives/same-solver-diagnostic-20261026-v1.zip', 'archive_prefix': 'r7_same_solver_diagnostic/', 'sibling_dependencies': [], 'bytes': 6109453, 'sha256': 'a63007acd7fc444cf245c015a6e1a7c8352729702c3fd60a6d6cc62cab16b951', 'package_manifest': {'member': 'r7_same_solver_diagnostic/MANIFEST.json', 'bytes': 80548, 'sha256': 'b735ea6ce441d908cafb650e6c09fded6dc966973199ff40f8301d503e721d8a'}, 'files_including_manifest': 334, 'uncompressed_bytes': 34890550}
DIAGNOSTIC_HANDOFF_PIN = {'bytes': 27644, 'sha256': '48acd641397d3f28e52665d1d2e10ddc4b236d4beeac85b84a0ba61e2a8b2be8'}
DIAGNOSTIC_INDEPENDENT_PRIVACY_PIN = {'bytes': 15858, 'sha256': 'b33171534b44e2899433eae230cc9fa9b15f3aa376f85d1c7507914aec36d5ef'}
DIAGNOSTIC_REQUIRED_QA_REPORT_PIN = {'bytes': 11682, 'sha256': 'd2bd9af73bfa46e6efd4f7e2b958ac6b638ae826ac6d7249332dfad2e6537a96'}
DIAGNOSTIC_SCIENTIFIC_ADOPTION_PINS = [{'bytes': 14018, 'sha256': '05d09f697e8b74fc2f54369a9ee56c8e0ee8cb2c0814385cede43a4fc6351a84'}, {'bytes': 1600, 'sha256': '276b812323c4e7983031ff01c48b5b60ffdf0d4c7f51fc21088a4225aa33602d'}]
R8_PRIOR_ROOT_IDS = ['Core', 'Verification', 'Lift', 'LiftCausal', 'LiftRegeneration', 'NormalizedEleven', 'ResidualCensus', 'NoninitialHandoff', 'IntruderBounded', 'IntruderCertificate', 'FiniteStudies', 'PendingNativeHandoff', 'PendingDiagnostic', 'Continuation', 'Vehicle188Native', 'Vehicle188Whole', 'FixedSevenNative', 'AA-COMPILED44', 'AC-OBSTACLE8CERT98', 'Z-HISTORICAL-PATROL', 'AD-PUBLIC-KIND-GUI', 'AE-R6-POSITIVE-CONTROLS']
R8_PRIOR_ROW_IDS = ['C59', 'C14', 'R11', 'GUARD-CONSTRUCTED', 'LIFT-T-SELECTED-POLICY', 'V188-P1', 'V188-P2', 'V188-P3', 'LIFT-P-DIRECT', 'LIFT-T-CAUSAL', 'SIX-DORMANT-CONTROLS', 'LIFT-MODELED-ADAPTATION', 'LIFT-PUBLIC-NATIVE-REGENERATION', 'LIFT-NODE680-STRICT-STATE-CERTIFICATE', 'NORMALIZED-ELEVEN-ORIGINAL-INITIALIZER', 'RESIDUAL-ELEVATOR-11-STATE-CENSUS', 'LIFT-NONINITIAL-HANDOFF-10-BOUNDARY-CENSUS', 'INTRUDER-BOUNDED-UNKNOWN-ORIGINAL-SOURCE', 'INTRUDER-SAVED-SOURCE-CERTIFICATES', 'FINITE-REQUEST-PROTOCOL-SIX-CELLS', 'HUMANOID-EIGHT-ARM-GUARD-CENSUS', 'GUARD-SAVED-ARENA-CAUSAL-AUDIT', 'pending-native-handoff-all-three-obligations', 'pending-diagnostic-patrol-saved-audit', 'pending-diagnostic-extended-lift-continuation', 'continuation-evidence-current-entrypoint', 'vehicle188-native-strict-selected-state', 'vehicle188-whole-region', 'fixed-seven-native', 'AA-COMPILED44', 'AC-OBSTACLE8CERT98', 'Z-HISTORICAL-PATROL', 'AD-PUBLIC-KIND-GUI', 'AE-R6-POSITIVE-CONTROLS']
R8_PRIOR_SOURCE_PATHS = ['tool/src/vehicle188/independent_core.py', 'tool/src/vehicle188/producer_core.py', 'tool/src/vehicle188/replay.py', 'tool/src/fixed-seven/independent_auditor.py', 'tool/src/fixed-seven/replay.py', 'tool/src/continuation/lasso/replay/code/independent_core.py', 'tool/src/continuation/lasso/replay/code/source_contracts.py', 'tool/src/continuation/lasso/replay/replay_lasso.py', 'tool/src/continuation/records/guard/check_guard_saved_arena.py', 'tool/src/continuation/replay/manager_semantics.py', 'tool/src/continuation/replay/reduced_semantics.py', 'tool/src/continuation/replay/replay.py', 'tool/src/graph-admission/initial_graph_checker.py', 'tool/src/graph-admission/vendor/bdd_core.py', 'tool/src/graph-admission/vendor/graph_fairness.py', 'tool/src/compiled-cohort/audit_core.py', 'tool/src/obstacle/check_saved.py', 'tool/src/obstacle-positive/check_certificate.py', 'tool/src/obstacle-positive/qualify_rejections.py']
R8_PRIOR_FINGERPRINTS = {'evidence_rows': '900189a51c3bcc80d249dfa0526f2d799ac45ccfabaf30276e9f47e89b73d747', 'archive_roots': 'cc4a54d9c66eef7344bfac7af669fa6deaf59aa882e8b26c707968445c292ca8', 'source_rows': 'c4a8b410f56d6ad84c5cb6cd125019537b676a3426176f9a9679e50b60b1baf3'}
DIAGNOSTIC_ROW_SHA = 'e643893d460811fc51ab562156c141334c5df5c97764ee03052d7ebee92e376d'
DIAGNOSTIC_SOURCES_SHA = '86fb933010400ab6b17a75a4cf67978abde119402480518a53eca1074237a3f0'
DIAGNOSTIC_RECORD_ASSERTIONS = {'history_event_summaries': [{'event_id': 'rev3_gate_unchanged', 'disposition': 'COMPLETE', 'model_builds': 1, 'raw_solver_calls': 0}, {'event_id': 'v4_gate_unchanged', 'disposition': 'COMPLETE', 'model_builds': 1, 'raw_solver_calls': 0}, {'event_id': 'v4_gate_S01_release', 'disposition': 'COMPLETE', 'model_builds': 1, 'raw_solver_calls': 0}, {'event_id': 'v4_cross_arm_gate', 'disposition': 'UNKNOWN', 'model_builds': 0, 'raw_solver_calls': 0}, {'event_id': 'v5_cross_arm_gate_revalidation', 'disposition': 'COMPLETE', 'model_builds': 0, 'raw_solver_calls': 0, 'realizable': None}, {'event_id': 'v5_solve_unchanged', 'disposition': 'COMPLETE', 'model_builds': 1, 'raw_solver_calls': 1, 'realizable': False}, {'event_id': 'v5_solve_S01_release', 'disposition': 'UNKNOWN', 'model_builds': 1, 'raw_solver_calls': 1, 'realizable': None}], 'history_event_fields': ['event_id', 'disposition', 'model_builds', 'raw_solver_calls', 'realizable'], 'record_fields': [{'member': 'records/HISTORY.json', 'keys': ['scientific_result'], 'expected': {'unchanged': {'outcome': False, 'outcome_type': 'JSON Boolean from exact released raw four-fixed-point solver', 'call_returned': True, 'capture_complete': True}, 'S01_release': {'outcome': 'UNKNOWN', 'Boolean_present': False, 'call_returned': False, 'capture_complete': False, 'immediate_observed_failure': 'RAW_STDOUT_CAP during ONE_RAW_FOUR_FP_CALL_BEGIN', 'unreturned_Boolean_inferred': False}}}, {'member': 'records/HISTORY.json', 'keys': ['budget'], 'expected': {'historical_models_before_solves': 3, 'new_models': 2, 'total_models': 5, 'model_limit': 5, 'raw_calls_entered': 2, 'raw_call_limit': 2, 'raw_calls_returned': 1, 'remaining_model_budget': 0, 'remaining_raw_call_budget': 0, 'retries_authorized': 0, 'cap_increase_authorized': False}}, {'member': 'records/HISTORY.json', 'keys': ['allowed_statement'], 'expected': 'With the same pinned released raw four-fixed-point solver at exact query B, the unchanged arm completed and returned false. The sole typed-S01-release arm entered the call but stopped at the predeclared raw-stdout capture cap before returning a Boolean and remains UNKNOWN. The intervention effect is unresolved.'}, {'member': 'records/HISTORY.json', 'keys': ['interpretation_limits'], 'expected': ['Private headless NoIDE exact-B run, not a recovered historical live GUI game or dispatch identity.', 'No completed two-Boolean comparison, no false/true or false/false substitution.', 'No effect magnitude, global raw-region identity with W_F/K_all/K_lp, solver-only cause, corrected-class pipeline success or extracted strategy correctness.', 'S01 PROCESS_FINISHED/teardown and supervisor pipe capture_complete do not imply solver return or complete native raw stdout.', 'Raw-call budget counts entered calls; winning_region_computations=1 is not completion evidence for S01.', 'No time/memory infeasibility conclusion from a diagnostic raw-output cap.']}, {'member': 'records/HISTORY.json', 'keys': ['v4_unrun_solves'], 'expected': {'status': 'NOT_RUN_AFTER_ORIGINAL_V4_CROSS_UNKNOWN', 'stages': ['solve_unchanged', 'solve_S01_release']}}, {'member': 'records/HISTORY.json', 'keys': ['public_package_adopted'], 'expected': False}, {'member': 'records/history/v4/UNRUN_SOLVES.json', 'keys': [], 'expected': {'status': 'NOT_RUN_AFTER_ORIGINAL_V4_CROSS_UNKNOWN', 'stages': ['solve_unchanged', 'solve_S01_release']}}, {'member': 'records/CAPTURE_INTEGRITY.json', 'keys': [], 'expected': {'schema': 'diagnostic-capture-byte-integrity-v1', 'decoding_is_not_scientific_replay': True, 'captures': [{'encoded': {'bytes': 4165, 'sha256': 'ebb73e7ae590267c8a03de2bd8306af8c4dab1894161e89e508c2bc3346de4bf'}, 'raw_bytes': 10957189, 'raw_sha256': 'a894abf570a62eff62622d0eed637827b0896aadee7ad97d3f7f1badfab5d495', 'record_count': 77, 'terminal_record': {'kind': 'end', 'raw_bytes': 10957189, 'repeated_lines': 202888}, 'privacy_scan': 'all decoded byte chunks and dictionaries inspected; no private identity tokens found', 'member': 'r7_same_solver_diagnostic/records/objects/sha256/ebb73e7ae590267c8a03de2bd8306af8c4dab1894161e89e508c2bc3346de4bf.txt', 'original': {'bytes': 4165, 'sha256': 'ebb73e7ae590267c8a03de2bd8306af8c4dab1894161e89e508c2bc3346de4bf'}}, {'encoded': {'bytes': 4165, 'sha256': '15f8253ef52d29b2f761b9edb48b60a23ff70bb5dd88bccee36b47d6979d0b39'}, 'raw_bytes': 16181635, 'raw_sha256': '5f11fe666f588ce1ee99536190dd26c6769e7850b0fd4f488d5c5877c84667cb', 'record_count': 77, 'terminal_record': {'kind': 'end', 'raw_bytes': 16181635, 'repeated_lines': 299637}, 'privacy_scan': 'all decoded byte chunks and dictionaries inspected; no private identity tokens found', 'member': 'r7_same_solver_diagnostic/records/objects/sha256/15f8253ef52d29b2f761b9edb48b60a23ff70bb5dd88bccee36b47d6979d0b39.txt', 'original': {'bytes': 4165, 'sha256': '15f8253ef52d29b2f761b9edb48b60a23ff70bb5dd88bccee36b47d6979d0b39'}}, {'encoded': {'bytes': 4165, 'sha256': 'ebb73e7ae590267c8a03de2bd8306af8c4dab1894161e89e508c2bc3346de4bf'}, 'raw_bytes': 10957189, 'raw_sha256': 'a894abf570a62eff62622d0eed637827b0896aadee7ad97d3f7f1badfab5d495', 'record_count': 77, 'terminal_record': {'kind': 'end', 'raw_bytes': 10957189, 'repeated_lines': 202888}, 'privacy_scan': 'all decoded byte chunks and dictionaries inspected; no private identity tokens found', 'member': 'r7_same_solver_diagnostic/records/objects/sha256/ebb73e7ae590267c8a03de2bd8306af8c4dab1894161e89e508c2bc3346de4bf.txt', 'original': {'bytes': 4165, 'sha256': 'ebb73e7ae590267c8a03de2bd8306af8c4dab1894161e89e508c2bc3346de4bf'}}, {'encoded': {'bytes': 4219, 'sha256': '71f5e374f4c5ad2fa5a6be8da8015be16fffff63abe9151ef3b010ef3f749c7e'}, 'raw_bytes': 62483773, 'raw_sha256': 'c2c67f96ced727d211f90d69dec3b74a3ef5b60f3fb6b06ee44d4c6b1e193f17', 'record_count': 78, 'terminal_record': {'kind': 'end', 'raw_bytes': 62483773, 'repeated_lines': 1157084}, 'privacy_scan': 'all decoded byte chunks and dictionaries inspected; no private identity tokens found', 'member': 'r7_same_solver_diagnostic/records/objects/sha256/71f5e374f4c5ad2fa5a6be8da8015be16fffff63abe9151ef3b010ef3f749c7e.txt', 'original': {'bytes': 4219, 'sha256': '71f5e374f4c5ad2fa5a6be8da8015be16fffff63abe9151ef3b010ef3f749c7e'}, 'stage': 'solve_unchanged', 'native_capture_complete': True, 'scope': 'entire completed capture', 'raw_cap_bytes': 67108864, 'capture_error': None}, {'encoded': {'bytes': 4220, 'sha256': '8dc0c851457b5a5767ad29a9c8cde0e649383fb8e2f801e5c7e93cfad1c662c8'}, 'raw_bytes': 67108819, 'raw_sha256': '2b27620bcbfc9c9d3a4dd6830ad74cb0c21defe34a4d8104b7008cbc24b455c4', 'record_count': 78, 'terminal_record': {'kind': 'end', 'raw_bytes': 67108819, 'repeated_lines': 1242733}, 'privacy_scan': 'all decoded byte chunks and dictionaries inspected; no private identity tokens found', 'member': 'r7_same_solver_diagnostic/records/objects/sha256/8dc0c851457b5a5767ad29a9c8cde0e649383fb8e2f801e5c7e93cfad1c662c8.txt', 'original': {'bytes': 4220, 'sha256': '8dc0c851457b5a5767ad29a9c8cde0e649383fb8e2f801e5c7e93cfad1c662c8'}, 'stage': 'solve_S01_release', 'native_capture_complete': False, 'scope': 'all recorded prefix bytes only; full call output incomplete', 'raw_cap_bytes': 67108864, 'capture_error': 'RAW_STDOUT_CAP'}]}}, {'member': 'records/v5/v5_solve_unchanged.json', 'keys': ['event_id'], 'expected': 'v5_solve_unchanged'}, {'member': 'records/v5/v5_solve_unchanged.json', 'keys': ['disposition'], 'expected': 'COMPLETE'}, {'member': 'records/v5/v5_solve_unchanged.json', 'keys': ['model_builds'], 'expected': 1}, {'member': 'records/v5/v5_solve_unchanged.json', 'keys': ['raw_solver_calls'], 'expected': 1}, {'member': 'records/v5/v5_solve_unchanged.json', 'keys': ['realizable'], 'expected': False}, {'member': 'records/v5/v5_solve_S01_release.json', 'keys': ['event_id'], 'expected': 'v5_solve_S01_release'}, {'member': 'records/v5/v5_solve_S01_release.json', 'keys': ['disposition'], 'expected': 'UNKNOWN'}, {'member': 'records/v5/v5_solve_S01_release.json', 'keys': ['model_builds'], 'expected': 1}, {'member': 'records/v5/v5_solve_S01_release.json', 'keys': ['raw_solver_calls'], 'expected': 1}, {'member': 'records/v5/v5_solve_S01_release.json', 'keys': ['realizable'], 'expected': None}, {'member': 'records/v5/v5_cross_arm_gate_revalidation.json', 'keys': ['event_id'], 'expected': 'v5_cross_arm_gate_revalidation'}, {'member': 'records/v5/v5_cross_arm_gate_revalidation.json', 'keys': ['disposition'], 'expected': 'COMPLETE'}, {'member': 'records/v5/v5_cross_arm_gate_revalidation.json', 'keys': ['model_builds'], 'expected': 0}, {'member': 'records/v5/v5_cross_arm_gate_revalidation.json', 'keys': ['raw_solver_calls'], 'expected': 0}, {'member': 'records/v5/v5_cross_arm_gate_revalidation.json', 'keys': ['realizable'], 'expected': None}]}
V71_ARCHIVES['AF-R7-SAME-SOLVER-DIAGNOSTIC'] = {'archive': 'same-solver-diagnostic-20261026-v1.zip', 'prefix': 'r7_same_solver_diagnostic/', 'siblings': [], 'counts': {'executed_history_events': 7, 'old_v4_never_entered_solve_slots': 2, 'total_models': 5, 'raw_calls_entered': 2, 'raw_calls_returned': 1, 'unchanged_false': 1, 'S01_UNKNOWN': 1, 'packaging_science_executions': 0, 'portable_execution_adapters': 0}}

# Candidate additions to reproduce/verify.py. Standard library only; no scientific import.
# Expected legacy fingerprints and archive constants are injected by build_validator.py.

V71_LIMITS = {'members': 10000, 'member_bytes': 64 * 1024 * 1024,
              'total_bytes': 512 * 1024 * 1024, 'zip_bytes': 128 * 1024 * 1024}
V71_PATH_LISTS = ('input_models', 'source_inputs', 'saved_graphs', 'input_navigation',
                  'saved_outputs', 'checker_sources')


def canonical_json_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                    separators=(',', ':')).encode('utf-8')).hexdigest()


def strict_json_bytes(data):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate JSON object key: ' + key)
            result[key] = value
        return result
    return json.loads(data.decode('utf-8'), object_pairs_hook=unique_pairs)


def v71_relative(value):
    require(isinstance(value, str) and value, 'Empty V71 member path')
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix() == value and
            '..' not in path.parts and '\\' not in value and ':' not in value and
            all(ord(c) >= 32 for c in value), 'Unsafe V71 member path: ' + value)
    return value


def v71_pin(row):
    require(isinstance(row.get('bytes'), int) and not isinstance(row['bytes'], bool)
            and row['bytes'] >= 0, 'Invalid V71 byte count')
    require(isinstance(row.get('sha256'), str) and
            re.fullmatch('[0-9a-f]{64}', row['sha256']), 'Missing/invalid V71 SHA-256')



# AG exact records; inherited constants retain their historical values.
COMPLETED_PAIR_ARCHIVE_RECORD = {'id': 'AG-R9-COMPLETED-SAME-OBSERVER-PAIR', 'path': 'results/archives/r9-completed-same-observer-pair-20261026-v1.zip', 'archive_prefix': 'r9_completed_pair/', 'sibling_dependencies': [], 'bytes': 10966131, 'sha256': 'b548e45835d5e52be6c0f68b60b3ada4cd016afa6d8ca448348d768d68445603', 'package_manifest': {'member': 'r9_completed_pair/MANIFEST.json', 'bytes': 261043, 'sha256': 'b2b7834bc66408b3c510be49972dc9d68d6141bad958024b96327be1770d293d'}, 'files_including_manifest': 880, 'uncompressed_bytes': 81436342}
COMPLETED_PAIR_HANDOFF_PIN = {'bytes': 16525, 'sha256': '8bdf55e3e1e480d2d86fd927de3dfea99c0d8dca4fdcbcc330bd09ac3d7f2aaf'}
COMPLETED_PAIR_SCIENCE_PIN = {'bytes': 13667, 'sha256': 'a9a938c5a86ad285535a8a35faa5b981ec6a8ec9c9a205b97e1d4ed2d8ab0cb0'}
COMPLETED_PAIR_INDEPENDENT_QA_PINS = [{'bytes': 10060, 'sha256': 'ed5b5f0c52df7210adc6497f75ec623ae81b8e095d0d2cae89db184b1ccf0f3f'}, {'bytes': 6503, 'sha256': 'a346c1bf2154fa8e761097fadad7c37f4d542e839fa7a52f0479f5b561fedd10'}, {'bytes': 4625, 'sha256': '343a66a37051bcacd2509e54a2192b88370d8f77c5f69ece796cfd6da0c312d6'}, {'bytes': 4395, 'sha256': 'a4bcdd16905398b4e100e92fb4fd241463b939d232569dcd534b2523816c9eba'}, {'bytes': 2258, 'sha256': '0cdc02becc32fea43a1e0c6319cffcb3e886512d9d7fac322252539ab3164b55'}]
COMPLETED_PAIR_INPUT_DESCRIPTOR_PIN = {'bytes': 6168, 'sha256': '1e07802f90e0a2db2558429dd41be7d7a42f8f7453eef40a24f4216ef695004c'}
COMPLETED_PAIR_FREEZE_UTC = '2026-10-26T00:19:55.097633+00:00'
COMPLETED_PAIR_HISTORY = {'old_completed_models': 5, 'new_model_attempts': 2, 'new_completed_models': 2, 'total_model_attempts': 7, 'old_entered_calls': 2, 'new_entered_calls': 2, 'total_entered_calls': 4, 'old_returned_calls': 1, 'new_returned_calls': 2, 'total_returned_calls': 3, 'remaining_attempts': 0, 'remaining_call_slots': 0, 'retries': 0}
COMPLETED_PAIR_NOT_ESTABLISHED = ['exclusive cause or identity of historical live GUI negatives', 'global raw-region / strict / Kind equivalence', 'correctness of the complete corrected public pipeline or strategy extraction / transfer', 'operational gate benefit, controller installation, incidence or performance advantage']
COMPLETED_PAIR_PUBLIC_SCOPE = {'adoption_kind': 'exact_AG_completed_pair_public_package_candidate', 'unchanged_outcome': False, 'S01_outcome': True, 'both_call_returns_present': True, 'both_captures_complete': True, 'same_observer_within_new_pair': True, 'local_exact_B_intervention_only': True, 'cumulative_models': 7, 'cumulative_entered_calls': 4, 'cumulative_returned_calls': 3, 'remaining_model_attempts': 0, 'remaining_raw_call_slots': 0, 'full_raw_integrity_inherited_from_prior_root_QA': True, 'raw_SHA256_recomputed_during_public_integrity': False, 'historical_GUI_identity_or_exclusive_cause_established': False, 'full_corrected_pipeline_or_strategy_transfer_established': False, 'relocated_replay_or_fresh_host_validation': False, 'scientific_execution_during_packaging_or_integration': False, 'external_publication_asserted': False}
COMPLETED_PAIR_STATUS_INTERPRETATION = 'Frozen pending labels describe the AG package freeze. This outer record records subsequent root candidate/privacy-input adoption only; it grants no scientific execution, replay or external publication.'
COMPLETED_PAIR_PUBLIC_ADOPTION_PATH = 'results/COMPLETED_PAIR_PUBLICATION_ADOPTION.json'
COMPLETED_PAIR_HISTORICAL_TAGS_SHA = 'fb78163c3d71a7f92931c5c9f1af380abd1ec90acf92ee6a16060e565f6fc230'
R9_PRIOR_SOURCE_PATHS = ['tool/src/vehicle188/independent_core.py', 'tool/src/vehicle188/producer_core.py', 'tool/src/vehicle188/replay.py', 'tool/src/fixed-seven/independent_auditor.py', 'tool/src/fixed-seven/replay.py', 'tool/src/continuation/lasso/replay/code/independent_core.py', 'tool/src/continuation/lasso/replay/code/source_contracts.py', 'tool/src/continuation/lasso/replay/replay_lasso.py', 'tool/src/continuation/records/guard/check_guard_saved_arena.py', 'tool/src/continuation/replay/manager_semantics.py', 'tool/src/continuation/replay/reduced_semantics.py', 'tool/src/continuation/replay/replay.py', 'tool/src/graph-admission/initial_graph_checker.py', 'tool/src/graph-admission/vendor/bdd_core.py', 'tool/src/graph-admission/vendor/graph_fairness.py', 'tool/src/compiled-cohort/audit_core.py', 'tool/src/obstacle/check_saved.py', 'tool/src/obstacle-positive/check_certificate.py', 'tool/src/obstacle-positive/qualify_rejections.py', 'tool/src/same-solver-diagnostic/cross_arm_gate.py', 'tool/src/same-solver-diagnostic/java/ExactBSameSolverDiagnostic.java', 'tool/src/same-solver-diagnostic/java/BoundedDiagnosticPrintStream.java']
R9_PRIOR_FINGERPRINTS = {'evidence_rows': '966dd008ffc341c3ae75a87a7a9611b7d51076aadfacfddcfca2220a6e384490', 'archive_roots': '170d239b3d6f57aedb63ddc73dcc9af210fee02d779d93894960a92f98cd1e8c', 'source_rows': 'c92dd5e9c0effd01c2d344064b2556490b9fc7412cd688fb3fc83570a30fd34e'}
COMPLETED_PAIR_ROW_SHA = 'a8223bbdc472b80d13b4dbfc0a478357a20008ed60c480b89c406bc606420ea8'
COMPLETED_PAIR_SOURCES_SHA = 'f7adebbe0eb9a3836757ff3238e4748f42ce87557ff4db721220b525d433d887'
V71_ARCHIVES['AG-R9-COMPLETED-SAME-OBSERVER-PAIR'] = {'archive': 'r9-completed-same-observer-pair-20261026-v1.zip', 'prefix': 'r9_completed_pair/', 'siblings': [], 'counts': {'new_models': 2, 'new_raw_calls_entered': 2, 'new_raw_calls_returned': 2, 'unchanged_false': 1, 'S01_true': 1, 'complete_captures': 2, 'cumulative_models': 7, 'cumulative_entered_calls': 4, 'cumulative_returned_calls': 3, 'remaining_model_slots': 0, 'remaining_raw_call_slots': 0, 'integration_scientific_executions': 0, 'integration_raw_expansion_bytes': 0}}


AG_DICT = b"lookup, class net.sf.javabdd.JTLVJavaFactory$BddCache\n"

def ag_pairs(values):
    out = {}
    for key, value in values:
        require(key not in out, 'duplicate JSON key')
        out[key] = value
    return out

def ag_parse(data):
    return json.loads(data, object_pairs_hook=ag_pairs,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))

def ag_integer(value):
    return type(value) is int and value >= 0

def ag_encoded_summary(data):
    require(len(data) <= 67108864, 'encoded limit')
    raw = repeats = literals = records = 0
    dictionary = end = False
    privacy_tail = b''
    for line in data.splitlines(keepends=True):
        require(len(line) <= 131072 and line.endswith(b'\n'), 'bounded complete line')
        row = ag_parse(line); records += 1
        require(not end and isinstance(row, dict), 'record after end or non-object')
        kind = row.get('kind')
        if kind == 'dictionary':
            require(records == 1 and not dictionary and set(row) == {'kind','id','data'}, 'dictionary order/schema')
            require(row['id'] == 'cache_lookup', 'dictionary id')
            decoded = base64.b64decode(row['data'], validate=True)
            require(decoded == AG_DICT, 'dictionary bytes')
            dictionary = True
        elif kind == 'bytes':
            require(dictionary and set(row) == {'kind','data'}, 'bytes schema')
            require(isinstance(row['data'], str) and len(row['data']) <= 87384, 'base64 bound')
            decoded = base64.b64decode(row['data'], validate=True)
            require(len(decoded) <= 65536 and base64.b64encode(decoded).decode() == row['data'], 'canonical literal')
            raw += len(decoded); literals += len(decoded)
        elif kind == 'repeat':
            require(dictionary and set(row) == {'kind','id','count'} and row['id'] == 'cache_lookup', 'repeat schema')
            require(ag_integer(row['count']) and 1 <= row['count'] <= 1000000, 'repeat bounds')
            raw += len(AG_DICT) * row['count']; repeats += row['count']
            decoded = AG_DICT  # inspect one fixed dictionary occurrence; no expansion
        elif kind == 'end':
            require(dictionary and set(row) == {'kind','raw_bytes','repeated_lines'}, 'end schema')
            require(ag_integer(row['raw_bytes']) and ag_integer(row['repeated_lines']), 'end integers')
            require(row['raw_bytes'] == raw and row['repeated_lines'] == repeats, 'end arithmetic')
            end = True; decoded = b''
        else:
            raise ValueError('unknown record kind')
        require(raw <= 68719476736, 'raw arithmetic limit')
        joined = privacy_tail + decoded
        require(all(x not in joined.lower() for x in (b'/users/', b'/home/', b'/private/var/folders/', b'file:/users/')), 'capture private path')
        privacy_tail = joined[-512:]
    require(dictionary and end, 'complete framing')
    return {'encoded_bytes': len(data), 'encoded_sha256': hashlib.sha256(data).hexdigest(),
            'full_raw_bytes': raw, 'repeated_lines': repeats, 'literal_bytes': literals,
            'records': records, 'raw_digest_recomputed': False}

def verify_v71_archive(root, row, plan):
    v71_pin(row)
    require(row['path'] == 'results/archives/' + plan['archive'], 'Wrong V71 archive path')
    require(row['archive_prefix'] == plan['prefix'], 'Wrong V71 archive prefix')
    require(row['sibling_dependencies'] == plan['siblings'], 'Wrong V71 sibling dependency declaration')
    require(row['bytes'] <= V71_LIMITS['zip_bytes'], 'V71 ZIP exceeds static size bound')
    archive_path = verify_record(root, row)
    prefix = row['archive_prefix']
    manifest_member = prefix + 'MANIFEST.json'
    manifest_pin = row['package_manifest']
    require(manifest_pin['member'] == manifest_member, 'Wrong V71 package manifest member')
    v71_pin(manifest_pin)
    require(manifest_pin['bytes'] <= V71_LIMITS['member_bytes'], 'Oversized V71 manifest')
    files = {}
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        require(0 < len(infos) <= V71_LIMITS['members'], 'V71 ZIP member count bound')
        require(len(infos) == len({i.filename for i in infos}), 'Duplicate V71 ZIP member')
        folded = set()
        total = 0
        for info in infos:
            name = info.filename.rstrip('/') if info.is_dir() else info.filename
            v71_relative(name)
            require(info.filename.startswith(prefix), 'V71 member outside fixed top directory')
            key = unicodedata.normalize('NFC', name).casefold()
            require(key not in folded, 'Cross-platform V71 ZIP name collision')
            folded.add(key)
            require(not stat.S_ISLNK(info.external_attr >> 16), 'Symlink in V71 ZIP')
            mode_type = stat.S_IFMT(info.external_attr >> 16)
            require(mode_type in (0, stat.S_IFREG, stat.S_IFDIR), 'Nonregular V71 ZIP member')
            require(not (info.flag_bits & 1), 'Encrypted V71 ZIP member')
            require(info.file_size <= V71_LIMITS['member_bytes'], 'Oversized V71 member')
            if info.is_dir():
                require(info.file_size == 0, 'Data in V71 directory member')
                continue
            require(mode_type != stat.S_IFDIR, 'V71 file marked as directory')
            relative = info.filename[len(prefix):]
            v71_relative(relative)
            total += info.file_size
            require(total <= V71_LIMITS['total_bytes'], 'V71 total uncompressed bound')
            files[relative] = info
        require('MANIFEST.json' in files, 'Missing V71 package manifest')
        raw_manifest = archive.read(files['MANIFEST.json'])
        require(len(raw_manifest) == manifest_pin['bytes'] and
                hashlib.sha256(raw_manifest).hexdigest() == manifest_pin['sha256'],
                'V71 package manifest pin differs')
        package = strict_json_bytes(raw_manifest)
        rows = package['files']
        if row['id'] == DIAGNOSTIC_ARCHIVE_RECORD['id']:
            require(package['schema'] == 'diagnostic-public-manifest-v1' and
                    package['evidence_id'] == row['id'] and package['archive_root'] == prefix and
                    package['manifest_self_excluded'] is True, 'AF inner manifest schema/root differs')
            require(isinstance(rows,list) and all(isinstance(r,dict) and set(r) == {'member','bytes','sha256'}
                    and isinstance(r['member'],str) and r['member'].startswith(prefix) for r in rows),
                    'AF exact member-based inventory differs')
            rows = [{'path':r['member'][len(prefix):], 'bytes':r['bytes'], 'sha256':r['sha256']} for r in rows]
        if row['id'] == COMPLETED_PAIR_ARCHIVE_RECORD['id']:
            require(package['schema'] == 'ag-r9-public-manifest-v1' and package['evidence_id'] == row['id']
                    and package['excluded'] == ['MANIFEST.json'], 'AG inner manifest identity differs')
        require(isinstance(rows, list), 'V71 package files must be a list')
        paths = [r['path'] for r in rows]
        require(len(paths) == len(set(paths)) and 'MANIFEST.json' not in paths,
                'V71 package duplicate or self-hashed manifest')
        require(set(paths) | {'MANIFEST.json'} == set(files), 'V71 package member roster differs')
        for member in rows:
            relative = v71_relative(member['path'])
            v71_pin(member)
            info = files[relative]
            require(info.file_size == member['bytes'], 'V71 inner member size differs: ' + relative)
            digest = hashlib.sha256()
            with archive.open(info) as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(chunk)
            require(digest.hexdigest() == member['sha256'], 'V71 inner member SHA differs: ' + relative)
        require(row['files_including_manifest'] == len(files), 'V71 file count differs')
        require(row['uncompressed_bytes'] == total, 'V71 uncompressed byte count differs')
        if 'file_count' in package:
            require(package['file_count'] == len(rows), 'V71 package declared count differs')
        if 'bytes_total' in package:
            require(package['bytes_total'] == total - len(raw_manifest), 'V71 package declared bytes differ')
    public_pins = {r['path']: {k:r[k] for k in ('bytes', 'sha256')} for r in rows}
    public_pins['MANIFEST.json'] = {k:manifest_pin[k] for k in ('bytes', 'sha256')}
    return public_pins, total


def verify_v71_extensions(root, manifest, file_paths):
    require(manifest['paper_version'] == 'v71-r10', 'Final v71-r10 paper is required')
    release_tag = manifest['release_tag']
    require(isinstance(release_tag, str) and re.fullmatch('[a-z0-9-]+', release_tag)
            and release_tag != 'reader-layout-20261024-v1' and 'pending' not in release_tag,
            'New fixed release tag must be selected before integration')
    rows = manifest['archive_additions']
    require(isinstance(rows, list) and len(rows) == 7, 'Exactly seven V71 added archives required')
    by_id = {r['id']: r for r in rows}
    require(len(by_id) == 7 and set(by_id) == set(V71_ARCHIVES), 'V71 archive ID roster differs')
    require(canonical_json_sha([r for r in rows if r['id'] in R6_PRIOR_ARCHIVE_IDS]) ==
            R6_PRIOR_FINGERPRINTS['archive_addition_rows'], 'Adopted r5 archive records changed')
    require(by_id[R6_ARCHIVE_ID] == R6_ARCHIVE_RECORD, 'Fixed r6 archive record changed')
    require(by_id[DIAGNOSTIC_ARCHIVE_RECORD['id']] == DIAGNOSTIC_ARCHIVE_RECORD, 'Fixed AF archive differs')
    require(by_id[COMPLETED_PAIR_ARCHIVE_RECORD['id']] == COMPLETED_PAIR_ARCHIVE_RECORD, 'Fixed AG archive differs')
    current_rows = {r['path']: r for r in manifest['files']}
    members = {}
    total = 0
    for key, plan in V71_ARCHIVES.items():
        row = by_id[key]
        require(row['path'] in current_rows, 'Added archive absent from distribution manifest')
        require({k: row[k] for k in ('bytes', 'sha256')} ==
                {k: current_rows[row['path']][k] for k in ('bytes', 'sha256')},
                'Added archive has conflicting manifest identities')
        members[key], count = verify_v71_archive(root, row, plan)
        total += count
    wanted = {'results/archives/' + name for name in BASELINE_ARCHIVES} | {r['path'] for r in rows}
    actual = {p for p in file_paths if p.startswith('results/archives/') and p.lower().endswith('.zip')}
    require(actual == wanted, 'Scientific archive ZIP roster must be preserved 17 plus added 7')

    index = strict_json_bytes((root / 'results/EVIDENCE_INDEX.json').read_bytes())
    require(index['schema'] == 'seams2027-evidence-index-v1', 'Evidence index schema differs')
    roots = index['archive_roots']
    require(set(roots) == set(V71_LEGACY_ROOT_IDS) | set(V71_ARCHIVES), 'Evidence archive-root roster differs')
    old_roots = {k: roots[k] for k in V71_LEGACY_ROOT_IDS}
    require(canonical_json_sha(old_roots) == V71_LEGACY_ROOTS_SHA, 'Historical archive-root records changed')
    require(canonical_json_sha(index['source_fetch_required_for_members']) == V71_LEGACY_FETCH_SHA,
            'Historical source-fetch roster changed')
    evidence_rows = index['rows']
    ids = [r['id'] for r in evidence_rows]
    require(len(ids) == len(set(ids)), 'Duplicate evidence row ID')
    old_rows = [r for r in evidence_rows if r['id'] in V71_LEGACY_ROW_IDS]
    require(canonical_json_sha(old_rows) == V71_LEGACY_ROWS_SHA, 'Historical evidence rows changed')
    require(set(ids) == set(V71_LEGACY_ROW_IDS) | set(V71_ARCHIVES), 'Evidence row roster differs')
    require(index['scientific_archive_count'] == 24 and index['reader_row_count'] == len(ids) == 36,
            'Evidence index count differs')
    require(canonical_json_sha({k: roots[k] for k in R6_PRIOR_ROOT_IDS}) ==
            R6_PRIOR_FINGERPRINTS['archive_roots'], 'Adopted r5 archive-root records changed')
    require(canonical_json_sha([r for r in evidence_rows if r['id'] in R6_PRIOR_ROW_IDS]) ==
            R6_PRIOR_FINGERPRINTS['evidence_rows'], 'Adopted r5 evidence rows changed')
    require(canonical_json_sha(next(r for r in evidence_rows if r['id'] == R6_ARCHIVE_ID)) ==
            R6_NEW_ROW_SHA, 'Fixed r6 evidence row changed')
    require(canonical_json_sha({k:roots[k] for k in R8_PRIOR_ROOT_IDS}) == R8_PRIOR_FINGERPRINTS['archive_roots'], 'Prior 22 archive roots changed')
    require(canonical_json_sha([r for r in evidence_rows if r['id'] in R8_PRIOR_ROW_IDS]) == R8_PRIOR_FINGERPRINTS['evidence_rows'], 'Prior 34 reader rows changed')
    require(canonical_json_sha(next(r for r in evidence_rows if r['id'] == DIAGNOSTIC_ARCHIVE_RECORD['id'])) == DIAGNOSTIC_ROW_SHA, 'AF reader row changed')
    require(canonical_json_sha([r for r in evidence_rows if r['id'] != COMPLETED_PAIR_ARCHIVE_RECORD['id']]) == R9_PRIOR_FINGERPRINTS['evidence_rows'], 'All prior35 evidence rows changed')
    require(canonical_json_sha({k:v for k,v in roots.items() if k != COMPLETED_PAIR_ARCHIVE_RECORD['id']}) == R9_PRIOR_FINGERPRINTS['archive_roots'], 'All prior23 archive roots changed')
    require(canonical_json_sha(next(r for r in evidence_rows if r['id'] == COMPLETED_PAIR_ARCHIVE_RECORD['id'])) == COMPLETED_PAIR_ROW_SHA, 'AG evidence row changed')
    checked_members = 0
    for row in evidence_rows:
        if row['id'] not in V71_ARCHIVES:
            continue
        key = row['id']; plan = V71_ARCHIVES[key]
        require(row['archive'] == key, 'New evidence row points to wrong archive')
        require(roots[key] == {'archive':plan['archive'], 'member_prefix':plan['prefix']},
                'New evidence archive-root binding differs')
        require(row['registered_counts'] == plan['counts'], 'New evidence denominators differ')
        require(row['sibling_dependencies'] == plan['siblings'], 'New evidence adjacency differs')
        require(row.get('reader_recipe') in members[key], 'Missing V71 reader recipe')
        require('integration_pending' not in row, 'Unfinished V71 evidence row')
        require(row.get('input_navigation'), 'V71 navigation must name exact members')
        require(row.get('saved_outputs'), 'V71 evidence must name its saved output members')
        for field in V71_PATH_LISTS:
            values = row.get(field, [])
            require(isinstance(values, list) and len(values) == len(set(values)),
                    'Invalid/duplicate V71 member list: ' + field)
            for value in values:
                v71_relative(value)
                require(value in members[key], 'Missing indexed V71 member: ' + key + '/' + value)
                checked_members += 1
    # Cross-package identities are verified against actual pinned package members,
    # not merely accepted as documentation strings inside AD.
    ad_row = by_id['AD-PUBLIC-KIND-GUI']
    with zipfile.ZipFile(root / ad_row['path']) as archive:
        dependency = strict_json_bytes(archive.read('ad_gui_kind_ab/DEPENDENCIES.json'))
        baselines = strict_json_bytes(archive.read('ad_gui_kind_ab/EXISTING_PACKAGE_BASELINES.json'))
    require(dependency['required_package'] == 'ac_obstacle8cert98', 'Wrong AD scientific sibling')
    require(dependency['AC_manifest']['path'] == '../ac_obstacle8cert98/MANIFEST.json',
            'Wrong AD AC manifest location')
    require({k:dependency['AC_manifest'][k] for k in ('bytes','sha256')} ==
            members['AC-OBSTACLE8CERT98']['MANIFEST.json'], 'AD AC manifest binding is stale')
    dependency_paths = [r['path'] for r in dependency['files']]
    require(len(dependency_paths) == len(set(dependency_paths)) and
            '../ac_obstacle8cert98/MANIFEST.json' in dependency_paths,
            'AD sibling dependency roster malformed')
    for item in dependency['files']:
        require(item['path'].startswith('../ac_obstacle8cert98/'), 'Unexpected AD dependency root')
        rel = v71_relative(item['path'][len('../ac_obstacle8cert98/'):])
        require(rel in members['AC-OBSTACLE8CERT98'] and
                {k:item[k] for k in ('bytes','sha256')} == members['AC-OBSTACLE8CERT98'][rel],
                'AD AC scientific dependency pin differs: ' + rel)
    expected_baselines = {'../'+V71_ARCHIVES[k]['prefix']+'MANIFEST.json':k
                          for k in ('AA-COMPILED44','AC-OBSTACLE8CERT98','Z-HISTORICAL-PATROL')}
    require(len(baselines['manifests']) == 3 and
            {r['path'] for r in baselines['manifests']} == set(expected_baselines),
            'AD assembly baseline manifest roster differs')
    for item in baselines['manifests']:
        require({k:item[k] for k in ('bytes','sha256')} ==
                members[expected_baselines[item['path']]]['MANIFEST.json'],
                'AD sibling assembly baseline manifest is stale')
    source_index = strict_json_bytes((root / 'tool/SOURCE_INDEX.json').read_bytes())
    old_sources = [r for r in source_index['files'] if r['path'] in V71_LEGACY_SOURCE_PATHS]
    require(canonical_json_sha(old_sources) == V71_LEGACY_SOURCES_SHA,
            'Historical code-browser ledger changed')
    all_sources = source_index['files']
    require(len(all_sources) == 26, 'Exact prior22 plus four AG source rows required')
    require(canonical_json_sha([r for r in all_sources if r['path'] in R6_PRIOR_SOURCE_PATHS]) ==
            R6_PRIOR_FINGERPRINTS['source_rows'], 'Adopted r5 code-browser rows changed')
    require(canonical_json_sha([r for r in all_sources if r['path'] in R8_PRIOR_SOURCE_PATHS and r['path'] not in R6_PRIOR_SOURCE_PATHS]) ==
            R6_NEW_SOURCES_SHA, 'Fixed r6 code-browser rows changed')
    require(canonical_json_sha([r for r in all_sources if r['path'] in R8_PRIOR_SOURCE_PATHS]) == R8_PRIOR_FINGERPRINTS['source_rows'], 'Prior 19 code rows changed')
    require(canonical_json_sha([r for r in all_sources if r['path'] in R9_PRIOR_SOURCE_PATHS and r['path'] not in R8_PRIOR_SOURCE_PATHS]) == DIAGNOSTIC_SOURCES_SHA, 'AF code rows changed')
    require(canonical_json_sha([r for r in all_sources if r['path'] in R9_PRIOR_SOURCE_PATHS]) == R9_PRIOR_FINGERPRINTS['source_rows'], 'All prior22 source rows changed')
    require(canonical_json_sha([r for r in all_sources if r['path'] not in R9_PRIOR_SOURCE_PATHS]) == COMPLETED_PAIR_SOURCES_SHA, 'AG source rows changed')
    completed_pair_report = verify_completed_pair_record_bindings(root)
    diagnostic_report = verify_diagnostic_record_bindings(root)
    r6_report = verify_r6_record_bindings(root, by_id, members)
    return {'added_archive_paths': {r['path'] for r in rows},
            'report': {'new_scientific_archives':7, 'total_scientific_archives':24,
                       'new_archive_files_verified':sum(len(x) for x in members.values()),
                       'new_archive_uncompressed_bytes_verified':total,
                       'new_indexed_members_verified':checked_members,
                       'AD_AC_dependency_files_verified':len(dependency_paths),
                       'AD_sibling_manifest_baselines_verified':3,
                       'historical_evidence_rows_unchanged':29,
                       'historical_code_copy_rows_unchanged':15,
                       'adopted_r5_evidence_rows_unchanged':33,
                       'adopted_r5_archive_roots_unchanged':21,
                       'adopted_r5_code_copy_rows_unchanged':17,
                       'adopted_r5_archive_addition_rows_unchanged':4,
                       **r6_report, **diagnostic_report, **completed_pair_report,
                       'evidence_index_scope':'All preceding35 reader rows,23 archive roots and22 source rows preserved; separate AF and AG records checked inside their exact ZIPs'}}



def verify_public_package_adoption(root):
    """Validate a dated candidate-adoption binding; never infer publication."""
    value = strict_json_bytes((root / PUBLIC_ADOPTION_PATH).read_bytes())
    require(set(value) == {'schema', 'status', 'adopted_utc', 'package_frozen_utc', 'archive',
            'package_manifest', 'replayed_v1_zip', 'root_adoption_record', 'root_review_evidence_pins',
            'scope', 'historic_status_interpretation'}, 'Outer adoption record fields differ')
    require(value['schema'] == 'v71-public-v2-package-adoption-binding-v1' and
            value['status'] == 'ROOT_ADOPTED_EXACT_PUBLIC_V2_PACKAGE_CANDIDATE', 'Outer adoption status differs')
    require(value['package_frozen_utc'] == PACKAGE_FREEZE_UTC and
            value['archive'] == {k: R6_ARCHIVE_RECORD[k] for k in ('path', 'bytes', 'sha256')} and
            value['package_manifest'] == R6_ARCHIVE_RECORD['package_manifest'] and
            value['replayed_v1_zip'] == REPLAYED_V1_ZIP and value['scope'] == PUBLIC_ADOPTION_SCOPE,
            'Outer adoption byte identities or scope differ')
    stamp = value['adopted_utc']
    require(isinstance(stamp, str) and stamp.endswith(('+00:00', 'Z')), 'Outer adoption must be UTC')
    when = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
    require(datetime.fromisoformat(PACKAGE_FREEZE_UTC) <= when <= datetime.now(timezone.utc),
            'Outer adoption must follow the freeze and not be future-dated')
    require(isinstance(value['root_review_evidence_pins'], list) and value['root_review_evidence_pins'],
            'Missing root review evidence pins')
    for item in [value['root_adoption_record']] + value['root_review_evidence_pins']:
        require(isinstance(item, dict) and set(item) == {'bytes', 'sha256'} and
                type(item['bytes']) is int and item['bytes'] > 0 and
                isinstance(item['sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', item['sha256']),
                'Malformed private root-record pin')
    require(value['historic_status_interpretation'] ==
            'Pending/unpublished candidate labels inside the frozen archive record its freeze-time state. This outer record records later root candidate adoption only.',
            'Historic freeze status interpretation differs')

def verify_r6_record_bindings(root, by_id, members):
    """Compare recorded metadata and prior copies; never run a scientific check."""
    row = by_id[R6_ARCHIVE_ID]
    prefix = row['archive_prefix']
    with zipfile.ZipFile(root / row['path']) as archive:
        def record(name):
            return strict_json_bytes(archive.read(prefix + name))
        disposition = record('SCIENTIFIC_DISPOSITION.json')
        counts = V71_ARCHIVES[R6_ARCHIVE_ID]['counts']
        c1 = disposition['C1']
        for field in ('A_states', 'A_policy_edges', 'B_states', 'B_policy_edges',
                      'typed_ENV_candidates_each', 'legal_ENV_edges',
                      'malformed_expected_rejections', 'qualification_positive_controls'):
            require(c1[field] == counts[field], 'R6 recorded count differs: ' + field)
        require(c1['all_D_states'] == counts['all_domain_states'] and
                c1['rank_maxima_both'] == [17, 17], 'R6 recorded domain/rank count differs')
        require(disposition['relocated_checker_replay_performed'] is True and
                disposition['packaging_science_runs'] == 0, 'R6 packaging execution scope differs')
        replay = disposition['relocated_replay']
        require(replay['status'] == 'ADOPTED_EXISTING_HOST_EXACT_PUBLIC_V1_INPUTS' and
                replay['current_v2_container_scientifically_replayed'] is False and
                replay['fresh_host_or_external_reproduction'] is False and
                replay['fully_hermetic_execution'] is False and
                replay['public_adoption'] == 'PENDING_ROOT_REVIEW', 'Recorded v1/v2 replay scope differs')
        replay_binding = record('replay/INPUT_BINDINGS.json')['common_original_input_pins']
        require({k: replay_binding['public_candidate_zip'][k] for k in ('bytes', 'sha256')} ==
                REPLAYED_V1_ZIP, 'Recorded replay did not identify the exact v1 ZIP')
        replay_map = record('replay/QUALIFICATION_REPLAY_INPUT_MAP.json')
        require(len(replay_map['cases']) == 50 and len(replay_map['positive_controls']) == 2 and
                replay_map['direct_hash_receipts'] == 48 and replay_map['duplicate_key_null_hash_receipts'] == 2,
                'Recorded replay qualification identity counts differ')
        require(record('replay/records/ROOT_PUBLIC_REPLAY_ADOPTION.json')['status'] ==
                'ADOPT_SCOPED_SUCCESSFUL_EXISTING_HOST_PUBLIC_BYTES_REPLAY', 'Recorded v1 replay adoption differs')
        # This earlier map retains its original-check identity; later replay has a separate map.
        mapping = record('PUBLIC_QUALIFICATION_INPUT_MAP.json')
        require(mapping['original_direct_checker_input_hashes'] == 48 and
                mapping['duplicate_key_null_checker_hashes'] == 2 and
                mapping['public_derivative_science_replayed'] is False,
                'R6 rejection input identity distinction differs')
        prior = record('PRIOR_EVIDENCE_REFERENCES.json')
        refs = prior['references']
        expected_refs = {V71_ARCHIVES[k]['archive']: by_id[k]
                         for k in ('AC-OBSTACLE8CERT98', 'AD-PUBLIC-KIND-GUI')}
        require(len(refs) == 2 and {r['archive_name'] for r in refs} == set(expected_refs),
                'R6 prior archive reference roster differs')
        for ref in refs:
            require({k:ref[k] for k in ('bytes','sha256')} ==
                    {k:expected_refs[ref['archive_name']][k] for k in ('bytes','sha256')},
                    'R6 prior archive identity differs')
        copied_prior = 0
        for name, member_pin in members[R6_ARCHIVE_ID].items():
            if not name.startswith('prior_kind/'):
                continue
            prior_name = 'gui/' + name[len('prior_kind/'):]
            require(prior_name in members['AD-PUBLIC-KIND-GUI'] and
                    member_pin == members['AD-PUBLIC-KIND-GUI'][prior_name],
                    'R6 selected-Kind copy differs from prior AD member: ' + name)
            copied_prior += 1
        require(copied_prior == 11, 'R6 selected-Kind copy roster differs')
        for case in ('A', 'B'):
            ordinary = record('c2/' + case + '/RESULT.json')
            selected = record('prior_kind/' + case + '/RESULT.json')
            require(ordinary['actual_result'] is True and ordinary['public_action_count'] == 1 and
                    ordinary['mode'] == 'Original GR(1)', 'R6 ordinary-mode record differs')
            require(selected['boolean_answer'] is False and selected['scientific_action_count'] == 1,
                    'R6 prior selected-Kind record differs')
    verify_public_package_adoption(root)
    return {'public_v2_candidate_adoption_binding_checked': True,
            'r6_recorded_metadata_bindings_checked': True,
            'r6_prior_archive_references_verified': 2,
            'r6_prior_kind_member_copies_verified': copied_prior,
            'r6_scientific_replay_executed': False}


def verify_diagnostic_record_bindings(root):
    """Check frozen saved metadata only; do not execute any scientific code."""
    row = DIAGNOSTIC_ARCHIVE_RECORD
    with zipfile.ZipFile(root / row['path']) as archive:
        prefix = row['archive_prefix']
        def record(name):
            return strict_json_bytes(archive.read(prefix + name))
        history = record('records/HISTORY.json')
        require(history['evidence_id'] == row['id'], 'AF history evidence ID differs')
        expected = DIAGNOSTIC_RECORD_ASSERTIONS
        summaries = [{k: e[k] for k in expected['history_event_fields'] if k in e} for e in history['events']]
        require(canonical_json_sha(summaries) == canonical_json_sha(expected['history_event_summaries'])
                and len(summaries) == 7, 'AF seven-event history changed')
        for assertion in expected['record_fields']:
            value = record(assertion['member'])
            for key in assertion['keys']:
                value = value[key]
            require(canonical_json_sha(value) == canonical_json_sha(assertion['expected']),
                    'AF saved record value changed: ' + assertion['member'] + ' ' + repr(assertion['keys']))
        names = set(archive.namelist())
        for event in history['events']:
            require(event['public_record_members'] and all(n in names for n in event['public_record_members']),
                    'AF history record link absent')
    value = strict_json_bytes((root / DIAGNOSTIC_PUBLIC_ADOPTION_PATH).read_bytes())
    fields = {'schema', 'status', 'adopted_utc', 'package_frozen_utc', 'archive', 'package_manifest',
              'package_handoff_pin', 'scientific_adoption_pins', 'root_adoption_record',
              'root_review_evidence_pins', 'public_input_adoption_pin', 'public_input_descriptor_pin',
              'privacy_review_pin', 'public_input_review_evidence_pins', 'scope', 'historic_status_interpretation'}
    require(set(value) == fields and value['schema'] == 'v71-r8-diagnostic-package-adoption-binding-v1'
            and value['status'] == 'ROOT_ADOPTED_EXACT_AF_DIAGNOSTIC_PUBLIC_PACKAGE_CANDIDATE',
            'AF outer adoption fields/status differ')
    require(value['package_frozen_utc'] == DIAGNOSTIC_FREEZE_UTC
            and value['archive'] == {k:row[k] for k in ('path','bytes','sha256')}
            and value['package_manifest'] == row['package_manifest']
            and value['package_handoff_pin'] == DIAGNOSTIC_HANDOFF_PIN
            and value['scientific_adoption_pins'] == DIAGNOSTIC_SCIENTIFIC_ADOPTION_PINS
            and canonical_json_sha(value['scope']) == canonical_json_sha(DIAGNOSTIC_PUBLIC_SCOPE)
            and value['historic_status_interpretation'] == DIAGNOSTIC_STATUS_INTERPRETATION,
            'AF outer adoption identities/scope differ')
    stamp = value['adopted_utc']
    require(isinstance(stamp,str) and stamp.endswith(('+00:00','Z')), 'AF adoption timestamp must be UTC')
    when = datetime.fromisoformat(stamp.replace('Z','+00:00'))
    require(datetime.fromisoformat(DIAGNOSTIC_FREEZE_UTC) <= when <= datetime.now(timezone.utc),
            'AF adoption must follow frozen package and not be future-dated')
    for key in ('root_review_evidence_pins','public_input_review_evidence_pins'):
        require(isinstance(value[key],list) and value[key], 'AF actual review evidence pins missing')
    pins = [value[k] for k in ('root_adoption_record','public_input_adoption_pin','public_input_descriptor_pin','privacy_review_pin')]
    pins += value['root_review_evidence_pins'] + value['public_input_review_evidence_pins']
    for item in pins:
        require(isinstance(item,dict) and set(item) == {'bytes','sha256'} and type(item['bytes']) is int
                and item['bytes'] > 0 and isinstance(item['sha256'],str)
                and re.fullmatch(r'[0-9a-f]{64}',item['sha256']), 'AF private record must expose only valid byte pins')
    require(value['privacy_review_pin'] in value['public_input_review_evidence_pins'],
            'AF independent privacy review pin absent from input review evidence')
    require(value['privacy_review_pin'] == DIAGNOSTIC_INDEPENDENT_PRIVACY_PIN and
            DIAGNOSTIC_REQUIRED_QA_REPORT_PIN in value['root_review_evidence_pins'],
            'AF exact errata01 independent review pins differ')
    guide = (root / 'results/guides/SAME_SOLVER_DIAGNOSTIC.md').read_text(encoding='utf-8')
    require('**Root candidate-adoption date (UTC): ' + stamp + '.**' in guide
            and '{{R8_AF_ADOPTED_UTC}}' not in guide,
            'AF reader guide must carry the actual adopted UTC from the outer record')
    return {'AF_candidate_adoption_binding_checked': True, 'AF_seven_history_events_checked': 7,
            'AF_v4_never_entered_solve_slots_checked': 2, 'AF_saved_false_UNKNOWN_scope_checked': True,
            'AF_static_record_integrity_only': True, 'AF_scientific_execution_or_replay': False}


def verify_completed_pair_record_bindings(root):
    """AG package/encoded bytes and saved adoption metadata only; no raw expansion."""
    row = COMPLETED_PAIR_ARCHIVE_RECORD
    with zipfile.ZipFile(root / row['path']) as archive:
        prefix = row['archive_prefix']
        infos = archive.infolist()
        require(len(infos) <= 2500 and all(i.file_size <= 67108864 for i in infos)
                and sum(i.file_size for i in infos) <= 268435456,
                'AG package-specific finite bounds differ')
        names = {i.filename for i in infos}
        def data(member):
            v71_relative(member)
            require(prefix + member in names, 'Missing AG member: ' + member)
            return archive.read(prefix + member)
        def record(member):
            return ag_parse(data(member))
        summary = record('RESULT_SUMMARY.json')
        require(summary['evidence_id'] == row['id']
                and canonical_json_sha(summary['history']) == canonical_json_sha(COMPLETED_PAIR_HISTORY),
                'AG result identity/history differs')
        require(summary['new_scientific_execution'] is False and summary['publication_authority'] is False,
                'AG frozen record is not execution/release authority')
        science = record(summary['root_adoption_member'])
        require(science['status'] == 'ADOPTED_EXACT_B_SAME_OBSERVER_FALSE_TRUE_PAIR'
                and science['capture_integrity']['both_complete'] is True
                and science['capture_integrity']['both_full_raw_and_encoded_SHA256_match'] is True
                and science['capture_integrity']['full_raw_bytes_verified_total'] == 3641273599,
                'AG adopted original full-capture QA differs')
        require(canonical_json_sha(science['history']) == canonical_json_sha(COMPLETED_PAIR_HISTORY),
                'AG original scientific history differs')
        require(canonical_json_sha(summary['not_established']) == canonical_json_sha(COMPLETED_PAIR_NOT_ESTABLISHED),
                'AG scientific claim limits differ')
        captured = []
        for arm, expected_boolean in (('unchanged', False), ('S01_release', True)):
            current = summary['arms'][arm]
            require(current['returned_raw_four_fixed_point_boolean'] is expected_boolean
                    and science['arms'][arm]['returned_raw_four_fixed_point_boolean'] is expected_boolean
                    and current['all24completionconditions'] is True,
                    'AG typed Boolean/full completion differs')
            native = record(current['scientific_native_result_member'])
            require(native['realizable'] is expected_boolean and native['accounting_finalized'] is True
                    and native['model_generation_call_dispatched'] is True
                    and native['raw_call_dispatch_recorded'] is True, 'AG native return/accounting differs')
            for key in ('model_generation_attempts', 'model_generations', 'raw_call_entry_attempts',
                        'raw_four_fixed_point_calls', 'raw_four_fixed_point_calls_returned'):
                require(type(native[key]) is int and native[key] == 1, 'AG native count differs')
            guardian = record(current['qa_guardian_member'])
            worker = record(current['qa_worker_member'])
            require(guardian['status'] == 'COMPLETE_QA' and type(guardian['return_code']) is int
                    and guardian['return_code'] == 0 and guardian['limit_or_error'] is None
                    and guardian['cleanup_confirmed'] is True and guardian['signals'] == [],
                    'AG actual finite QA guardian differs')
            require(worker['status'] == 'VERIFIED_CAPTURE_AND_LISTED_ADMINISTRATIVE_CHECKS'
                    and worker['all_listed_completion_conditions'] is True
                    and len(worker['observed_completion_conditions']) == 24
                    and all(value is True for value in worker['observed_completion_conditions'].values()),
                    'AG actual 24-condition QA differs')
            capture = worker['capture']
            require(capture['status'] == 'VERIFIED_COMPLETE_CAPTURE'
                    and capture['capture_complete_verified'] is True
                    and capture['all_admitted_raw_digest_verified'] is True
                    and capture['framed_raw_sha256'] == current['full_raw_sha256']
                    and capture['framed_raw_bytes'] == current['full_raw_bytes'],
                    'AG inherited full raw integrity evidence differs')
            actual = ag_encoded_summary(data(current['encoded_capture_member']))
            for key in ('encoded_bytes', 'encoded_sha256', 'full_raw_bytes', 'repeated_lines', 'literal_bytes', 'records'):
                require(type(actual[key]) is type(current[key]) and actual[key] == current[key],
                        'AG encoded/count binding differs: ' + key)
            captured.append({'arm': arm, **actual})
    value = strict_json_bytes((root / COMPLETED_PAIR_PUBLIC_ADOPTION_PATH).read_bytes())
    fields = {'schema', 'status', 'adopted_utc', 'package_frozen_utc', 'archive', 'package_manifest',
              'package_handoff_pin', 'scientific_adoption_pin', 'independent_review_pins', 'root_adoption_record',
              'root_review_evidence_pins', 'public_input_adoption_pin', 'public_input_descriptor_pin',
              'public_input_review_evidence_pins', 'scope', 'historic_status_interpretation'}
    require(set(value) == fields and value['schema'] == 'v71-r9-completed-pair-package-adoption-binding-v1'
            and value['status'] == 'ROOT_ADOPTED_EXACT_AG_COMPLETED_PAIR_PUBLIC_PACKAGE_CANDIDATE',
            'AG separate outer package adoption required')
    require(value['package_frozen_utc'] == COMPLETED_PAIR_FREEZE_UTC
            and value['archive'] == {k: row[k] for k in ('path', 'bytes', 'sha256')}
            and value['package_manifest'] == row['package_manifest']
            and value['package_handoff_pin'] == COMPLETED_PAIR_HANDOFF_PIN
            and value['scientific_adoption_pin'] == COMPLETED_PAIR_SCIENCE_PIN
            and value['independent_review_pins'] == COMPLETED_PAIR_INDEPENDENT_QA_PINS
            and value['public_input_descriptor_pin'] == COMPLETED_PAIR_INPUT_DESCRIPTOR_PIN
            and canonical_json_sha(value['scope']) == canonical_json_sha(COMPLETED_PAIR_PUBLIC_SCOPE)
            and value['historic_status_interpretation'] == COMPLETED_PAIR_STATUS_INTERPRETATION,
            'AG exact outer identity/scope differs')
    stamp = value['adopted_utc']
    require(isinstance(stamp, str) and stamp.endswith(('+00:00', 'Z')), 'AG UTC adoption timestamp required')
    when = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
    require(datetime.fromisoformat(COMPLETED_PAIR_FREEZE_UTC) <= when <= datetime.now(timezone.utc),
            'AG adoption timestamp precedes freeze or is future-dated')
    for key in ('root_review_evidence_pins', 'public_input_review_evidence_pins'):
        require(isinstance(value[key], list) and value[key]
                and all(pin in value[key] for pin in COMPLETED_PAIR_INDEPENDENT_QA_PINS),
                'AG exact independent review evidence missing')
    pins = [value[k] for k in ('root_adoption_record', 'public_input_adoption_pin', 'public_input_descriptor_pin')]
    pins += value['root_review_evidence_pins'] + value['public_input_review_evidence_pins']
    for item in pins:
        require(isinstance(item, dict) and set(item) == {'bytes', 'sha256'}
                and type(item['bytes']) is int and item['bytes'] > 0
                and isinstance(item['sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', item['sha256']),
                'AG private adoption evidence must expose valid byte pins only')
    guide = (root / 'results/guides/COMPLETED_SAME_OBSERVER_PAIR.md').read_text(encoding='utf-8')
    require('**Root candidate-adoption date (UTC): ' + stamp + '.**' in guide
            and '{{R9_AG_ADOPTED_UTC}}' not in guide, 'AG guide adoption date differs')
    tags = strict_json_bytes((root / 'docs/HISTORICAL_TAG_SNAPSHOT.json').read_bytes())
    require(canonical_json_sha(tags['tags']) == COMPLETED_PAIR_HISTORICAL_TAGS_SHA
            and len(tags['tags']) == 22 and tags['current_remote_state_rechecked'] is False,
            'Saved exact 22-tag observation differs')
    return {'AG_completed_pair_binding_checked': True, 'AG_inherited_full_raw_integrity_bytes': 3641273599,
            'AG_encoded_captures': captured, 'AG_raw_SHA256_recomputed': False,
            'AG_scientific_execution': False, 'AG_historical_tag_observation_preserved': 22,
            'AG_current_remote_tag_state_checked': False}



def verify(root):
    root = root.resolve(strict=True)
    manifest = read_json(root / MANIFEST_PATH)
    require(manifest["schema"] == "seams2027-purpose-layout-v1", "Wrong manifest schema")
    require(manifest["baseline_commit"] == BASELINE_COMMIT, "Wrong baseline commit")
    require(manifest["scientific_payload_executed"] is False, "Wrong execution scope")
    rows = manifest["files"]
    file_paths = [row["path"] for row in rows]
    require(len(file_paths) == len(set(file_paths)), "Duplicate inventory path")
    require(MANIFEST_PATH not in file_paths, "Manifest must not hash itself")
    for row in rows:
        verify_record(root, row)
    actual = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if relative.parts[0] == ".git":
            continue
        require(not path.is_symlink(), "Unexpected symlink: " + relative.as_posix())
        if path.is_file() and relative.as_posix() != MANIFEST_PATH:
            actual.add(relative.as_posix())
    require(actual == set(file_paths), "File roster differs: missing=" +
            repr(sorted(set(file_paths) - actual)) + "; extra=" + repr(sorted(actual - set(file_paths))))

    archives = manifest["archive_preservation"]
    require(len(archives) == len(BASELINE_ARCHIVES), "Incorrect preserved archive count")
    seen = set()
    for row in archives:
        name = PurePosixPath(row["path"]).name
        require(name in BASELINE_ARCHIVES and name not in seen, "Unexpected/duplicate archive: " + name)
        seen.add(name)
        require(row["path"] == "results/archives/" + name
                and row["baseline_path"] == "archives/" + name, "Wrong archive relocation: " + name)
        require({"bytes": row["bytes"], "sha256": row["sha256"]} == BASELINE_ARCHIVES[name],
                "Baseline archive identity differs: " + name)
        verify_record(root, row)
    require(seen == set(BASELINE_ARCHIVES), "Preserved archive set differs")

    paper = read_json(root / "paper/PAPER_MANIFEST.json")
    require(paper["version"] == manifest["paper_version"], "Paper version mismatch")
    require({r["path"] for r in paper["files"]} ==
            {"paper/main.pdf", "paper/supplement.pdf", "paper/source.zip"}, "Paper triplet differs")
    for row in paper["files"]:
        verify_record(root, row)

    paper_source_report = verify_paper_source_tree(root, paper)
    extension = verify_v71_extensions(root, manifest, file_paths)

    sources = read_json(root / "tool/SOURCE_INDEX.json")["files"]
    copied = set()
    for row in sources:
        require(row["path"].startswith("tool/src/"), "Source copy outside tool/src")
        require(row["path"] not in copied, "Duplicate source copy")
        copied.add(row["path"])
        target = verify_record(root, row)
        archive_path = safe_path(root, row["archive"])
        require(row["archive"] in ({a["path"] for a in archives} | extension["added_archive_paths"]),
                "Unpinned source archive")
        with zipfile.ZipFile(archive_path) as archive:
            require(archive.namelist().count(row["member"]) == 1, "Missing/duplicate archive member")
            require(archive.read(row["member"]) == target.read_bytes(), "Source copy differs from archive: " + row["path"])
    require(copied == {p for p in file_paths if p.startswith("tool/src/")}, "Source-copy ledger incomplete")

    return {"status": "PASS_LAYOUT_AND_FILE_INTEGRITY_ONLY", "files_verified": len(rows),
            "preserved_scientific_archives": len(archives), "source_copies_verified": len(sources),
            "paper_version": paper["version"], "baseline_commit": BASELINE_COMMIT,
            "scientific_code_executed": False, "native_solver_executed": False,
            **extension["report"], **paper_source_report, **verify_links(root, file_paths)}


def main():
    try:
        report = verify(Path(__file__).resolve().parent.parent)
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as error:
        print(json.dumps({"status": "FAIL_LAYOUT_OR_FILE_INTEGRITY", "error": str(error)}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
