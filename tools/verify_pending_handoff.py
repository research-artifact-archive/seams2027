#!/usr/bin/env python3
"""Check the pending-handoff release's archive and navigation; execute no evidence."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import zipfile

TAG = "pending-native-handoff-evidence-20261023-v1"
ARCHIVE = "archives/" + TAG + ".zip"
PREFIX = "seams2027-pending-native-handoff/"
MANIFEST = "PENDING_NATIVE_HANDOFF_MANIFEST.json"
VALIDATION = "PENDING_NATIVE_HANDOFF_VALIDATION.json"
GUIDE = "PENDING_NATIVE_HANDOFF.md"
VALIDATOR = "tools/verify_pending_handoff.py"
ROW_ID = "pending-native-handoff-all-three-obligations"
ROOT_KEY = "PendingNativeHandoff"
MUTABLE = ("README.md", "EVIDENCE_READER_INDEX.txt", "EVIDENCE_READER_INDEX.json",
           "CLAIM_TO_FILE_INDEX.json", "SHA256SUMS", "THIRD_PARTY_NOTICES.md")
INDEX_FILES = ("EVIDENCE_READER_INDEX.json", "CLAIM_TO_FILE_INDEX.json")
READER_MEMBERS = ("README.txt", "PUBLIC_BINDINGS.json", "PUBLIC_PIN_MAP.json",
                  "REFERENCE_CLOSURE.json", "tools/restore_pending_sources.py",
                  "tools/bind_pending_replay.py", "tools/run_pending_replay_stage.py",
                  "tools/compare_pending_replay.py", "qualification/REPLAY_SUMMARY.json")
GATES = ("scientific_results_adopted", "exact_source_restoration_passed",
         "relocated_replay_passed", "metadata_only_transformation_verified",
         "reference_closure_passed", "privacy_review_passed",
         "all_attempts_and_negative_results_retained", "release_manifest_complete")


def need(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "Duplicate JSON key: " + key)
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_name(name):
    need(type(name) is str and bool(name), "Expected nonempty relative path")
    p = PurePosixPath(name)
    need(not p.is_absolute() and ".." not in p.parts and ".git" not in p.parts
         and "\\" not in name and ":" not in name and "\x00" not in name
         and str(p) == name, "Unsafe relative path: " + name)
    return p


def below(root, name):
    p = root.joinpath(*safe_name(name).parts)
    need(p.resolve().is_relative_to(root.resolve()), "Path escapes repository: " + name)
    q = p
    while q != root:
        need(not q.is_symlink(), "Symlink in repository path: " + name)
        q = q.parent
    return p


def pin(root, name):
    p = below(root, name)
    need(p.is_file(), "Missing regular file: " + name)
    return {"path": name, "bytes": p.stat().st_size, "sha256": digest(p)}


def verify_pin(root, row):
    need(pin(root, row["path"]) == row, "File binding differs: " + row["path"])


def inspect_archive(path):
    names, total = set(), 0
    with zipfile.ZipFile(path) as archive:
        for item in archive.infolist():
            p = safe_name(item.filename)
            need(item.filename.startswith(PREFIX) and len(p.parts) >= 2,
                 "Unexpected archive root")
            need(not item.is_dir() and not stat.S_ISLNK(item.external_attr >> 16)
                 and not item.flag_bits & 1, "Directory, symlink or encrypted ZIP member")
            need(item.filename not in names, "Duplicate ZIP member")
            need(item.file_size <= 128 * 1024 * 1024, "ZIP member exceeds 128 MiB")
            total += item.file_size
            need(total <= 1024 * 1024 * 1024, "Expanded ZIP exceeds 1 GiB")
            names.add(item.filename)
            with archive.open(item) as stream:
                size = sum(len(c) for c in iter(lambda: stream.read(1024 * 1024), b""))
            need(size == item.file_size, "ZIP expanded size mismatch")
        release_name, assembly_name = PREFIX + "RELEASE_MANIFEST.json", PREFIX + "MANIFEST.json"
        need(release_name in names and assembly_name in names, "Missing release/assembly manifest")
        release_raw, assembly_raw = archive.read(release_name), archive.read(assembly_name)
        release, assembly = decode(release_raw), decode(assembly_raw)
        need(assembly.get("schema") == "pending-handoff-assembly-manifest-v1"
             and assembly.get("status") == "ASSEMBLED_NOT_REPLAY_QUALIFIED",
             "Public assembly snapshot must retain its pre-replay status")
        assembly_indexed = set()
        for row in assembly["files"]:
            name = PREFIX + str(safe_name(row["path"]))
            need(name in names and name not in assembly_indexed
                 and name not in {assembly_name, release_name}, "Invalid assembly inventory")
            raw = archive.read(name)
            need(type(row["bytes"]) is int and len(raw) == row["bytes"]
                 and sha(raw) == row["sha256"], "Public assembly payload differs from its manifest: " + name)
            assembly_indexed.add(name)
        need(type(assembly["file_count_excluding_manifest"]) is int
             and len(assembly_indexed) == assembly["file_count_excluding_manifest"],
             "Public assembly file count differs")
        need(all(PREFIX + member in assembly_indexed for member in READER_MEMBERS[:8]),
             "Reader tools or bindings were not part of the compared assembly")
        indexed = set()
        for row in release["files"]:
            name = PREFIX + str(safe_name(row["path"]))
            need(name not in indexed and name != release_name and name in names,
                 "Duplicate, self-including or missing release member")
            raw = archive.read(name)
            need(type(row["bytes"]) is int and len(raw) == row["bytes"]
                 and sha(raw) == row["sha256"], "Release member binding differs: " + name)
            indexed.add(name)
        need(indexed == names - {release_name}, "Release manifest must cover every other member")
        need(all(PREFIX + member in names for member in READER_MEMBERS),
             "Missing required reader entrypoint")
        comparer_raw = archive.read(PREFIX + "tools/compare_pending_replay.py")
    return {"path": ARCHIVE, "bytes": path.stat().st_size, "sha256": digest(path),
            "members": len(names), "uncompressed_bytes": total, "member_prefix": PREFIX,
            "release_manifest": {"path": "RELEASE_MANIFEST.json", "bytes": len(release_raw),
                                 "sha256": sha(release_raw)},
            "assembly_manifest": {"path": "MANIFEST.json", "bytes": len(assembly_raw),
                                  "sha256": sha(assembly_raw),
                                  "status": "ASSEMBLED_NOT_REPLAY_QUALIFIED"},
            "replay_comparer": {"path": "tools/compare_pending_replay.py",
                                "bytes": len(comparer_raw), "sha256": sha(comparer_raw)}}, names


def verify_repository(root):
    root = root.resolve()
    manifest = decode(below(root, MANIFEST).read_bytes())
    need(manifest["schema"] == "pending-native-handoff-public-release-v1"
         and manifest["version_tag"] == TAG, "Unexpected public manifest")
    actual, names = inspect_archive(below(root, ARCHIVE))
    need(actual == manifest["archive"], "Archive descriptor differs")
    preserved, metadata = manifest["preserved_repository_files"], manifest["release_metadata_files"]
    need(len(preserved) == 289 and len(metadata) == 9, "Expected 289 preserved and 9 metadata files")
    paths = [row["path"] for row in preserved + metadata]
    need(len(set(paths)) == len(paths), "Duplicate repository manifest path")
    need(set(row["path"] for row in metadata) == set(MUTABLE) | {GUIDE, VALIDATOR, VALIDATION},
         "Unexpected release metadata paths")
    for row in preserved + metadata:
        verify_pin(root, row)
    expected = set(paths) | {ARCHIVE, MANIFEST}
    entries = [p for p in root.rglob("*") if ".git" not in p.relative_to(root).parts]
    need(not any(p.is_symlink() for p in entries), "Unexpected repository symlink")
    found = {str(p.relative_to(root)) for p in entries if p.is_file()}
    need(found == expected, "Repository has missing or extra files")
    sums = (root / "SHA256SUMS").read_text().splitlines()
    need(len(sums) == 22 and sums[:21] == manifest["historical_sha256sums_lines"],
         "Expected the unchanged 21 lines and one appended checksum")
    parsed = {}
    for line in sums:
        h, name = line.split("  ", 1)
        need(name not in parsed and digest(below(root, name)) == h, "Checksum mismatch/duplicate")
        parsed[name] = h
    need(sums[-1] == actual["sha256"] + "  " + ARCHIVE, "New archive checksum not appended")
    need(len([n for n in parsed if n.startswith("archives/")]) == 12
         and len([n for n in parsed if n.startswith("documents/")]) == 10,
         "Expected 12 archive and 10 document downloads")
    for name in INDEX_FILES:
        index = decode((root / name).read_bytes())
        need(len(index["rows"]) == index["reader_row_count"] == 23
             and len(index["extensions"]) == 9 and index["scientific_archive_count"] == 12
             and index["document_download_count"] == 10, "Current reader counts differ")
        need(index["rows"][-1] == manifest["reader_row"]
             and index["extensions"][-1] == manifest["reader_extension"], "New reader entry differs")
        need(index["archive_roots"][ROOT_KEY] == {"archive": Path(ARCHIVE).name,
                                                 "member_prefix": PREFIX}, "Reader archive root differs")
        for field in ("input_navigation", "saved_outputs", "checkers"):
            need(all(PREFIX + str(safe_name(v)) in names for v in index["rows"][-1][field]),
                 "Reader member reference missing")
        # Reverse only the declared append/count update and compare every old value.
        index["rows"].pop()
        index["extensions"].pop()
        del index["archive_roots"][ROOT_KEY]
        del index["pending_native_handoff_extension"]
        index.update(reader_row_count=22, scientific_archive_count=11, document_download_count=10)
        need(sha(canonical(index)) == manifest["historical_index_values_sha256"][name],
             "Historical reader objects or metadata changed")
    validation = decode((root / VALIDATION).read_bytes())
    need(validation["schema"] == "pending-handoff-public-validation-v1"
         and validation["status"] == "PASS_BOUND_RELEASE_QUALIFICATION"
         and validation["archive"] == {k: actual[k] for k in ("path", "bytes", "sha256")},
         "Release qualification archive binding differs")
    need(set(validation["gates"]) == set(GATES)
         and all(v is True for v in validation["gates"].values()), "Release gate is not true")
    need(validation["replay_comparison_origin"]["status"] == "PASS_RELOCATED_REPLAY"
         and validation["replay_comparison_origin"]["event_count"] == 98
         and validation["replay_comparison_origin"]["episode_count"] == 6,
         "Replay qualification summary differs")
    for key, archive_key in (("assembly_manifest", "assembly_manifest"),
                              ("comparer", "replay_comparer")):
        need(validation["replay_comparison_origin"][key]
             == {k: actual[archive_key][k] for k in ("bytes", "sha256")},
             "Replay origin does not bind the delivered " + key)
    return {"status": "PASS_PENDING_HANDOFF_ARCHIVE_INTEGRITY_ONLY", "archive": actual,
            "preserved_repository_files": len(preserved), "scientific_archives": 12,
            "document_downloads": 10, "checksum_entries": 22, "reader_rows": 23,
            "reader_extensions": 9, "scientific_code_executed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    print(json.dumps(verify_repository(args.repository), indent=2))


if __name__ == "__main__":
    main()
