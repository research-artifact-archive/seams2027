#!/usr/bin/env python3
"""Verify the fourth addendum and optionally extract it. Execute no evidence code."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import stat
import zipfile

PREFIX = "seams2027-lift-causal-extension/"
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def safe(name):
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or ".." in path.parts or "\\" in name
            or str(path) != name or ":" in path.parts[0] or not name.startswith(PREFIX)):
        raise ValueError("Unsafe archive member")
    return path


def verify(archive_path, expected):
    raw = archive_path.read_bytes()
    if len(raw) != expected["bytes"] or sha(raw) != expected["sha256"]:
        raise ValueError("Archive byte count or SHA-256 mismatch")
    payload = {}
    total = 0
    with zipfile.ZipFile(archive_path) as archive:
        for info in archive.infolist():
            safe(info.filename)
            mode = info.external_attr >> 16
            if info.is_dir() or stat.S_ISLNK(mode) or info.filename in payload:
                raise ValueError("Directory, symlink or duplicate member")
            total += info.file_size
            if info.file_size > MAX_FILE or total > MAX_TOTAL:
                raise ValueError("Archive expansion budget exceeded")
            data = archive.read(info)
            if len(data) != info.file_size:
                raise ValueError("Incomplete member")
            payload[info.filename] = data
    if len(payload) != expected["members"] or total != expected["uncompressed_bytes"]:
        raise ValueError("Archive inventory differs")
    manifest_name = PREFIX + "MANIFEST.json"
    manifest = json.loads(payload[manifest_name])
    if manifest["schema"] != "lift-causal-extension-public-manifest-v1":
        raise ValueError("Unexpected inner manifest")
    declared = set()
    for row in manifest["files"]:
        name = PREFIX + row["path"]
        safe(name)
        if name in declared:
            raise ValueError("Duplicate inner-manifest entry")
        declared.add(name)
        if name not in payload or len(payload[name]) != row["bytes"] or sha(payload[name]) != row["sha256"]:
            raise ValueError("Inner member hash mismatch")
    if set(payload) != declared | {manifest_name}:
        raise ValueError("Inner file closure differs")
    return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--extract-to", type=Path)
    parser.add_argument("--descriptor", type=Path,
                        default=Path(__file__).resolve().parent.parent / "LIFT_CAUSAL_EXTENSION_MANIFEST.json")
    args = parser.parse_args()
    descriptor = json.loads(args.descriptor.read_text())
    payload = verify(args.archive, descriptor["archive"])
    if args.extract_to:
        target = args.extract_to
        if target.exists() or target.is_symlink() or not target.parent.is_dir():
            raise ValueError("Extraction target must be absent with an existing parent")
        target.mkdir()
        for name, raw in payload.items():
            path = target.joinpath(*safe(name).parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(raw)
    print(json.dumps({"status": "PASS_LIFT_CAUSAL_ARCHIVE_INTEGRITY_ONLY",
                      "members": len(payload), "extracted": bool(args.extract_to),
                      "scientific_checks": 0, "native_runs": 0}))


if __name__ == "__main__":
    main()
