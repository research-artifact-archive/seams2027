#!/usr/bin/env python3
"""Verify the two certificate/finite-study ZIPs without executing evidence code."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import zipfile


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_name(name):
    p = PurePosixPath(name)
    require(bool(name) and not p.is_absolute() and ".." not in p.parts
            and "\\" not in name and ":" not in p.parts[0]
            and str(p) == name, "Unsafe archive name: " + name)
    return p


def inspect_archive(path, expected_sha256=None):
    actual = digest(path)
    if expected_sha256 is not None:
        require(actual == expected_sha256, "ZIP hash mismatch: " + path.name)
    names, prefixes, total = set(), set(), 0
    with zipfile.ZipFile(path) as z:
        for item in z.infolist():
            p = safe_name(item.filename)
            require(len(p.parts) >= 2, "ZIP member lacks a root directory")
            require(not item.is_dir() and not stat.S_ISLNK(item.external_attr >> 16),
                    "Unexpected directory/symlink member")
            require(not item.flag_bits & 1, "Encrypted ZIP member")
            require(item.filename not in names, "Duplicate ZIP member")
            require(item.file_size <= 128 * 1024 * 1024, "Member exceeds 128 MiB")
            names.add(item.filename)
            prefixes.add(p.parts[0])
            total += item.file_size
            require(total <= 1024 * 1024 * 1024, "Archive exceeds 1 GiB expanded limit")
            # Full reads check ZIP CRCs and stream lengths without importing payloads.
            with z.open(item) as stream:
                consumed = sum(len(x) for x in iter(lambda: stream.read(1024 * 1024), b""))
            require(consumed == item.file_size, "Member expanded size mismatch")
        require(len(prefixes) == 1, "Expected one archive root")
        prefix = next(iter(prefixes)) + "/"
        manifest_path = prefix + "MANIFEST.json"
        require(manifest_path in names, "Missing outer MANIFEST.json")
        raw_manifest = z.read(manifest_path)
        inner = json.loads(raw_manifest)
        rows = inner["files"]
        indexed = set()
        for row in rows:
            name = prefix + str(safe_name(row["path"]))
            require(name not in indexed, "Duplicate manifest member")
            require(name != manifest_path, "Outer manifest unexpectedly includes itself")
            require(name in names, "Missing manifest member: " + name)
            raw = z.read(name)
            require(len(raw) == row["bytes"], "Manifest member byte count mismatch")
            require(hashlib.sha256(raw).hexdigest() == row["sha256"],
                    "Manifest member hash mismatch: " + name)
            indexed.add(name)
        require(indexed == names - {manifest_path}, "Manifest does not cover every ZIP member")
    return {
        "path": "archives/" + path.name, "bytes": path.stat().st_size,
        "sha256": actual, "members": len(names), "uncompressed_bytes": total,
        "member_prefix": prefix,
        "inner_manifest": {"path": "MANIFEST.json", "bytes": len(raw_manifest),
                           "sha256": hashlib.sha256(raw_manifest).hexdigest()},
    }, names


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path,
                        default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--archive-dir", type=Path)
    parser.add_argument("--extract-to", type=Path,
                        help="Fresh directory; its parent must already exist")
    args = parser.parse_args()
    root = args.repository.resolve()
    archive_dir = args.archive_dir or root / "archives"
    manifest = json.loads((root / "CERTIFICATE_FINITE_MANIFEST.json").read_text())
    require(manifest["schema"] == "certificate-finite-public-release-v1", "Unexpected manifest schema")
    verified, all_names, expanded = [], set(), 0
    for expected in manifest["archives"]:
        path = archive_dir / Path(expected["path"]).name
        actual, names = inspect_archive(path, expected["sha256"])
        require(actual == expected, "ZIP descriptor differs: " + path.name)
        require(not all_names.intersection(names), "Cross-archive member collision")
        all_names.update(names)
        expanded += actual["uncompressed_bytes"]
        verified.append(actual)
    for row in manifest["preserved_repository_files"]:
        path = root.joinpath(*safe_name(row["path"]).parts)
        require(path.is_file() and not path.is_symlink(), "Missing preserved file: " + row["path"])
        require(path.stat().st_size == row["bytes"] and digest(path) == row["sha256"],
                "Prior repository file changed: " + row["path"])
    for row in manifest["release_metadata_files"]:
        path = root.joinpath(*safe_name(row["path"]).parts)
        require(path.stat().st_size == row["bytes"] and digest(path) == row["sha256"],
                "Current release metadata changed: " + row["path"])
    sums = {}
    for line in (root / "SHA256SUMS").read_text().splitlines():
        h, name = line.split("  ", 1)
        require(name not in sums, "Duplicate SHA256SUMS entry")
        sums[name] = h
        path = root.joinpath(*safe_name(name).parts)
        require(digest(path) == h, "SHA256SUMS mismatch: " + name)
    require(len(sums) == 21, "Expected 11 archive and 10 historical document hashes")
    for row in verified:
        require(sums[row["path"]] == row["sha256"], "New ZIP absent from SHA256SUMS")
    if args.extract_to:
        target = args.extract_to
        require(not target.exists() and not target.is_symlink(), "Extraction destination already exists")
        require(target.parent.is_dir(), "Extraction parent must exist")
        require(shutil.disk_usage(target.parent).free >= expanded + 1024 * 1024 * 1024,
                "Extraction needs expanded size plus 1 GiB free")
        target.mkdir()
        for row in verified:
            with zipfile.ZipFile(archive_dir / Path(row["path"]).name) as z:
                for item in z.infolist():
                    destination = target.joinpath(*safe_name(item.filename).parts)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(item) as source, destination.open("xb") as output:
                        shutil.copyfileobj(source, output, 1024 * 1024)
    print(json.dumps({"status": "PASS_CERTIFICATE_FINITE_ARCHIVE_INTEGRITY_ONLY",
                      "archives": verified,
                      "preserved_repository_files": len(manifest["preserved_repository_files"]),
                      "extracted": args.extract_to is not None,
                      "scientific_code_executed": False}, indent=2))


if __name__ == "__main__":
    main()
