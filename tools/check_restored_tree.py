#!/usr/bin/env python3
"""Compare a restored inspection tree with every historical member hash."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parent.parent


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    release = json.loads((REPOSITORY / "RELEASE_MANIFEST.json").read_text())
    index_path = REPOSITORY / "HISTORICAL_FILE_INDEX.json.gz"
    if digest(index_path) != release["historical_file_index_sha256"]:
        raise ValueError("Historical file index identity changed")
    index = json.loads(gzip.decompress(index_path.read_bytes()))
    expected_paths = set()
    for row in index["files"]:
        relative = row["member"]
        path = root / relative
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError("Unsafe restored path: " + relative)
        if not path.is_file() or path.stat().st_size != row["bytes"]:
            raise ValueError("Missing or changed-size historical member: " + relative)
        if digest(path) != row["sha256"]:
            raise ValueError("Changed historical member bytes: " + relative)
        expected_paths.add(relative)
    actual_paths = set()
    for archive in release["archives"]:
        prefix = root / archive["member_prefix"].rstrip("/")
        for path in prefix.rglob("*"):
            if path.is_symlink():
                raise ValueError("Symlink in restored tree")
            if path.is_file():
                actual_paths.add(path.relative_to(root).as_posix())
    if actual_paths != expected_paths:
        raise ValueError("Unexpected files in restored historical tree")
    print(json.dumps({
        "status": "PASS_HISTORICAL_TREE_BYTES_RESTORED_ONLY",
        "historical_members_verified": len(expected_paths),
        "scientific_code_executed": False,
        "historical_zip_bytes_reconstructed": False,
    }, indent=2))


if __name__ == "__main__":
    main()
