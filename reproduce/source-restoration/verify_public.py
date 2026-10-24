#!/usr/bin/env python3
"""Check public download bytes and optionally extract to a new directory.

This standard-library-only operation does not execute any evidence code.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import zipfile


REPOSITORY = Path(__file__).resolve().parent


def sha256_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest() if hasattr(
            hashlib, "file_digest"
        ) else streamed_digest(stream)


def streamed_digest(stream):
    result = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        result.update(chunk)
    return result.hexdigest()


def safe_name(name):
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or ".." in path.parts or "\\" in name
            or ":" in path.parts[0] or str(path) != name):
        raise ValueError("Unsafe archive member: " + name)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive-dir", type=Path, required=True)
    parser.add_argument("--extract-to", type=Path,
                        help="New directory whose parent already exists")
    args = parser.parse_args()
    manifest = json.loads((REPOSITORY / "RELEASE_MANIFEST.json").read_text())
    if args.extract_to:
        if args.extract_to.exists() or args.extract_to.is_symlink():
            raise ValueError("Extraction destination must not exist")
        if not args.extract_to.parent.is_dir():
            raise ValueError("Extraction parent must already exist")
    verified = []
    total_uncompressed = 0
    all_names = set()
    # Verify every archive before creating an extraction directory.
    for expected in manifest["archives"]:
        path = args.archive_dir / expected["public_name"]
        if path.stat().st_size != expected["public_bytes"]:
            raise ValueError("Archive byte count differs: " + path.name)
        if sha256_file(path) != expected["public_sha256"]:
            raise ValueError("Archive SHA-256 differs: " + path.name)
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) != expected["public_members"]:
                raise ValueError("Archive member count differs: " + path.name)
            names = set()
            size = 0
            for info in infos:
                relative = safe_name(info.filename)
                mode = info.external_attr >> 16
                if info.is_dir() or stat.S_ISLNK(mode):
                    raise ValueError("Unexpected directory or symlink member")
                if info.filename in names or info.filename in all_names:
                    raise ValueError("Duplicate archive member")
                if relative.parts[0] != expected["member_prefix"].rstrip("/"):
                    raise ValueError("Unexpected archive prefix")
                if info.file_size > 128 * 1024 * 1024:
                    raise ValueError("Member exceeds 128 MiB limit")
                names.add(info.filename)
                all_names.add(info.filename)
                size += info.file_size
                # Reading fully checks decompression and the ZIP CRC.
                with archive.open(info) as member:
                    consumed = sum(len(chunk) for chunk in iter(
                        lambda: member.read(1024 * 1024), b""
                    ))
                if consumed != info.file_size:
                    raise ValueError("Expanded member size differs")
            if size != expected["public_uncompressed_bytes"]:
                raise ValueError("Expanded archive size differs")
            total_uncompressed += size
        verified.append({
            "archive": path.name, "sha256": expected["public_sha256"],
            "members": len(infos),
        })
    if args.extract_to:
        required = total_uncompressed + 1024 * 1024 * 1024
        if shutil.disk_usage(args.extract_to.parent).free < required:
            raise ValueError("Extraction requires its size plus 1 GiB free")
        args.extract_to.mkdir()
        for expected in manifest["archives"]:
            with zipfile.ZipFile(args.archive_dir / expected["public_name"]) as archive:
                for info in archive.infolist():
                    target = args.extract_to.joinpath(*safe_name(info.filename).parts)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info) as source, target.open("xb") as output:
                        shutil.copyfileobj(source, output, 1024 * 1024)
                    if shutil.disk_usage(args.extract_to).free < 1024 * 1024 * 1024:
                        raise ValueError("Extraction stopped at 1 GiB free-space floor")
    print(json.dumps({
        "status": "PASS_PUBLIC_ARCHIVE_INTEGRITY_ONLY",
        "archives": verified, "extracted": args.extract_to is not None,
        "source_files_omitted": manifest["omitted_source_files"],
        "scientific_code_executed": False,
    }, indent=2))


if __name__ == "__main__":
    main()
