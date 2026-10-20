#!/usr/bin/env python3
"""Check the fifth archive's exact bytes and optionally extract; execute no kit code."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import io
import json
import re
import stat
import zipfile

PREFIX = "seams2027-lift-public-regeneration-kit/"
READY = "FROZEN_QUALIFIED_SAME_HOST_NATIVE_AND_SAVED_NODE680"
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_MEMBERS = 10000


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def read_json(data):
    return json.loads(data, object_pairs_hook=unique_object)


def valid_pin(row, maximum):
    need(type(row.get("bytes")) is int and 0 <= row["bytes"] <= maximum,
         "Invalid byte bound")
    need(isinstance(row.get("sha256"), str)
         and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]), "Invalid SHA-256")


def safe(name):
    need(isinstance(name, str), "Member name is not text")
    path = PurePosixPath(name)
    need(name and not path.is_absolute() and str(path) == name
         and ".." not in path.parts and "\\" not in name and "\x00" not in name
         and name.startswith(PREFIX) and len(path.parts) > 1
         and not any(":" in part for part in path.parts), "Unsafe archive member")
    return path


def verify(archive_path, descriptor):
    need(descriptor.get("schema") == "lift-public-native-regeneration-release-v1",
         "Unexpected release descriptor")
    need(descriptor.get("status") == READY,
         "Descriptor is unfrozen or lacks the required recorded qualification")
    need(descriptor.get("member_prefix") == PREFIX, "Unexpected member prefix")
    expected = descriptor["archive"]
    inner = descriptor["inner_manifest"]
    valid_pin(expected, MAX_ARCHIVE)
    valid_pin(inner, MAX_FILE)
    need(inner.get("path") == "MANIFEST.json" and isinstance(inner.get("schema"), str)
         and inner["schema"], "Invalid inner-manifest identity")
    need(type(expected.get("members")) is int
         and 1 <= expected["members"] <= MAX_MEMBERS, "Invalid member count")
    need(type(expected.get("uncompressed_bytes")) is int
         and 0 <= expected["uncompressed_bytes"] <= MAX_TOTAL, "Invalid expansion bound")
    archive_path = Path(archive_path)
    need(archive_path.is_file() and not archive_path.is_symlink(), "Archive must be a regular file")
    need(archive_path.stat().st_size <= MAX_ARCHIVE, "Archive budget exceeded")
    with archive_path.open("rb") as stream:
        raw = stream.read(MAX_ARCHIVE + 1)
    need(len(raw) == expected["bytes"] and sha(raw) == expected["sha256"],
         "Archive length or digest mismatch")
    payload = {}
    total = 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        need(len(infos) == expected["members"], "Archive member count differs")
        for info in infos:
            safe(info.filename)
            kind = stat.S_IFMT(info.external_attr >> 16)
            need(not info.is_dir() and kind in (0, stat.S_IFREG)
                 and info.filename not in payload, "Directory, nonregular or duplicate member")
            need(not info.flag_bits & 1, "Encrypted member")
            need(info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                 "Unsupported compression")
            total += info.file_size
            need(0 <= info.file_size <= MAX_FILE and total <= MAX_TOTAL,
                 "Archive expansion budget exceeded")
            data = archive.read(info)
            need(len(data) == info.file_size, "Incomplete member")
            payload[info.filename] = data
    need(total == expected["uncompressed_bytes"], "Expanded byte count differs")
    manifest_name = PREFIX + "MANIFEST.json"
    need(manifest_name in payload, "Missing inner manifest")
    data = payload[manifest_name]
    need(len(data) == inner["bytes"] and sha(data) == inner["sha256"],
         "Inner-manifest byte identity differs")
    manifest = read_json(data)
    need(manifest.get("schema") == inner["schema"], "Inner-manifest schema differs")
    need(isinstance(manifest.get("files"), list), "Missing inner file list")
    declared = set()
    for row in manifest["files"]:
        valid_pin(row, MAX_FILE)
        name = PREFIX + row["path"]
        safe(name)
        need(name != manifest_name and name not in declared, "Duplicate/self manifest row")
        declared.add(name)
        need(name in payload and len(payload[name]) == row["bytes"]
             and sha(payload[name]) == row["sha256"], "Inner-member identity differs")
    need(set(payload) == declared | {manifest_name}, "Inner file closure differs")
    return payload


def extract(payload, target):
    target = Path(target)
    need(not target.exists() and not target.is_symlink() and target.parent.is_dir(),
         "Extraction requires an absent destination and existing parent")
    target.mkdir()
    for name, data in payload.items():
        path = target.joinpath(*safe(name).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--extract-to", type=Path)
    parser.add_argument("--descriptor", type=Path,
                        default=Path(__file__).resolve().parent.parent / "NATIVE_REGENERATION_MANIFEST.json")
    args = parser.parse_args()
    descriptor = read_json(args.descriptor.read_bytes())
    payload = verify(args.archive, descriptor)
    if args.extract_to:
        extract(payload, args.extract_to)
    print(json.dumps({"status": "PASS_NATIVE_REGENERATION_ARCHIVE_INTEGRITY_ONLY",
                      "members": len(payload), "extracted": bool(args.extract_to),
                      "scientific_checks": 0, "native_runs": 0}))


if __name__ == "__main__":
    main()
