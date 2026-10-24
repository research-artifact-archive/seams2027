#!/usr/bin/env python3
"""Verify this public distribution; no scientific checker or solver is executed.

Python 3.9+ standard library. Run from any directory with:
    python3 -I -S -B /path/to/seams2027/reproduce/verify.py
The adjacent MANIFEST.json is the declared inventory, not a signature. Verify a
trusted Git tag/commit separately when authenticity, rather than consistency,
is required. Archive preservation is also checked against embedded v69 pins.
"""

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

    sources = read_json(root / "tool/SOURCE_INDEX.json")["files"]
    copied = set()
    for row in sources:
        require(row["path"].startswith("tool/src/"), "Source copy outside tool/src")
        require(row["path"] not in copied, "Duplicate source copy")
        copied.add(row["path"])
        target = verify_record(root, row)
        archive_path = safe_path(root, row["archive"])
        require(row["archive"] in {a["path"] for a in archives}, "Unpinned source archive")
        with zipfile.ZipFile(archive_path) as archive:
            require(archive.namelist().count(row["member"]) == 1, "Missing/duplicate archive member")
            require(archive.read(row["member"]) == target.read_bytes(), "Source copy differs from archive: " + row["path"])
    require(copied == {p for p in file_paths if p.startswith("tool/src/")}, "Source-copy ledger incomplete")

    return {"status": "PASS_LAYOUT_AND_FILE_INTEGRITY_ONLY", "files_verified": len(rows),
            "preserved_scientific_archives": len(archives), "source_copies_verified": len(sources),
            "paper_version": paper["version"], "baseline_commit": BASELINE_COMMIT,
            "scientific_code_executed": False, "native_solver_executed": False,
            **paper_source_report, **verify_links(root, file_paths)}


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
