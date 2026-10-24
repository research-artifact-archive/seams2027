#!/usr/bin/env python3
"""Fetch pinned public listing bytes and restore declared source-only copies.

This utility does not import artifact checkers, run a solver, execute a model,
or make a new scientific claim. It uses only the Python standard library.
"""

import argparse
import base64
import difflib
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import urllib.request


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pin(data, spec, label):
    require(len(data) == spec["bytes"], label + ": byte count changed")
    require(digest(data) == spec["sha256"], label + ": SHA-256 changed")
    return data


def get_listing(html, listing_id):
    figures = re.findall(
        r'<figure\b[^>]*id="' + re.escape(listing_id)
        + r'"[^>]*>(.*?)</figure>', html, re.S
    )
    require(len(figures) == 1, listing_id + ": expected one figure")
    payloads = re.findall(
        r'href="data:text/plain;base64,([^"]+)"', figures[0]
    )
    require(len(payloads) == 1, listing_id + ": expected one source payload")
    return base64.b64decode(payloads[0], validate=True)


def reconstruct_sources(html_bytes, manifest):
    html = html_bytes.decode("utf-8")
    raws = {}
    for row in manifest["listings"]:
        raws[row["id"]] = pin(
            get_listing(html, row["listing_id"]), row["raw"], row["id"] + "/raw"
        )
    pattern_spec = manifest["pattern"]
    donor = raws[pattern_spec["donor_id"]]
    start = donor.index(pattern_spec["start_marker"].encode("utf-8"))
    pattern = pin(donor[start:], pattern_spec, "same-paper response pattern")
    by_hash = {digest(pattern): pattern}
    canonical = {"sources/pRespondsToS.from_C2_1.spectra": pattern}
    for row in manifest["listings"]:
        name = row["id"]
        raw = raws[name]
        rebuilt = raw.decode("utf-8")
        for edit in row["edits"]:
            op = edit["operation"]
            if op == "append_exact_omitted_pattern":
                require("pattern pRespondsToS" not in rebuilt, name + ": pattern already present")
                rebuilt += "\n\n" + pattern.decode("utf-8")
            elif op in (
                "declared_typographical_reconstruction",
                "infinite_trace_equivalent_response_lowering",
            ):
                require(
                    rebuilt.count(edit["old"]) == edit.get("occurrences", 1),
                    name + ": replacement occurrence count changed",
                )
                rebuilt = rebuilt.replace(edit["old"], edit["new"])
            else:
                raise ValueError("Unknown declared edit: " + op)
        reconstructed = pin(rebuilt.encode("utf-8"), row["reconstructed"], name + "/reconstructed")
        differences = difflib.unified_diff(
            raw.decode("utf-8").splitlines(keepends=True),
            rebuilt.splitlines(keepends=True),
            fromfile="raw/" + name + ".spectra",
            tofile="reconstructed/" + name + ".spectra",
        )
        diff = "".join(
            line if line.endswith("\n")
            else line + "\n\\ No newline at end of file\n"
            for line in differences
        ).encode("utf-8")
        pin(diff, row["diff"], name + "/diff")
        for kind, data, suffix in (
            ("raw", raw, ".spectra"),
            ("reconstructed", reconstructed, ".spectra"),
            ("diffs", diff, ".spectra.diff"),
        ):
            by_hash[digest(data)] = data
            canonical[kind + "/" + name + suffix] = data
    return by_hash, canonical


def safe_target(root, relative):
    path = PurePosixPath(relative)
    require(not path.is_absolute() and ".." not in path.parts, "Unsafe destination")
    target = root.joinpath(*path.parts)
    require(target.resolve().is_relative_to(root.resolve()), "Destination escapes output root")
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).with_name("PAPER_SOURCE_FETCH_MANIFEST.json"))
    parser.add_argument("--html", type=Path, help="Use a previously obtained arXiv v1 HTML file without network access")
    parser.add_argument("--output-root", type=Path, help="Directory containing extracted archive prefixes")
    parser.add_argument("--canonical-dir", type=Path, help="Optionally write the full 16 raw/reconstructed/diff set here")
    parser.add_argument("--check-only", action="store_true", help="Fetch, reconstruct, and hash-check in memory without writing source files")
    args = parser.parse_args()
    require(args.check_only or args.output_root or args.canonical_dir, "Select an output directory or --check-only")
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if args.html:
        html_bytes = args.html.read_bytes()
        source_mode = "LOCAL_HTML"
    else:
        request = urllib.request.Request(
            manifest["source_url"],
            headers={"User-Agent": "Saved-Evidence-Source-Retrieval/1.0"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            html_bytes = response.read(5_000_001)
        require(len(html_bytes) <= 5_000_000, "Source HTML exceeds 5 MB limit")
        source_mode = "HTTPS_GET"
    by_hash, canonical = reconstruct_sources(html_bytes, manifest)
    planned = []
    for destination in manifest["archive_destinations"]:
        data = pin(by_hash[destination["sha256"]], destination, destination["member"])
        if args.output_root:
            planned.append((safe_target(args.output_root, destination["member"]), data))
    if args.canonical_dir:
        planned.extend((safe_target(args.canonical_dir, name), data) for name, data in canonical.items())
    require(len({str(path.resolve()) for path, _ in planned}) == len(planned), "Duplicate output paths")
    for path, data in planned:
        require(not path.exists() or path.read_bytes() == data, "Refusing to overwrite different bytes: " + path.name)
    written = 0
    if not args.check_only:
        for path, data in planned:
            if not path.exists():
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("xb") as handle:
                    handle.write(data)
                written += 1
    print(json.dumps({
        "status": "PASS_SOURCE_BYTE_RECONSTRUCTION_ONLY",
        "source_mode": source_mode,
        "source_url": manifest["source_url"],
        "html_sha256": digest(html_bytes),
        "historical_html_sha256_matches": digest(html_bytes) == manifest["historical_html_sha256"],
        "listings_checked": len(manifest["listings"]),
        "raw_reconstructed_diff_pins_checked": 3 * len(manifest["listings"]),
        "canonical_pattern_pin_checked": True,
        "archive_destinations_checked": len(manifest["archive_destinations"]),
        "files_written": written,
        "scientific_code_executed": False,
    }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError) as error:
        print("Source retrieval stopped: " + str(error), file=sys.stderr)
        sys.exit(1)
