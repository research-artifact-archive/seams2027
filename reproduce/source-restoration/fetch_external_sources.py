#!/usr/bin/env python3
"""Retrieve omitted source bytes directly from their original distributors.

Only downloads, document text extraction, and byte checks are performed.
No synthesis engine, native binary, model, or evidence checker is executed.
"""

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import sys
import urllib.request
import zipfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def check(data, pin, label):
    if len(data) != pin["bytes"] or digest(data) != pin["sha256"]:
        raise ValueError("Pinned source bytes changed: " + label)
    return data


def get_source(row, cache):
    destination = cache / row["id"]
    if destination.exists():
        return check(destination.read_bytes(), row, row["id"])
    request = urllib.request.Request(
        row["url"], headers={"User-Agent": "Saved-Evidence-Source-Retrieval/1.0"}
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        data = response.read(row["bytes"] + 1)
    check(data, row, row["id"])
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        stream.write(data)
    return data


def text_from_pdf(data):
    import pypdf
    if pypdf.__version__ != "6.10.0":
        raise ValueError("Exact literature-text restoration requires pypdf==6.10.0")
    pages = pypdf.PdfReader(io.BytesIO(data)).pages
    return "\n".join(
        "\n===== PDF PAGE " + str(index + 1) + " =====\n" + page.extract_text()
        for index, page in enumerate(pages)
    )


def safe_target(root, member):
    relative = PurePosixPath(member)
    if relative.is_absolute() or ".." in relative.parts or "\\" in member:
        raise ValueError("Unsafe destination")
    target = root.joinpath(*relative.parts)
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError("Destination escapes output root")
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path,
                        default=Path(__file__).with_name("EXTERNAL_SOURCE_FETCH_MANIFEST.json"))
    parser.add_argument("--cache", type=Path, required=True,
                        help="Private local directory for publisher downloads")
    parser.add_argument("--output-root", type=Path,
                        help="Directory containing the extracted archive prefixes")
    parser.add_argument("--check-only", action="store_true",
                        help="Download and verify without restoring evidence-tree files")
    args = parser.parse_args()
    if not args.check_only and args.output_root is None:
        parser.error("Select --output-root or --check-only")
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    # Check the optional PDF extraction dependency before any network request.
    import pypdf
    if pypdf.__version__ != "6.10.0":
        raise ValueError("Install pypdf==6.10.0 in a separate environment")
    payloads = {
        row["id"]: get_source(row, args.cache)
        for row in manifest["upstream_sources"]
    }
    restored = []
    for row in manifest["archive_destinations"]:
        if row["kind"] == "zip_member":
            with zipfile.ZipFile(io.BytesIO(payloads[row["source_id"]])) as archive:
                data = archive.read(row["source_member"])
        elif row["kind"] == "direct":
            data = payloads[row["source_id"]]
        elif row["kind"] == "literature_text":
            friendly = text_from_pdf(payloads["friendly2019v1.pdf"])
            kind = text_from_pdf(payloads["kind2024-appendices.pdf"])
            text = (
                "PRIMARY NON-CONFLICTING PAPER FULL TEXT (arXiv1902.05629v1)\n"
                + friendly
                + "\n\nPRIMARY KIND EXCERPT, original saved text lines211-445\n"
                + "\n".join(kind.splitlines()[210:445])
            )
            data = text.encode("utf-8")
        else:
            raise ValueError("Unknown reconstruction kind")
        check(data, row, row["member"])
        restored.append((row, data))
    targets = []
    if args.output_root:
        for row, data in restored:
            target = safe_target(args.output_root, row["member"])
            if target.exists() and target.read_bytes() != data:
                raise ValueError("Refusing to replace different bytes: " + target.name)
            targets.append((target, data))
    written = 0
    if not args.check_only:
        for target, data in targets:
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as stream:
                    stream.write(data)
                written += 1
    print(json.dumps({
        "status": "PASS_EXTERNAL_SOURCE_BYTE_RESTORATION_ONLY",
        "upstream_downloads_verified": len(payloads),
        "archive_destinations_verified": len(restored),
        "files_written": written,
        "scientific_code_executed": False,
        "scope": "Original publishers' source terms continue to apply",
    }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, ImportError, zipfile.BadZipFile) as error:
        print("Source restoration stopped: " + str(error), file=sys.stderr)
        sys.exit(1)
