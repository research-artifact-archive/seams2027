"""Finite saved-byte QA only. No solver, model import, or scientific execution."""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import stat
import sys
import time

RAW_CAP = 68_719_476_736
ENCODED_CAP = 67_108_864
LINE_CAP = 131_072
LITERAL_CAP = 65_536
BLOCK_CAP = 1_048_576
REPEAT_CAP = 1_000_000
WALL_SECONDS = 300
CPU_SECONDS = 240
RSS_CAP = 1_073_741_824
DICTIONARY = b"lookup, class net.sf.javabdd.JTLVJavaFactory$BddCache\n"
SCHEMA = "bounded-exact-println-dictionary-rle-v1"
PIN_KEYS = {"path", "bytes", "sha256"}
RECEIPT_KEYS = {"schema", "capture_complete", "raw_bytes", "raw_sha256",
                "encoded_bytes", "encoded_sha256", "repeated_lines",
                "unflushed_repeated_lines", "records", "raw_cap_bytes",
                "encoded_cap_bytes", "cap_reached", "diagnostic_line_base64",
                "capture_error"}


class QAError(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise QAError(message)


def count(value, name, maximum=RAW_CAP):
    need(type(value) is int and 0 <= value <= maximum, "invalid integer count: " + name)
    return value


def sha(value):
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
         "invalid SHA-256")
    return value


def strict_json(data):
    def unique(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def integer(text):
        need(len(text) <= 21, "overlong integer")
        return int(text)

    def finite(text):
        value = float(text)
        need(math.isfinite(value), "nonfinite JSON number")
        return value

    def forbidden(_):
        raise QAError("nonfinite JSON number")

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique,
                          parse_int=integer, parse_float=finite,
                          parse_constant=forbidden)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise QAError("invalid JSON") from error


def rss_peak():
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform == "darwin" else value * 1024)


class Budget:
    """Cooperative checks supplement the separate guardian and OS CPU limit."""
    def __init__(self, wall=WALL_SECONDS, cpu=CPU_SECONDS, rss=RSS_CAP):
        need(0 < wall <= WALL_SECONDS and 0 < cpu <= CPU_SECONDS and 0 < rss <= RSS_CAP,
             "limits may only be tightened")
        self.started = time.monotonic()
        self.cpu_started = time.process_time()
        self.wall, self.cpu, self.rss = wall, cpu, rss
        self.checks = 0

    def check(self):
        self.checks += 1
        need(time.monotonic() - self.started < self.wall, "QA_WALL_LIMIT")
        need(time.process_time() - self.cpu_started < self.cpu, "QA_CPU_LIMIT")
        need(rss_peak() <= self.rss, "QA_RSS_LIMIT")

    def report(self):
        return {"wall_seconds": time.monotonic() - self.started,
                "cpu_seconds": time.process_time() - self.cpu_started,
                "rss_peak_bytes": rss_peak(), "cooperative_checks": self.checks}


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def ordinary_file(path):
    path = Path(path)
    need(path.is_absolute() and ".." not in path.parts, "absolute normalized path required")
    for item in (path, *path.parents):
        need(not item.is_symlink(), "symlink path forbidden")
    info = path.stat()
    need(stat.S_ISREG(info.st_mode), "ordinary file required")
    return path, info


def pin_shape(value, maximum=268_435_456):
    need(type(value) is dict and set(value) == PIN_KEYS, "exact file-pin fields required")
    need(type(value["path"]) is str, "string pin path required")
    count(value["bytes"], "pin.bytes", maximum)
    sha(value["sha256"])


def read_pinned(value, budget, maximum=8_388_608, retain=True):
    """Read bounded administrative bytes; never interpret predicate semantics."""
    pin_shape(value, maximum)
    path, before = ordinary_file(value["path"])
    need(before.st_size == value["bytes"], "pinned size differs")
    digest, total = hashlib.sha256(), 0
    chunks = [] if retain else None
    with path.open("rb") as stream:
        need(identity(os.fstat(stream.fileno())) == identity(before), "open identity differs")
        while True:
            budget.check()
            block = stream.read(BLOCK_CAP)
            if not block:
                break
            total += len(block)
            need(total <= maximum and total <= value["bytes"], "file grew over bound")
            digest.update(block)
            if retain:
                chunks.append(block)
        need(identity(os.fstat(stream.fileno())) == identity(before), "open file changed")
    need(identity(path.stat()) == identity(before), "file changed while hashing")
    need(total == value["bytes"] and digest.hexdigest() == value["sha256"], "file pin mismatch")
    return b"".join(chunks) if retain else None


def decode64(value, maximum):
    need(type(value) is str and len(value) <= 4 * ((maximum + 2) // 3), "base64 field over bound")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError) as error:
        raise QAError("malformed base64") from error
    need(len(raw) <= maximum and base64.b64encode(raw).decode("ascii") == value,
         "noncanonical or oversized base64")
    return raw


def admit_raw(current, added, receipt_total=None):
    count(current, "current raw bytes")
    count(added, "added raw bytes")
    need(added <= RAW_CAP - current, "raw admission cap exceeded")
    if receipt_total is not None:
        count(receipt_total, "receipt raw bytes")
        need(added <= receipt_total - current, "receipt raw total exceeded")


def validate_receipt(receipt, mode):
    need(type(receipt) is dict and set(receipt) == RECEIPT_KEYS, "exact capture receipt fields")
    need(receipt["schema"] == SCHEMA, "capture receipt schema")
    for name in ("capture_complete", "cap_reached"):
        need(type(receipt[name]) is bool, "typed receipt Boolean: " + name)
    for name in ("raw_bytes", "encoded_bytes", "repeated_lines", "unflushed_repeated_lines",
                 "records", "raw_cap_bytes", "encoded_cap_bytes"):
        count(receipt[name], name)
    need(receipt["raw_cap_bytes"] == RAW_CAP and receipt["encoded_cap_bytes"] == ENCODED_CAP,
         "exact R9 capture caps")
    need(receipt["encoded_bytes"] <= ENCODED_CAP and
         receipt["repeated_lines"] <= RAW_CAP // len(DICTIONARY) and
         receipt["unflushed_repeated_lines"] <= REPEAT_CAP,
         "receipt counts within encoder bounds")
    sha(receipt["raw_sha256"]); sha(receipt["encoded_sha256"])
    need(decode64(receipt["diagnostic_line_base64"], len(DICTIONARY)) == DICTIONARY,
         "exact receipt dictionary")
    need(receipt["capture_error"] is None or
         (type(receipt["capture_error"]) is str and 0 < len(receipt["capture_error"]) <= 128),
         "typed capture error")
    if mode == "COMPLETE":
        need(receipt["capture_complete"] is True and receipt["cap_reached"] is False and
             receipt["capture_error"] is None and receipt["unflushed_repeated_lines"] == 0,
             "complete capture requires complete/error-free receipt")
    else:
        need(receipt["capture_complete"] is False and
             (receipt["cap_reached"] is True or receipt["capture_error"] is not None),
             "PREFIX receipt must explicitly be incomplete")


def audit_capture(encoded_pin, receipt, mode, budget):
    """Hash recorded data only. PREFIX can never become a COMPLETE finding."""
    need(mode in ("COMPLETE", "PREFIX"), "explicit capture mode required")
    pin_shape(encoded_pin, ENCODED_CAP)
    need(receipt is not None or mode == "PREFIX", "COMPLETE requires a receipt")
    if receipt is not None:
        validate_receipt(receipt, mode)
    path, before = ordinary_file(encoded_pin["path"])
    need(before.st_size == encoded_pin["bytes"] and before.st_size <= ENCODED_CAP,
         "encoded file size/cap")
    raw_hash, encoded_hash = hashlib.sha256(), hashlib.sha256()
    # One reusable allocation is less than 1 MiB. Remainders are memoryview slices.
    repeats_per_block = BLOCK_CAP // len(DICTIONARY)
    repeated_block = DICTIONARY * repeats_per_block
    repeated_view = memoryview(repeated_block)
    raw_total = repeated_total = encoded_total = records = literals = literal_total = repeat_records = 0
    ended = False
    tail_bytes = 0
    terminal = None
    with path.open("rb") as stream:
        need(identity(os.fstat(stream.fileno())) == identity(before), "encoded open identity")
        while True:
            budget.check()
            line = stream.readline(LINE_CAP + 1)
            if not line:
                break
            need(len(line) <= LINE_CAP, "JSON line exceeds bound")
            encoded_total += len(line)
            need(encoded_total <= ENCODED_CAP and encoded_total <= encoded_pin["bytes"],
                 "encoded stream exceeds admission bound")
            encoded_hash.update(line)
            need(not ended, "record or bytes after terminal end")
            if not line.endswith(b"\n"):
                need(mode == "PREFIX" and receipt is None, "truncated record")
                tail_bytes = len(line)
                break
            row = strict_json(line)
            need(type(row) is dict and type(row.get("kind")) is str, "record object/kind")
            kind = row["kind"]
            if records == 0:
                need(set(row) == {"kind", "id", "data"} and kind == "dictionary" and
                     row["id"] == "cache_lookup" and
                     decode64(row["data"], len(DICTIONARY)) == DICTIONARY, "single first dictionary")
            elif kind == "bytes":
                need(set(row) == {"kind", "data"}, "exact literal fields")
                data = decode64(row["data"], LITERAL_CAP)
                need(0 < len(data) <= LITERAL_CAP, "nonempty bounded literal")
                admit_raw(raw_total, len(data), None if receipt is None else receipt["raw_bytes"])
                budget.check()
                raw_hash.update(data)
                raw_total += len(data); literal_total += len(data); literals += 1
            elif kind == "repeat":
                need(set(row) == {"kind", "id", "count"} and row["id"] == "cache_lookup",
                     "exact repeat fields/id")
                amount = count(row["count"], "repeat.count", REPEAT_CAP)
                need(amount >= 1, "positive repeat count")
                added = amount * len(DICTIONARY)
                admit_raw(raw_total, added, None if receipt is None else receipt["raw_bytes"])
                remaining = amount
                while remaining:
                    budget.check()
                    part = min(remaining, repeats_per_block)
                    raw_hash.update(repeated_view[:part * len(DICTIONARY)])
                    remaining -= part
                raw_total += added; repeated_total += amount; repeat_records += 1
            elif kind == "end":
                need(set(row) == {"kind", "raw_bytes", "repeated_lines"}, "exact terminal fields")
                count(row["raw_bytes"], "end.raw_bytes")
                count(row["repeated_lines"], "end.repeated_lines")
                need(row["raw_bytes"] == raw_total and row["repeated_lines"] == repeated_total,
                     "terminal totals disagree with decoded totals")
                ended = True; terminal = row
            else:
                raise QAError("unknown kind, repeated dictionary, or invalid record order")
            records += 1
        need(identity(os.fstat(stream.fileno())) == identity(before), "encoded file changed while open")
    budget.check()
    need(identity(path.stat()) == identity(before), "encoded file changed during read")
    need(records >= 1, "missing dictionary")
    need(encoded_total == encoded_pin["bytes"] and encoded_hash.hexdigest() == encoded_pin["sha256"],
         "entire encoded stream pin mismatch")
    all_admitted_raw_verified = False
    if receipt is not None:
        need(encoded_total == receipt["encoded_bytes"] and
             encoded_hash.hexdigest() == receipt["encoded_sha256"] and records == receipt["records"],
             "encoded/record counts disagree with receipt")
        pending = receipt["unflushed_repeated_lines"]
        need(raw_total + pending * len(DICTIONARY) <= RAW_CAP and
             receipt["raw_bytes"] == raw_total + pending * len(DICTIONARY) and
             receipt["repeated_lines"] == repeated_total + pending,
             "receipt raw/repeat totals do not reconcile")
        if pending:
            need(mode == "PREFIX" and not ended, "unflushed repeats cannot have terminal end")
            # Never invent missing bytes from a receipt to make its digest match.
        else:
            need(raw_hash.hexdigest() == receipt["raw_sha256"], "full recorded raw digest mismatch")
            all_admitted_raw_verified = True
    if mode == "COMPLETE":
        need(ended and tail_bytes == 0 and all_admitted_raw_verified, "complete framing and raw hash required")
    return {"status": "VERIFIED_COMPLETE_CAPTURE" if mode == "COMPLETE" else "VERIFIED_PREFIX_ONLY",
            "mode": mode, "capture_complete_verified": mode == "COMPLETE",
            "all_admitted_raw_digest_verified": all_admitted_raw_verified,
            "framed_raw_bytes": raw_total, "framed_raw_sha256": raw_hash.hexdigest(),
            "encoded_bytes": encoded_total, "encoded_sha256": encoded_hash.hexdigest(),
            "records": records, "repeated_lines": repeated_total, "repeat_records": repeat_records,
            "literal_records": literals, "literal_bytes": literal_total,
            "terminal_end_present": ended, "terminal": terminal, "unparsed_tail_bytes": tail_bytes,
            "unflushed_repeats_not_reconstructed": 0 if receipt is None else receipt["unflushed_repeated_lines"],
            "maximum_reusable_raw_block_bytes": len(repeated_block),
            "scientific_outcome": "NOT_ASSESSED", "scientific_adoption_permitted": False}
