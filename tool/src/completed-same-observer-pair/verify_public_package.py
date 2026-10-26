#!/usr/bin/env python3
"""Finite package-byte / encoded-record verifier. Never reconstructs raw repeats.

This program imports only Python's standard library and executes no included
scientific sources. Full raw SHA results are inherited evidence, not reverified.
"""
import base64
import hashlib
import json
import pathlib
import sys
import zipfile

MAX_FILES = 2500
MAX_MEMBER = 64 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
DICT = b'lookup, class net.sf.javabdd.JTLVJavaFactory$BddCache\n'

def require(ok, message):
    if not ok:
        raise ValueError(message)

def pairs(values):
    out = {}
    for key, value in values:
        require(key not in out, 'duplicate JSON key')
        out[key] = value
    return out

def parse(data):
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))

def integer(value):
    return type(value) is int and value >= 0

def encoded_summary(data):
    require(len(data) <= 67108864, 'encoded limit')
    raw = repeats = literals = records = 0
    dictionary = end = False
    privacy_tail = b''
    for line in data.splitlines(keepends=True):
        require(len(line) <= 131072 and line.endswith(b'\n'), 'bounded complete line')
        row = parse(line); records += 1
        require(not end and isinstance(row, dict), 'record after end or non-object')
        kind = row.get('kind')
        if kind == 'dictionary':
            require(records == 1 and not dictionary and set(row) == {'kind','id','data'}, 'dictionary order/schema')
            require(row['id'] == 'cache_lookup', 'dictionary id')
            decoded = base64.b64decode(row['data'], validate=True)
            require(decoded == DICT, 'dictionary bytes')
            dictionary = True
        elif kind == 'bytes':
            require(dictionary and set(row) == {'kind','data'}, 'bytes schema')
            require(isinstance(row['data'], str) and len(row['data']) <= 87384, 'base64 bound')
            decoded = base64.b64decode(row['data'], validate=True)
            require(len(decoded) <= 65536 and base64.b64encode(decoded).decode() == row['data'], 'canonical literal')
            raw += len(decoded); literals += len(decoded)
        elif kind == 'repeat':
            require(dictionary and set(row) == {'kind','id','count'} and row['id'] == 'cache_lookup', 'repeat schema')
            require(integer(row['count']) and 1 <= row['count'] <= 1000000, 'repeat bounds')
            raw += len(DICT) * row['count']; repeats += row['count']
            decoded = DICT  # inspect one fixed dictionary occurrence; no expansion
        elif kind == 'end':
            require(dictionary and set(row) == {'kind','raw_bytes','repeated_lines'}, 'end schema')
            require(integer(row['raw_bytes']) and integer(row['repeated_lines']), 'end integers')
            require(row['raw_bytes'] == raw and row['repeated_lines'] == repeats, 'end arithmetic')
            end = True; decoded = b''
        else:
            raise ValueError('unknown record kind')
        require(raw <= 68719476736, 'raw arithmetic limit')
        joined = privacy_tail + decoded
        require(all(x not in joined.lower() for x in (b'/users/', b'/home/', b'/private/var/folders/', b'file:/users/')), 'capture private path')
        privacy_tail = joined[-512:]
    require(dictionary and end, 'complete framing')
    return {'encoded_bytes': len(data), 'encoded_sha256': hashlib.sha256(data).hexdigest(),
            'full_raw_bytes': raw, 'repeated_lines': repeats, 'literal_bytes': literals,
            'records': records, 'raw_digest_recomputed': False}

def main():
    require(len(sys.argv) <= 2, 'usage: python3 verify_public_package.py [archive.zip]')
    archive = pathlib.Path(sys.argv[1]) if len(sys.argv) == 2 else None
    root = pathlib.Path(__file__).resolve().parent
    if archive:
        zf = zipfile.ZipFile(archive)
        infos = zf.infolist()
        require(len(infos) <= MAX_FILES and len({x.filename for x in infos}) == len(infos), 'archive roster')
        require(all(not x.is_dir() and x.filename.startswith('r9_completed_pair/') and '..' not in pathlib.PurePosixPath(x.filename).parts for x in infos), 'archive names')
        require(all(x.file_size <= MAX_MEMBER and not x.flag_bits & 1 for x in infos), 'member bounds/encryption')
        require(sum(x.file_size for x in infos) <= MAX_TOTAL, 'archive total bound')
        names = {x.filename.removeprefix('r9_completed_pair/') for x in infos}
        def read(name):
            require(name in names, 'missing member ' + name)
            return zf.read('r9_completed_pair/' + name)  # verifies member CRC
    else:
        files = [x for x in root.rglob('*') if x.is_file()]
        require(len(files) <= MAX_FILES and not any(x.is_symlink() for x in root.rglob('*')), 'local roster')
        require(all(x.stat().st_size <= MAX_MEMBER for x in files) and sum(x.stat().st_size for x in files) <= MAX_TOTAL, 'local bounds')
        names = {x.relative_to(root).as_posix() for x in files}
        def read(name):
            require(name in names and '..' not in pathlib.PurePosixPath(name).parts, 'missing/unsafe member')
            return (root / name).read_bytes()
    manifest = parse(read('MANIFEST.json'))
    require(manifest['schema'] == 'ag-r9-public-manifest-v1', 'manifest schema')
    rows = manifest['files']; expected = {r['path'] for r in rows}
    require(len(expected) == len(rows) and names == expected | {'MANIFEST.json'}, 'exact manifest roster')
    for row in rows:
        data = read(row['path'])
        require(integer(row['bytes']) and len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'], 'member pin ' + row['path'])
    result = parse(read('RESULT_SUMMARY.json'))
    require(result['evidence_id'] == 'AG-R9-COMPLETED-SAME-OBSERVER-PAIR', 'evidence identity')
    require(result['arms']['unchanged']['returned_raw_four_fixed_point_boolean'] is False, 'unchanged Boolean')
    require(result['arms']['S01_release']['returned_raw_four_fixed_point_boolean'] is True, 'S01 Boolean')
    captures = []
    for arm in ('unchanged', 'S01_release'):
        a = result['arms'][arm]; actual = encoded_summary(read(a['encoded_capture_member']))
        for key in ('encoded_bytes','encoded_sha256','full_raw_bytes','repeated_lines','literal_bytes','records'):
            require(actual[key] == a[key], arm + ': ' + key)
        captures.append({'arm':arm, **actual})
    print(json.dumps({'status':'PASS_PACKAGE_AND_ENCODED_RECORDS_ONLY','files':len(names),
                      'captures':captures,'raw_SHA256_recomputed':False,
                      'scientific_execution':False,'adoption_or_public_release':False}, indent=2))

if __name__ == '__main__':
    main()
