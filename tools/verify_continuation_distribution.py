#!/usr/bin/env python3
"""Verify distribution metadata and exact bytes without executing scientific code."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import unicodedata
import zipfile

TAG = 'continuation-evidence-20261024-v1'
MANIFEST = 'CURRENT_DISTRIBUTION_MANIFEST.json'
DESCRIPTOR = 'CONTINUATION_EVIDENCE_MANIFEST.json'
ARCHIVE = 'archives/continuation-evidence-20261024-v1.zip'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def objects_sha(value):
    return sha(json.dumps(value, sort_keys=True, ensure_ascii=False,
                          separators=(',', ':')).encode())


def pin(data, row):
    require(len(data) == row['bytes'] and sha(data) == row['sha256'],
            'byte identity mismatch: ' + row['path'])


def safe(name):
    p = PurePosixPath(name)
    require(name and not p.is_absolute() and '\\' not in name
            and all(x not in ('', '.', '..') for x in name.split('/'))
            and unicodedata.normalize('NFC', name) == name
            and not re.match(r'^[A-Za-z]:', name), 'unsafe path: ' + name)
    return name


def members(data):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        infos = z.infolist()
        require(len(infos) == len({x.filename for x in infos}), 'duplicate ZIP name')
        require(z.testzip() is None, 'ZIP CRC failure')
        out = {}
        for i in infos:
            safe(i.filename.rstrip('/') if i.is_dir() else i.filename)
            require(not stat.S_ISLNK(i.external_attr >> 16), 'ZIP symlink')
            require(not i.flag_bits & 1, 'encrypted ZIP member')
            if not i.is_dir():
                out[i.filename] = z.read(i)
        return out


def verify(root):
    root = Path(root).resolve()
    m = json.loads((root / MANIFEST).read_text())
    require(m['schema'] == 'current-anonymous-distribution-v4', 'unexpected schema')
    require(m['version_tag'] == TAG and m['publication_mode'] == 'evidence-only',
            'publication identity')
    require(m['scientific_executions_for_publication'] == 0, 'publication scope')
    actual = {}
    for p in root.rglob('*'):
        rel = p.relative_to(root)
        if '.git' in rel.parts:
            continue
        require(not p.is_symlink(), 'repository symlink: ' + str(p))
        if p.is_file():
            actual[safe(rel.as_posix())] = p.read_bytes()
    rows = m['files']
    names = [safe(r['path']) for r in rows]
    require(len(names) == len(set(names)), 'duplicate inventory entry')
    require(set(actual) == set(names) | {MANIFEST}, 'repository roster mismatch')
    require(len(rows) == m['file_count_excluding_manifest'], 'inventory count')
    for row in rows + m['preserved_prior_files']:
        pin(actual[row['path']], row)
    require(len(m['preserved_prior_files']) == 299, 'preserved prior file count')
    require(m['publication_parent']['commit'] == '24ff3d58194c8037b8dfa64bf7c6cdb068712763',
            'unexpected baseline commit')
    require(m['removed_files'] == [], 'unexpected removal')
    archives = sorted(n for n in actual if n.startswith('archives/') and n.endswith('.zip'))
    docs = sorted(n for n in actual if n.startswith('documents/') and n.endswith(('.pdf', '.zip')))
    require(len(archives) == m['scientific_archive_count'] == 14, 'archive count')
    require(len(docs) == m['document_download_count'] == 10, 'document count')
    sums = ''.join(sha(actual[n]) + '  ' + n + '\n' for n in sorted(archives + docs))
    require(actual['SHA256SUMS'] == sums.encode(), 'download checksum roster')
    require(actual['EVIDENCE_READER_INDEX.json'] == actual['CLAIM_TO_FILE_INDEX.json'],
            'index mirror differs')
    index = json.loads(actual['EVIDENCE_READER_INDEX.json'])
    require(index['reader_row_count'] == len(index['rows']) == 26, 'reader row count')
    require(len(index['extensions']) == 11, 'extension count')
    require(index['scientific_archive_count'] == 14 and index['document_download_count'] == 10,
            'reader download counts')
    require(objects_sha(index['rows'][:25]) == m['historical_index_objects']['rows_sha256'],
            'historical row values changed')
    require(objects_sha(index['extensions'][:10]) == m['historical_index_objects']['extensions_sha256'],
            'historical extension values changed')
    d = json.loads(actual[DESCRIPTOR])
    require(d['version_tag'] == TAG and d['archive']['path'] == ARCHIVE, 'descriptor identity')
    require(d['scientific_executions_for_publication'] == 0, 'descriptor scope')
    pin(actual[ARCHIVE], d['archive'])
    packed = members(actual[ARCHIVE])
    zipped_rows = d['archive_members']
    require(len(zipped_rows) == d['archive_file_count'], 'archive member count')
    require(len(zipped_rows) == len({r['path'] for r in zipped_rows}), 'duplicate archive row')
    require(set(packed) == {safe(r['path']) for r in zipped_rows}, 'archive roster mismatch')
    for row in zipped_rows:
        pin(packed[row['path']], row)
    prefix = d['member_prefix']
    require(prefix.endswith('/'), 'member prefix')
    safe(prefix[:-1])
    require(all(n.startswith(prefix) for n in packed), 'archive member outside prefix')
    for row in d['reader_entrypoints'] + d['recorded_qualification']:
        pin(packed[prefix + safe(row['path'])], row)
    latest = index['rows'][-1]
    require(latest['id'] == 'continuation-evidence-current-entrypoint', 'new reader row identity')
    require(latest['input_navigation'] == [r['path'] for r in d['reader_entrypoints']],
            'new reader navigation differs')
    require(latest['saved_outputs'] == [r['path'] for r in d['recorded_qualification']],
            'new qualification navigation differs')
    require(index['current_distribution']['validator'] == 'tools/verify_continuation_distribution.py',
            'current validator navigation')
    require('SELECTED_DOCUMENT_SNAPSHOT_MANIFEST.json' not in actual,
            'unexpected new document snapshot')
    return {'status': 'PASS_METADATA_AND_BYTE_INTEGRITY_ONLY', 'version_tag': TAG,
            'repository_files': len(actual), 'preserved_prior_files': 299,
            'scientific_archives': len(archives), 'historical_document_downloads': len(docs),
            'new_archive_members': len(packed), 'reader_rows': 26, 'extension_objects': 11,
            'scientific_executions': 0, 'publication_mode': 'evidence-only',
            'qualification_scope': 'Recorded qualification is byte-bound, not reexecuted by this checker.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    print(json.dumps(verify(args.root), indent=2))
