#!/usr/bin/env python3
"""Check distribution bytes and metadata only; never import scientific checkers."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import unicodedata
import zipfile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pin(data, row):
    require(len(data) == row['bytes'] and digest(data) == row['sha256'],
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
            if i.is_dir():
                safe(i.filename.rstrip('/'))
                continue
            safe(i.filename)
            require(not stat.S_ISLNK(i.external_attr >> 16), 'ZIP symlink')
            require(not i.flag_bits & 1, 'encrypted ZIP member')
            out[i.filename] = z.read(i)
        return out


def check_manifest(container, manifest_name, prefix):
    manifest = json.loads(container[manifest_name])
    rows = manifest['files']
    names = [prefix + safe(r['path']) for r in rows]
    require(len(names) == len(set(names)), 'duplicate manifest entry')
    require(set(container) == set(names) | {manifest_name}, 'ZIP manifest roster mismatch')
    for row, name in zip(rows, names):
        pin(container[name], row)
    return manifest


def verify(root):
    root = Path(root).resolve()
    name = 'CURRENT_DISTRIBUTION_MANIFEST.json'
    m = json.loads((root / name).read_text())
    require(m['schema'] == 'current-anonymous-distribution-v3', 'unexpected current schema')
    require(m['scientific_executions_for_publication'] == 0, 'publication execution scope')
    require(m['version_tag'] == 'pending-diagnostic-evidence-20261023-v1', 'version tag')
    actual = {}
    for p in root.rglob('*'):
        if '.git' in p.relative_to(root).parts:
            continue
        require(not p.is_symlink(), 'repository symlink: ' + str(p))
        if p.is_file():
            actual[safe(p.relative_to(root).as_posix())] = p.read_bytes()
    rows = m['files']
    names = [safe(r['path']) for r in rows]
    require(len(names) == len(set(names)), 'duplicate inventory entry')
    require(set(actual) == set(names) | {name}, 'repository roster mismatch')
    require(m['file_count_excluding_manifest'] == len(rows), 'inventory count')
    for row in rows + m['preserved_prior_files']:
        pin(actual[row['path']], row)
    require(len(m['preserved_prior_files']) == 295, 'prior preserved file count')
    archives = sorted(n for n in actual if n.startswith('archives/') and n.endswith('.zip'))
    docs = sorted(n for n in actual if n.startswith('documents/') and n.endswith(('.pdf', '.zip')))
    require(len(archives) == 13 and len(docs) == 10, 'download counts')
    sums = '\n'.join(digest(actual[n]) + '  ' + n for n in sorted(archives + docs)) + '\n'
    require(actual['SHA256SUMS'] == sums.encode(), 'download checksum roster')
    require(actual['EVIDENCE_READER_INDEX.json'] == actual['CLAIM_TO_FILE_INDEX.json'], 'index mirror')
    index = json.loads(actual['EVIDENCE_READER_INDEX.json'])
    require(index['reader_row_count'] == len(index['rows']) == 25, 'reader row count')
    require(index['scientific_archive_count'] == 13 and index['document_download_count'] == 10,
            'reader download count')
    require(len(index['extensions']) == 10, 'extension count')
    require(digest(json.dumps(index['rows'][:23], sort_keys=True, ensure_ascii=False,
                             separators=(',', ':')).encode()) == m['historical_index_objects']['rows_sha256'],
            'historical row values changed')
    require(digest(json.dumps(index['extensions'][:9], sort_keys=True, ensure_ascii=False,
                             separators=(',', ':')).encode()) == m['historical_index_objects']['extensions_sha256'],
            'historical extension values changed')
    d = json.loads(actual['PENDING_DIAGNOSTIC_MANIFEST.json'])
    pin(actual[d['archive']['path']], d['archive'])
    outer = members(actual[d['archive']['path']])
    require(len(outer) == 8, 'outer ZIP file count')
    prefix = d['member_prefix']
    pin(outer[prefix + 'DELIVERY_MANIFEST.json'], d['delivery_manifest'])
    check_manifest(outer, prefix + 'DELIVERY_MANIFEST.json', prefix)
    inner_bytes = outer[prefix + 'pending-diagnostic-evidence-v1.zip']
    pin(inner_bytes, d['tested_inner_archive'])
    inner = members(inner_bytes)
    require(len(inner) == 76, 'inner kit file count')
    inner_prefix = 'pending-diagnostic-evidence-v1/'
    pin(inner[inner_prefix + 'MANIFEST.json'], d['tested_inner_manifest'])
    check_manifest(inner, inner_prefix + 'MANIFEST.json', inner_prefix)
    attestation = json.loads(outer[prefix + 'VALIDATION_ATTESTATION.json'])
    require(attestation['status'] == 'PASS_RELOCATED_SAVED_EVIDENCE_RECHECK', 'recorded status')
    require(attestation['new_controller_executions'] == attestation['new_native_exports']
            == attestation['saved_BDD_reexecutions'] == 0, 'recorded execution scope')
    require(m['publication_mode'] == 'evidence-only', 'publication mode')
    require('SELECTED_DOCUMENT_SNAPSHOT_MANIFEST.json' not in actual, 'unexpected document snapshot')
    return {'status': 'PASS_METADATA_AND_BYTE_INTEGRITY_ONLY', 'repository_files': len(actual),
            'preserved_prior_files': len(m['preserved_prior_files']), 'scientific_archives': len(archives),
            'document_downloads': len(docs), 'outer_files': len(outer), 'inner_files': len(inner),
            'scientific_executions': 0, 'publication_mode': 'evidence-only'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    print(json.dumps(verify(args.root), indent=2))
