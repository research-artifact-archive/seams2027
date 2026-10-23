#!/usr/bin/env python3
"""Verify the current anonymous distribution; execute no scientific payload."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import zipfile

MANIFEST = 'CURRENT_DISTRIBUTION_MANIFEST.json'


def need(condition, message):
    if not condition:
        raise ValueError(message)


def load_helper(root, name):
    spec = importlib.util.spec_from_file_location(name, root / 'tools' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(root):
    pending = load_helper(root, 'verify_pending_handoff')
    certificate = load_helper(root, 'verify_certificate_finite')
    manifest = pending.decode((root / MANIFEST).read_bytes())
    need(manifest['schema'] == 'current-anonymous-distribution-v2', 'Unexpected manifest schema')
    need(manifest['scientific_executions'] == 0, 'Unexpected execution claim')
    indexed = set()
    for row in manifest['files']:
        need(row['path'] != MANIFEST and row['path'] not in indexed, 'Self/duplicate manifest entry')
        pending.verify_pin(root, row)
        indexed.add(row['path'])
    found = set()
    for p in root.rglob('*'):
        if '.git' in p.relative_to(root).parts:
            continue
        need(not p.is_symlink(), 'Unexpected repository symlink')
        if p.is_file():
            found.add(str(p.relative_to(root)))
    need(found == indexed | {MANIFEST}, 'Missing or extra repository file')
    need(len(indexed) == manifest['file_count_excluding_manifest'], 'Repository count differs')
    need(not (root / manifest['superseded_current_archive']['path']).exists(), 'Superseded archive remains in current tree')

    sums = {}
    for line in (root / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split('  ', 1)
        need(name not in sums, 'Duplicate download checksum')
        need(pending.digest(pending.below(root, name)) == digest, 'Download checksum mismatch')
        sums[name] = digest
    downloads = {str(p.relative_to(root)) for d in ['archives', 'documents'] for p in (root / d).iterdir() if p.is_file()}
    need(set(sums) == downloads and len(sums) == 22, 'Download inventory differs')
    need(sum(n.startswith('archives/') for n in sums) == 12, 'Expected twelve scientific archives')

    archive_names = {}
    for expected in manifest['current_archive_descriptors']:
        path = pending.below(root, expected['path'])
        if path.name.startswith('pending-native-handoff-'):
            actual, names = pending.inspect_archive(path)
        else:
            actual, names = certificate.inspect_archive(path, expected['sha256'])
        need(actual == expected, 'Current archive descriptor differs')
        archive_names[path.name] = names

    derivative = manifest['privacy_derivative']
    with zipfile.ZipFile(pending.below(root, derivative['archive'])) as z:
        prefix = derivative['member_prefix']
        raw = z.read(prefix + 'PRIVACY_AMENDMENT.json')
        need({'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()} == derivative['amendment'], 'Amendment binding differs')
        amendment = pending.decode(raw)
        need(amendment['scientific_executions'] == 0 and amendment['new_replay_qualification'] is False, 'Invalid derivative qualification')
        inner_raw = z.read(prefix + 'saved-study-inputs/MANIFEST.json')
        need({'bytes':len(inner_raw),'sha256':hashlib.sha256(inner_raw).hexdigest()} == amendment['inner_manifest']['current_v2'], 'Current inner manifest binding differs')
        inner = pending.decode(inner_raw)
        need(inner['status'] == 'ASSEMBLED_NOT_REPLAY_QUALIFIED', 'Changed binder input status')
        inner_names = set()
        for row in inner['files']:
            name = prefix + 'saved-study-inputs/' + str(pending.safe_name(row['path']))
            need(name not in inner_names, 'Duplicate inner manifest entry')
            data = z.read(name)
            need(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'], 'Inner manifest member differs')
            inner_names.add(name)
        delivered = {n for n in z.namelist() if n.startswith(prefix + 'saved-study-inputs/')}
        need(inner_names | {prefix + 'saved-study-inputs/MANIFEST.json'} == delivered, 'Incomplete inner manifest')
        for row in amendment['historical_records_unchanged']:
            data = z.read(prefix + str(pending.safe_name(row['path'])))
            need(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'], 'Historical record binding differs')

    for name in ['EVIDENCE_READER_INDEX.json', 'CLAIM_TO_FILE_INDEX.json']:
        index = pending.decode((root / name).read_bytes())
        need(len(index['rows']) == index['reader_row_count'] == 23 and len(index['extensions']) == 9, 'Reader counts differ')
        need(index['scientific_archive_count'] == 12 and index['document_download_count'] == 10, 'Download counts differ')
        for row in index['rows']:
            descriptor = index['archive_roots'].get(row.get('archive'))
            if not isinstance(descriptor, dict) or descriptor['archive'] not in archive_names:
                continue
            names = archive_names[descriptor['archive']]
            for field in ['input_navigation', 'saved_outputs', 'checkers']:
                for member in row.get(field, []):
                    need(descriptor['member_prefix'] + str(pending.safe_name(member)) in names, 'Missing current reader reference')
        need(index['current_distribution']['manifest'] == MANIFEST, 'Missing current distribution pointer')
    need((root/'EVIDENCE_READER_INDEX.json').read_bytes() == (root/'CLAIM_TO_FILE_INDEX.json').read_bytes(), 'Index mirrors differ')
    return {'status':'PASS_CURRENT_DISTRIBUTION_INTEGRITY_ONLY','repository_files':len(found),'scientific_archives':12,'document_downloads':10,'current_archive_manifests_checked':3,'scientific_code_executed':False,'new_replay_qualification':False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    print(json.dumps(verify(args.repository.resolve()), indent=2))
