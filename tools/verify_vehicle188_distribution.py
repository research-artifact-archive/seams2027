#!/usr/bin/env python3
"""Check distribution metadata and saved bytes; execute no scientific payload."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import unicodedata
import zipfile

sys.dont_write_bytecode = True
TAG = 'vehicle188-native-evidence-20261024-v1'
MANIFEST = 'CURRENT_DISTRIBUTION_MANIFEST.json'
DESCRIPTOR = 'VEHICLE188_NATIVE_EVIDENCE_MANIFEST.json'
GUIDE = 'VEHICLE188_NATIVE_EVIDENCE.md'
ARCHIVE = 'archives/' + TAG + '.zip'
VALIDATOR = 'tools/verify_vehicle188_distribution.py'
PARENT = '42c64f7348d27e3c930eca82a49cd797e15210ba'
ROW_ID = 'vehicle188-native-strict-selected-state'
ROWS_SHA = 'a15e9ebecff5445f04dbcc61302da99b41e8d1cfc95b3544b3aa6c5358b3a545'
EXTENSIONS_SHA = 'f56b95f04a9b7febf7a4845185e20ebd5a0f018d51c9ae85f8fa315ca923bfe2'
INNER_MANIFEST_SHA = '066ed7c22c0276c2a2575990d67bf3189ee19c720dbfb443dcca50661595eeb7'
PARENT_TAGS = {
    'artifact-identities-20261020-v1': '6dfcf9a3240f74390058b6f08c262d50d032626b',
    'certificate-finite-evidence-20261023-v1': '4d4f4e4425b06eb772c41fe6af5359d22a3727eb',
    'certificate-finite-evidence-20261023-v2': '3b7c7be60bac7f1c1af928ff9b596a36323de60a',
    'continuation-evidence-20261024-v1': PARENT,
    'guard-evidence-20261021-v1': '8bf5d18fd0803d78c5c4afc3d8349ae0a6e137d3',
    'intruder-bounded-evidence-20261021-v1': '1dbc6928f93813495f0dbbc52cd51822deaf5259',
    'lift-causal-evidence-20261021-v1': '8eec7ac8812a734e1f5813885a4b7bcdd30b9a86',
    'minepump-records-20261020-v1': '4ca771169a4d32f99ca4d7a5067413941cef0161',
    'native-regeneration-evidence-20261021-v1': 'ad64eecbe0767e6b003b92cac43b3456c1509295',
    'noninitial-handoff-evidence-20261021-v1': 'd4ae88d916acb85920b2772a85acdf3f74fea6ea',
    'normalized-eleven-evidence-20261021-v1': 'b53454bb9e4e74f878a04cf2bc023bc07f23429c',
    'pending-diagnostic-evidence-20261023-v1': '24ff3d58194c8037b8dfa64bf7c6cdb068712763',
    'pending-native-handoff-evidence-20261023-v1': 'd510bebdadc9862165205a693c5e4f00861a43c0',
    'pending-native-handoff-evidence-20261023-v2': '3b7c7be60bac7f1c1af928ff9b596a36323de60a',
    'reader-index-20261020-v2': 'a168657bd86f2ad53d12769238fd01133ee83e49',
    'residual-census-evidence-20261021-v1': 'c4766884d152de2dfa1a13f732ae668af2df8d65',
    'saved-evidence-20261020-v1': '9d70c917f3dc5cdfc8ddde5354221da9e7ab30eb',
}
MODIFIED = {
    'README.md', 'CLAIM_TO_FILE_INDEX.json', 'EVIDENCE_READER_INDEX.json',
    'EVIDENCE_READER_INDEX.txt', 'THIRD_PARTY_NOTICES.md', 'SHA256SUMS',
    MANIFEST, 'CONTINUATION_EVIDENCE.md',
}
ADDED = {ARCHIVE, GUIDE, DESCRIPTOR, VALIDATOR}


class VerificationError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise VerificationError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def objects_sha(value):
    return sha(json.dumps(value, sort_keys=True, ensure_ascii=False,
                          separators=(',', ':')).encode('utf-8'))


def decode(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def safe(name):
    require(isinstance(name, str) and bool(name), 'nonempty string path required')
    require(not PurePosixPath(name).is_absolute() and '\\' not in name
            and all(p not in ('', '.', '..') for p in name.split('/'))
            and not re.match(r'^[A-Za-z]:', name)
            and not any(ord(c) < 32 or ord(c) == 127 for c in name)
            and unicodedata.normalize('NFC', name) == name,
            'unsafe relative path: ' + name)
    return name


def pin_rows(rows, label):
    require(isinstance(rows, list), label + ': expected list')
    result = {}
    for row in rows:
        require(isinstance(row, dict), label + ': expected pin object')
        name = safe(row['path'])
        require(name not in result, label + ': duplicate path: ' + name)
        require(type(row['bytes']) is int and row['bytes'] >= 0,
                label + ': invalid byte size: ' + name)
        require(isinstance(row['sha256'], str)
                and re.fullmatch(r'[0-9a-f]{64}', row['sha256']),
                label + ': invalid SHA256: ' + name)
        result[name] = row
    return result


def verify_pin(data, row):
    require(len(data) == row['bytes'] and sha(data) == row['sha256'],
            'byte identity mismatch: ' + row['path'])


def inventory(directory):
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink(), 'directory required')
    directory = directory.resolve()
    files = {}
    def visit(folder):
        for p in sorted(folder.iterdir()):
            if p.name == '.git':
                continue
            rel = safe(p.relative_to(directory).as_posix())
            require(not p.is_symlink(), 'symlink forbidden: ' + rel)
            if p.is_dir():
                visit(p)
            else:
                require(p.is_file(), 'nonregular repository member: ' + rel)
                files[rel] = p
    visit(directory)
    return files


def verify(root, overlay=None):
    actual = inventory(root)
    if overlay is not None:
        actual.update(inventory(overlay))
    require(MANIFEST in actual, 'missing current distribution manifest')
    read = lambda name: actual[safe(name)].read_bytes()
    m = decode(read(MANIFEST))
    require(m['schema'] == 'current-anonymous-distribution-v5', 'manifest schema')
    require(m['version_tag'] == TAG and m['publication_mode'] == 'evidence-only',
            'publication identity')
    require(m['scientific_executions_for_publication'] == 0, 'publication execution scope')
    require(m['current_archive_descriptor'] == DESCRIPTOR, 'current archive descriptor')
    files = pin_rows(m['files'], 'repository inventory')
    require(MANIFEST not in files and set(actual) == set(files) | {MANIFEST},
            'exact virtual repository roster')
    require(len(actual) == 314 and len(files) == m['file_count_excluding_manifest'] == 313,
            'repository inventory count')
    # Hash large historical archives incrementally; never import their contents.
    hashes = {}
    for name, row in files.items():
        h = hashlib.sha256()
        size = 0
        with actual[name].open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                size += len(block)
                h.update(block)
        hashes[name] = h.hexdigest()
        require(size == row['bytes'] and hashes[name] == row['sha256'],
                'repository pin mismatch: ' + name)
    preserved = pin_rows(m['preserved_file_pins'], 'preserved prior files')
    require(len(preserved) == 302, 'preserved prior file count')
    require(set(preserved) == set(actual) - MODIFIED - ADDED,
            'preserved prior file roster')
    for name, row in preserved.items():
        require(row['bytes'] == files[name]['bytes'] and row['sha256'] == hashes[name],
                'preserved file differs: ' + name)
    require(set(m['modified_existing_files']) == MODIFIED
            and len(m['modified_existing_files']) == len(MODIFIED), 'modified file roster')
    require(set(m['added_files']) == ADDED and len(m['added_files']) == len(ADDED),
            'added file roster')
    require(m['removed_files'] == [], 'unexpected removed files')
    parent = m['publication_parent']
    require(parent['commit'] == PARENT, 'publication parent commit')
    expected_tags = {'refs/tags/' + name + ' ' + digest
                     for name, digest in PARENT_TAGS.items()}
    require(len(parent['tags']) == 17 and set(parent['tags']) == expected_tags,
            'seventeen recorded parent tag references')
    require(parent['manifest']['path'] == MANIFEST
            and parent['manifest']['bytes'] == 139916
            and parent['manifest']['sha256'] ==
            '5bee628342c956afe71ad07a6a7c84d020fdbd6649434f74ce03aa7fa0012272',
            'recorded parent manifest identity')
    archives = sorted(n for n in actual if n.startswith('archives/') and n.endswith('.zip'))
    documents = sorted(n for n in actual if n.startswith('documents/') and n.endswith(('.pdf', '.zip')))
    require(len(archives) == m['scientific_archive_count'] == 15, 'archive count')
    require(len(documents) == m['document_download_count'] == 10, 'document count')
    sums = ''.join(hashes[n] + '  ' + n + '\n' for n in sorted(archives + documents))
    require(read('SHA256SUMS') == sums.encode('ascii'), '25-download SHA256SUMS roster')
    require(read('EVIDENCE_READER_INDEX.json') == read('CLAIM_TO_FILE_INDEX.json'),
            'reader index mirror differs')
    index = decode(read('EVIDENCE_READER_INDEX.json'))
    require(len(index['rows']) == index['reader_row_count'] == 27, 'reader row count')
    require(len(index['extensions']) == 12, 'extension object count')
    require(index['scientific_archive_count'] == 15 and index['document_download_count'] == 10,
            'reader download counts')
    require(objects_sha(index['rows'][:26]) == ROWS_SHA, 'historical reader rows changed')
    require(objects_sha(index['extensions'][:11]) == EXTENSIONS_SHA,
            'historical extension objects changed')
    require(index['archive_roots']['Vehicle188Native'] ==
            {'archive': TAG + '.zip', 'member_prefix': TAG + '/'}, 'new archive root')
    require(index['current_distribution']['validator'] == VALIDATOR
            and index['current_distribution']['manifest'] == MANIFEST
            and index['current_distribution']['tags'] == [TAG], 'current reader navigation')
    latest = index['rows'][-1]
    require(latest['id'] == ROW_ID and latest['archive'] == 'Vehicle188Native',
            'new reader row identity')
    extension = index['extensions'][-1]
    native = index['vehicle188_native_evidence']
    for entry in (extension, native):
        require(entry['version_tag'] == TAG and entry['archive'] == ARCHIVE
                and entry['descriptor'] == DESCRIPTOR and entry['reader_guide'] == GUIDE,
                'new extension navigation')
    require(extension['claims'] == [ROW_ID], 'new extension claims')
    require(native['missing_references'] == [] and type(native['references_checked']) is int
            and native['references_checked'] > 0, 'new reference audit metadata')
    require(isinstance(native['scope'], str) and native['scope'], 'new extension scope')
    d = decode(read(DESCRIPTOR))
    require(d['version_tag'] == TAG and d['reader_guide'] == GUIDE, 'descriptor identity')
    archive = d['archive']
    require(archive['path'] == ARCHIVE and archive['root_directory'] == TAG
            and archive['member_count'] == 101, 'descriptor archive identity')
    require(archive['bytes'] == files[ARCHIVE]['bytes']
            and archive['sha256'] == hashes[ARCHIVE], 'descriptor archive pin')
    require(archive['manifest_sha256'] == INNER_MANIFEST_SHA, 'accepted inner manifest pin')
    member_pins = pin_rows(d['member_pins'], 'archive members')
    require(len(member_pins) == 101, 'descriptor member pin count')
    prefix = TAG + '/'
    with zipfile.ZipFile(actual[ARCHIVE]) as z:
        infos = z.infolist()
        require(len(infos) == len({i.filename for i in infos}), 'duplicate ZIP member')
        packed = {}
        for info in infos:
            name = safe(info.filename[:-1] if info.is_dir() else info.filename)
            require(name == TAG or name.startswith(prefix), 'ZIP member outside declared root')
            require(not info.flag_bits & 1, 'encrypted ZIP member')
            mode = info.external_attr >> 16
            require(not stat.S_ISLNK(mode), 'ZIP symlink')
            require(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR), 'ZIP special member')
            if not info.is_dir():
                require(name in member_pins, 'unlisted ZIP file: ' + name)
                require(info.file_size == member_pins[name]['bytes'], 'ZIP member size: ' + name)
                packed[name] = z.read(info)
        require(z.testzip() is None, 'ZIP CRC check')
    require(set(packed) == set(member_pins), 'exact ZIP file roster')
    for name, row in member_pins.items():
        verify_pin(packed[name], row)
    inner_bytes = packed[prefix + 'MANIFEST.json']
    require(sha(inner_bytes) == archive['manifest_sha256'], 'internal manifest identity')
    inner = decode(inner_bytes)
    require(inner['schema'] == 'vehicle188-native-evidence-manifest-v1'
            and inner['version_tag'] == TAG, 'internal manifest schema/identity')
    inner_pins = pin_rows(inner['files'], 'internal manifest')
    require('MANIFEST.json' not in inner_pins and len(inner_pins) == 100,
            'internal manifest count/self exclusion')
    require({prefix + name for name in inner_pins} | {prefix + 'MANIFEST.json'} == set(packed),
            'internal manifest exact member roster')
    for name, row in inner_pins.items():
        verify_pin(packed[prefix + name], row)
    references = set(d['reader_entrypoints']) | {d['qualification_entrypoint']}
    for key in ('input_navigation', 'input_models', 'source_inputs', 'saved_outputs',
                'checker_sources', 'checkers'):
        for name in latest.get(key, []):
            references.add(name)
    for name in references:
        require(prefix + safe(name) in packed, 'missing new reader member: ' + name)
    replay = d['replay']
    command = replay['command']
    require(isinstance(command, (str, list)) and bool(command), 'replay command metadata')
    tokens = command.split() if isinstance(command, str) else command
    require(tokens == ['python3', '-I', '-S', '-B', 'replay.py', '--bundle', '.',
                       '--out', '../vehicle188-replay-result.json'], 'declared replay command')
    require(replay['expected_status'] == 'PASS_SAVED_IDENTITY_MEMBERSHIP_INITIALIZATION',
            'declared saved replay status')
    require(isinstance(replay['scope'], str) and bool(replay['scope'])
            and isinstance(replay['limits'], (str, list)) and bool(replay['limits']),
            'replay scope and limits')
    require('SELECTED_DOCUMENT_SNAPSHOT_MANIFEST.json' not in actual,
            'unexpected manuscript/document snapshot')
    return {'status': 'PASS_METADATA_AND_BYTE_INTEGRITY_ONLY', 'version_tag': TAG,
            'repository_files': len(actual), 'preserved_prior_files': len(preserved),
            'scientific_archives': len(archives), 'historical_document_downloads': len(documents),
            'reader_rows': len(index['rows']), 'extension_objects': len(index['extensions']),
            'recorded_parent_tag_references': 17, 'new_archive_members': len(packed),
            'inner_manifest_sha256': sha(inner_bytes), 'new_reader_members_checked': len(references),
            'scientific_executions': 0, 'publication_mode': 'evidence-only',
            'scope': 'Metadata and byte integrity only. No archived code, replay, solver, '
                     'network or Git operation executed. Parent refs are recorded pins, '
                     'not a live remote-ref verification.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--overlay', type=Path,
                        help='Resolve staged files before repository files; do not modify either tree')
    args = parser.parse_args()
    try:
        report = verify(args.root, args.overlay)
    except Exception as error:
        print(json.dumps({'status': 'FAIL_METADATA_OR_BYTE_INTEGRITY',
                          'errors': [{'type': type(error).__name__, 'message': str(error)}],
                          'scientific_executions': 0}, ensure_ascii=False, indent=2))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
