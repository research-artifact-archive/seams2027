#!/usr/bin/env python3
"""Verify navigation/publication bytes and local navigation links; execute no research code.

Manifest: schema='artifact-navigation-distribution-v1', baseline_commit,
files=[{path,bytes,sha256}], legacy_files=[{original_path,published_path,bytes,sha256}],
navigation_markdown_files=[relative paths]. The manifest excludes only itself.
Legacy rows are the frozen 324-file inventory, with README.md mapped to
HISTORICAL_NAVIGATION.md. Prior tools, archives and documents are unchanged.
"""
import argparse
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

MANIFEST = 'NAVIGATION_MANIFEST.json'
BASELINE = '9e62e3d7da65de0644f6e66c27cc5f9e425aba79'
LEGACY_SHA = '820f128d49501ed31acba8dedba0174984525aadb92c0b381e3f8a1d6e08692f'

def need(ok, why):
    if not ok:
        raise ValueError(why)

def safe(name):
    need(isinstance(name, str) and name and not PurePosixPath(name).is_absolute(), 'relative file path required')
    need('\\' not in name and not re.match(r'^[A-Za-z]:', name), 'unsafe path: ' + name)
    need(all(x not in ('', '.', '..') for x in name.split('/')), 'unsafe path component: ' + name)
    need(not any(ord(c) < 32 or ord(c) == 127 for c in name) and unicodedata.normalize('NFC', name) == name, 'unsafe path text')
    return name

def digest_file(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1048576), b''):
            h.update(block)
    return h.hexdigest()

def unique(pairs):
    out = {}
    for k, v in pairs:
        need(k not in out, 'duplicate JSON key: ' + k)
        out[k] = v
    return out

def inventory(root):
    need(root.is_dir() and not root.is_symlink(), 'regular repository directory required')
    found = {}
    def visit(folder):
        for p in sorted(folder.iterdir()):
            if folder == root and p.name == '.git':
                continue
            name = safe(p.relative_to(root).as_posix())
            need(not p.is_symlink(), 'symlink forbidden: ' + name)
            if p.is_dir():
                visit(p)
            else:
                need(p.is_file(), 'nonregular file: ' + name)
                found[name] = p
    visit(root)
    return found

def rows(values, key):
    need(isinstance(values, list), 'pin list required')
    result = {}
    for v in values:
        n = safe(v[key])
        need(n not in result, 'duplicate pin: ' + n)
        need(type(v['bytes']) is int and v['bytes'] >= 0, 'invalid byte size: ' + n)
        need(isinstance(v['sha256'], str) and re.fullmatch('[0-9a-f]{64}', v['sha256']), 'invalid digest: ' + n)
        result[n] = v
    return result

def verify(repository):
    root = repository.resolve()
    actual = inventory(root)
    need(MANIFEST in actual, 'missing navigation manifest')
    m = json.loads(actual[MANIFEST].read_text(encoding='utf-8'), object_pairs_hook=unique)
    need(m['schema'] == 'artifact-navigation-distribution-v1', 'navigation schema')
    need(m['baseline_commit'] == BASELINE, 'baseline identity')
    pins = rows(m['files'], 'path')
    need(MANIFEST not in pins and set(actual) == set(pins) | {MANIFEST}, 'exact current file roster')
    for n, row in pins.items():
        need(actual[n].stat().st_size == row['bytes'] and digest_file(actual[n]) == row['sha256'], 'current file mismatch: ' + n)
    legacy = m['legacy_files']
    encoded = json.dumps(legacy, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
    need(hashlib.sha256(encoded).hexdigest() == LEGACY_SHA, 'frozen legacy pin object')
    original = rows(legacy, 'original_path')
    published = rows(legacy, 'published_path')
    need(len(original) == len(published) == 324, 'legacy file count')
    for n, row in original.items():
        dest = 'HISTORICAL_NAVIGATION.md' if n == 'README.md' else n
        need(row['published_path'] == dest and dest in pins, 'legacy mapping: ' + n)
        need(all(pins[dest][k] == row[k] for k in ('bytes', 'sha256')), 'legacy byte preservation: ' + n)
    need(len([n for n in original if n.startswith('archives/')]) == 17, 'archive count')
    need(len([n for n in original if n.startswith('documents/')]) == 10, 'historical document count')
    nav = m['navigation_markdown_files']
    need(isinstance(nav, list) and len(nav) == len(set(nav)) and 'README.md' in nav, 'navigation Markdown roster')
    checked = []
    for n in nav:
        safe(n)
        need(n in pins and n.endswith('.md'), 'navigation Markdown file: ' + n)
        text = actual[n].read_text(encoding='utf-8')
        targets = re.findall(r'\[[^\]\n]*\]\(\s*(<[^>]+>|[^\s)]+)(?:\s+"[^"]*")?\s*\)', text)
        targets += re.findall(r'(?m)^\s*\[[^\]\n]+\]:\s*(<[^>]+>|\S+)', text)
        for target in targets:
            target = target.strip('<>')
            parts = urlsplit(target)
            if parts.scheme or parts.netloc:
                need(parts.scheme in ('http', 'https', 'mailto') or (not parts.scheme and parts.netloc), 'unsupported link scheme: ' + target)
                continue
            if not parts.path:
                continue
            path = (actual[n].parent / unquote(parts.path)).resolve()
            need(path == root or root in path.parents, 'link escapes repository: ' + n + ': ' + target)
            need(path.exists(), 'missing local link target: ' + n + ': ' + target)
            checked.append({'source': n, 'target': target})
    return {'status': 'PASS_NAVIGATION_AND_FILE_INTEGRITY_ONLY', 'repository_files': len(actual),
            'legacy_files_preserved': 324, 'scientific_archives': 17, 'historical_documents': 10,
            'navigation_markdown_files': len(nav), 'local_link_targets_checked': len(checked),
            'link_scope': 'Literal inline links and reference definitions; local target existence only, not fragment anchors or remote URLs.',
            'scientific_payload_executed': False, 'Git_tag_identity_checked': False}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.repository), indent=2))
    except (ValueError, KeyError, OSError, UnicodeError, json.JSONDecodeError) as error:
        print(json.dumps({'status': 'FAIL', 'error': str(error), 'scientific_payload_executed': False}), file=sys.stderr)
        sys.exit(1)
