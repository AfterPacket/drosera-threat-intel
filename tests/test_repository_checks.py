"""Sample-free, offline negative tests for the repository release gates."""
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tools'))
import check_repository as checks


class FeedTests(unittest.TestCase):
    def test_valid_and_comments(self):
        self.assertEqual(checks.parse_feed('# note\n8.8.8.8\nexample.invalid\n'),
                         ['8.8.8.8', 'example.invalid'])

    def test_invalid_entries_fail_closed(self):
        for value in ['8.8.8.8\n8.8.8.8', '10.0.0.1', '127.0.0.1', '224.0.0.1',
                      '8.8.8.0/24', 'https://example.invalid/a', '*.workers.dev',
                      '999.1.2.3', '-bad.invalid', 'bad_.invalid', 'UPPER.invalid', '']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                checks.parse_feed(value)

    def test_protected_values_fail(self):
        for value in checks.PROTECTED:
            with self.subTest(value=value), self.assertRaises(ValueError):
                checks.parse_feed(value)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'bundle.zip'
        self.expected = {'README.md': b'fixture\n', 'yara/test.yar': b'harmless text\n'}

    def test_build_is_deterministic(self):
        self.assertEqual(checks.build_bundle(self.path, self.expected), 2)
        first = self.path.read_bytes()
        checks.build_bundle(self.path, self.expected)
        self.assertEqual(self.path.read_bytes(), first)

    def test_stale_bytes_rejected(self):
        checks.build_bundle(self.path, {**self.expected, 'README.md': b'stale\n'})
        with self.assertRaises(ValueError):
            checks.verify_bundle(self.path, self.expected)

    def test_missing_or_unsafe_member_rejected(self):
        for content in [{'README.md': b'fixture\n'},
                        {**self.expected, 'samples/fixture.bin': b'not malware'},
                        {**self.expected, '../escape.txt': b'fixture'}]:
            with self.subTest(names=list(content)):
                # Deliberately malformed archive fixture, never extracted.
                with zipfile.ZipFile(self.path, 'w') as archive:
                    for name, data in content.items():
                        archive.writestr(name, data)
                with self.assertRaises(ValueError):
                    checks.verify_bundle(self.path, self.expected)

    def test_unsafe_staged_input_rejected(self):
        for name in ['tools/fixture.bin', 'reports/fixture.zip', 'reports/fixture.exe',
                     'tools/fixture.BIN', 'tools/__pycache__/x.pyc']:
            with self.subTest(name=name), patch.object(checks.subprocess, 'check_output',
                                                       return_value=(name+'\0').encode()):
                with self.assertRaises(ValueError):
                    checks.canonical_inputs(Path(self.temp.name))


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ['README.md', 'blocklist.txt', 'index.html',
                     'firewalla/drosera_block.txt', 'reports/DEEP_STATIC_BATCH1_coverage.csv']:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, path)
        shutil.copytree(ROOT / 'suricata', self.root / 'suricata')
        (self.root / 'samples').mkdir()
        # Empty filename placeholders only; encrypted archives are NOT read/extracted.
        for path in (ROOT / 'samples').glob('*.zip'):
            (self.root / 'samples' / path.name).touch()

    def test_metadata_positive(self):
        self.assertEqual(checks.check_metadata(self.root)['coverage_rows'], 96)

    def test_feed_parity_failure(self):
        with (self.root / 'blocklist.txt').open('a') as handle:
            handle.write('example.invalid\n')
        with self.assertRaisesRegex(ValueError, 'mismatch'):
            checks.check_metadata(self.root)

    def test_duplicate_sid_failure(self):
        path = self.root / 'suricata/mirai_ohshit.rules'
        path.write_text(path.read_text(encoding='utf-8').replace('sid:9001002;', 'sid:9001001;'),
                        encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'SIDs'):
            checks.check_metadata(self.root)

    def test_website_count_drift_failure(self):
        path = self.root / 'index.html'
        path.write_text(path.read_text(encoding='utf-8').replace('>7/15<', '>7/16<'), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'architecture'):
            checks.check_metadata(self.root)

    def test_review_state_drift_failure(self):
        path = self.root / 'reports/DEEP_STATIC_BATCH1_coverage.csv'
        path.write_text(path.read_text(encoding='utf-8').replace('PENDING_DEEP_REVIEW',
                        'SOURCE_REVIEW_COMPLETE', 1), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'Review-state'):
            checks.check_metadata(self.root)


if __name__ == '__main__':
    unittest.main()
