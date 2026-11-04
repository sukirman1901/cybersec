"""Synthetic local artifacts only; advisory data is mocked, no executables/network."""
import asyncio
import json
import os
from pathlib import Path
import plistlib
import struct
import tempfile
import unittest
from unittest.mock import patch

from cyber_tools.desktop_strings import desktop_strings
from cyber_tools.desktop_electron import desktop_electron
from cyber_tools.desktop_entitlements import desktop_entitlements
from cyber_tools.desktop_packages import desktop_packages


class ArtifactAccuracy(unittest.TestCase):
    def test_open_time_swaps_are_rejected(self):
        import builtins
        real_open = builtins.open
        tools = [(desktop_strings, 'swap.bin'), (desktop_electron, 'swap.js'),
                 (desktop_entitlements, 'swap.plist'), (desktop_packages, 'package.json')]
        for tool, name in tools:
            for symlink in [True, False]:
                with self.subTest(tool=tool.__name__, symlink=symlink):
                    path = self.file(name, b'original')
                    other = self.file('replacement', b'synthetic-private-replacement')
                    def swapped(file, *args, **kwargs):
                        if file == path:
                            os.unlink(path)
                            if symlink:
                                os.symlink(other, path)
                            else:
                                os.replace(other, path)
                        return real_open(file, *args, **kwargs)
                    with patch('builtins.open', side_effect=swapped):
                        result = self.call(tool, path)
                    self.assertTrue(result.get('error') or result.get('errors'))
                    self.assertIs(result.get('coverage_complete'), False)
                    self.assertIn(result.get('execution_status'), {'partial', 'not_started'})
                    self.assertNotIn('synthetic-private-replacement', json.dumps(result))
                    os.unlink(path)

    def test_safe_open_flags(self):
        real_open = os.open
        for tool, name, content in [(desktop_strings, 'flags.bin', b'ordinary'),
                                    (desktop_electron, 'flags.js', b'const x=1;'),
                                    (desktop_entitlements, 'flags.plist', plistlib.dumps({})),
                                    (desktop_packages, 'package.json', b'{}')]:
            with self.subTest(tool=tool.__name__):
                path = self.file(name, content)
                flags_seen = []
                def checked_open(file, flags, *args, **kwargs):
                    flags_seen.append(flags)
                    return real_open(file, flags, *args, **kwargs)
                with patch('os.open', side_effect=checked_open):
                    result = self.call(tool, path)
                self.assertTrue(flags_seen)
                self.assertTrue(all(flags & os.O_NOFOLLOW and flags & os.O_NONBLOCK for flags in flags_seen))
                self.assertIs(result.get('coverage_complete'), True)
                self.assertEqual(result.get('execution_status'), 'completed')

    def test_missing_inputs_have_explicit_incomplete_status(self):
        for tool in [desktop_strings, desktop_electron, desktop_entitlements, desktop_packages]:
            result = self.call(tool, str(self.root / 'missing'))
            self.assertIs(result.get('coverage_complete'), False)
            self.assertEqual(result.get('execution_status'), 'not_started')

    def test_display_truncation_is_explicit(self):
        result = self.call(desktop_strings, self.file('many.bin', b'password=fixtureprivate\0' * 51))
        self.assertEqual(len(result['findings']), 50)
        self.assertIs(result.get('coverage_complete'), False)
        self.assertEqual(result.get('execution_status'), 'partial')

    def test_package_display_truncation_is_explicit(self):
        advisory = {f'fixture-{i}': {'min_safe': '2.0.0', 'cve': 'SYNTHETIC'} for i in range(101)}
        path = self.file('package.json', json.dumps({'dependencies': {name: '1.0.0' for name in advisory}}))
        with patch('cyber_tools.desktop_packages.KNOWN_VULN_PACKAGES', advisory):
            result = self.call(desktop_packages, path)
        self.assertEqual(len(result['vulnerable_packages']), 100)
        self.assertTrue(result['truncated'])
        self.assertIs(result.get('coverage_complete'), False)
        self.assertEqual(result.get('execution_status'), 'partial')

    def test_electron_display_truncation_is_explicit(self):
        body = b'nodeIntegration: true'
        result = self.call(desktop_electron, self.asar({f'{i}.js': {'offset': '0', 'size': len(body)} for i in range(101)}, body))
        self.assertEqual(len(result['insecure_findings']), 100)
        self.assertIs(result.get('coverage_complete'), False)
        self.assertEqual(result.get('execution_status'), 'partial')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def file(self, name, content):
        path = self.root / name
        path.write_bytes(content if isinstance(content, bytes) else content.encode())
        return str(path)

    def call(self, tool, path, **kwargs):
        return asyncio.run(tool(path, **kwargs))

    def asar(self, files, body=b""):
        header = json.dumps({"files": files}).encode()
        padded = header + b"\0" * (-len(header) % 4)
        return self.file("sample.asar", struct.pack("<IIII", 4, len(padded) + 8, len(padded) + 4, len(header)) + padded + body)

    def test_strings_redacts_credentials_and_url(self):
        path = self.file("app.bin", 'api_key=ABCDEFGHIJKLMNOPQRST\0https://user:secret@example.invalid/?token=private\0')
        result = self.call(desktop_strings, path)
        self.assertTrue(result["findings"])
        for value in ["ABCDEFGHIJKLMNOPQRST", "user:secret", "token=private"]:
            self.assertNotIn(value, json.dumps(result))

    def test_strings_false_positives_and_information_risk(self):
        result = self.call(desktop_strings, self.file("app.bin", 'notpassword=abcdefghi\0v999.999.999.999\0http://example.invalid\0'))
        self.assertEqual([f["type"] for f in result["findings"]], ["URL"])
        self.assertEqual(result["risk"], "INFO")

    def test_strings_json_assignments_and_valid_ip(self):
        result = self.call(desktop_strings, self.file("app.bin", '"api_key": "ABCDEFGHIJKLMNOPQRST"\x0010.0.0.1\0'))
        self.assertIn("API Key", [f["type"] for f in result["findings"]])
        self.assertIn("IP Address", [f["type"] for f in result["findings"]])

    def test_strings_secret_pattern_families(self):
        data = '\0'.join(['token=ABCDEFGHIJKLMNOPQRST', 'password=privatefixture',
                           'secret=privatefixture', '-----BEGIN PRIVATE KEY-----', 'AKIA' + 'A' * 16])
        result = self.call(desktop_strings, self.file('secrets.bin', data))
        self.assertEqual({f['type'] for f in result['findings']}, {'Token', 'Password', 'Secret', 'Private Key', 'AWS Access Key'})
        self.assertNotIn('privatefixture', json.dumps(result))

    def test_strings_invalid_min_length(self):
        path = self.file("app.bin", b"fixture")
        for value in [0, -1, True, "6", 5000]:
            with self.subTest(value=value):
                self.assertIn("error", self.call(desktop_strings, path, min_length=value))

    def test_all_tools_missing_and_wrong_input(self):
        for tool in [desktop_strings, desktop_electron, desktop_entitlements, desktop_packages]:
            for path in [None, str(self.root / "missing")]:
                with self.subTest(tool=tool.__name__, path=path):
                    self.assertIn("error", self.call(tool, path))

    def test_oversize_files_are_bounded(self):
        for tool, name in [(desktop_strings, "large.bin"), (desktop_electron, "large.js"),
                           (desktop_entitlements, "large.plist"), (desktop_packages, "package.json")]:
            path = self.file(name, b"")
            with open(path, "wb") as stream:
                stream.truncate(16 * 1024 * 1024 + 1)
            with self.subTest(tool=tool.__name__):
                with patch('builtins.open', side_effect=AssertionError('Oversize file must not be opened')):
                    result = self.call(tool, path)
                self.assertTrue(result.get("error") or result.get("errors"))
                self.assertNotEqual(result.get("risk"), "INFO")

    def test_read_errors_are_explicit_and_redacted(self):
        for tool, name in [(desktop_strings, "read.bin"), (desktop_electron, "read.js"),
                           (desktop_entitlements, "read.plist"), (desktop_packages, "package.json")]:
            path = self.file(name, b"fixture")
            with self.subTest(tool=tool.__name__), patch('builtins.open', side_effect=PermissionError('secret-error-detail')):
                result = self.call(tool, path)
                self.assertTrue(result.get('error') or result.get('errors'))
                self.assertNotIn('secret-error-detail', json.dumps(result))

    def test_strings_scan_budget_is_disclosed(self):
        result = self.call(desktop_strings, self.file('strings.bin', b'ordinary string\0' * 5001))
        self.assertTrue(result['coverage']['truncated'])
        self.assertEqual(result['total_strings'], 5000)
        self.assertEqual(result['risk'], 'UNKNOWN')

    def test_electron_object_options_and_observation_scope(self):
        result = self.call(desktop_electron, self.file("main.js", 'const w = new BrowserWindow({webPreferences: {nodeIntegration: true, contextIsolation: false}});'))
        self.assertEqual(result["total_findings"], 2)
        for finding in result["insecure_findings"]:
            self.assertEqual(finding.get("assessment"), "candidate")
            self.assertIn("coverage", finding)

    def test_electron_comments_strings_and_substrings(self):
        source = '// nodeIntegration = true\nconst x = "contextIsolation = false";\nconst mynodeIntegration = true;'
        self.assertEqual(self.call(desktop_electron, self.file("main.js", source))["total_findings"], 0)

    def test_electron_unterminated_comment_is_not_code(self):
        source = '/* unclosed comment nodeIntegration: true'
        self.assertEqual(self.call(desktop_electron, self.file('main.js', source))['total_findings'], 0)

    def test_electron_quoted_property_options(self):
        result = self.call(desktop_electron, self.file('main.js', 'const opts = {"nodeIntegration": true, \'contextIsolation\': false};'))
        self.assertEqual(result['total_findings'], 2)

    def test_electron_remaining_review_patterns(self):
        source = 'enableRemoteModule: true; w.openDevTools(); shell.openExternal(url); webContents.send(channel); const x={preload:"bridge.js"};'
        result = self.call(desktop_electron, self.file('main.js', source))
        self.assertEqual(result['total_findings'], 5)

    def test_electron_no_supported_sources_is_unknown(self):
        result = self.call(desktop_electron, self.asar({'image.png': {'offset': '0', 'size': 1}}, b'x'))
        self.assertEqual(result['risk'], 'UNKNOWN')

    def test_electron_asar_resource_limits(self):
        body = b'a' * 9000
        files = {f'{i}.js': {'size': len(body), 'offset': '0'} for i in range(1000)}
        self.assertIn('error', self.call(desktop_electron, self.asar(files, body)))
        files = {f'{i}.js': {'size': 0, 'offset': '0'} for i in range(1001)}
        self.assertIn('error', self.call(desktop_electron, self.asar(files)))

    def test_electron_malformed_archive_and_binary_header(self):
        self.assertIn('error', self.call(desktop_electron, self.file('bad.asar', b'not an archive')))

    def test_electron_asar_scans_without_extracting(self):
        body = b"nodeIntegration: true"
        path = self.asar({"main.js": {"offset": "0", "size": len(body)}}, body)
        with patch("subprocess.run", side_effect=AssertionError("No extraction executable allowed")):
            result = self.call(desktop_electron, path)
        self.assertEqual(result["total_findings"], 1)

    def test_electron_asar_rejects_traversal_links_and_bad_offsets(self):
        for files in [{"../escape.js": {"size": 1, "offset": "0"}},
                      {"main.js": {"link": "../../escape"}},
                      {"main.js": {"size": 5, "offset": "9999"}}]:
            with self.subTest(files=files), patch("subprocess.run", side_effect=AssertionError("No extraction")):
                result = self.call(desktop_electron, self.asar(files, b"x"))
                self.assertTrue(result.get("error") or result.get("errors"))

    def test_entitlements_only_boolean_true_and_redaction(self):
        values = {"com.apple.security.cs.allow-jit": True,
                  "com.apple.security.network.client": False,
                  "com.apple.security.device.camera": "private-value"}
        result = self.call(desktop_entitlements, self.file("a.plist", plistlib.dumps(values)))
        self.assertEqual(result["total_high_risk"], 1)
        self.assertNotIn("private-value", json.dumps(result))
        self.assertTrue(result.get("errors"))

    def test_entitlements_invalid_and_non_object_are_not_clean(self):
        for data in [b"not plist", plistlib.dumps(["com.apple.security.cs.allow-jit"])]:
            result = self.call(desktop_entitlements, self.file("a.plist", data))
            self.assertTrue(result.get("error") or result.get("errors"))
            self.assertNotEqual(result.get("risk"), "INFO")

    def test_entitlements_embedded_and_binary_plists(self):
        value = {"com.apple.security.cs.allow-jit": True}
        for data in [b"PREFIX" + plistlib.dumps(value) + b"TAIL", plistlib.dumps(value, fmt=plistlib.FMT_BINARY)]:
            result = self.call(desktop_entitlements, self.file("a.bin", data))
            self.assertEqual(result["total_high_risk"], 1)

    def test_directory_symlinks_do_not_escape(self):
        external = self.file("outside.plist", plistlib.dumps({"com.apple.security.cs.allow-jit": True}))
        directory = self.root / "tree"
        directory.mkdir()
        os.symlink(external, directory / "leak.plist")
        result = self.call(desktop_entitlements, str(directory))
        self.assertEqual(result["total_high_risk"], 0)
        self.assertTrue(result.get("errors"))

    def test_packages_exact_mock_advisory_candidates(self):
        advisory = {"fixture": {"min_safe": "2.0.0", "cve": "SYNTHETIC-ADVISORY"}}
        path = self.file("package.json", json.dumps({"dependencies": {"fixture": "1.0.0"}}))
        with patch("cyber_tools.desktop_packages.KNOWN_VULN_PACKAGES", advisory):
            result = self.call(desktop_packages, path)
        self.assertEqual(result["total_vulnerable"], 1)
        self.assertEqual(result["vulnerable_packages"][0].get("assessment"), "candidate")
        self.assertIn("coverage", result)

    def test_packages_ranges_urls_and_other_ecosystems_not_pinned(self):
        advisory = {"fixture": {"min_safe": "2.0.0", "cve": "SYNTHETIC-ADVISORY"}}
        with patch("cyber_tools.desktop_packages.KNOWN_VULN_PACKAGES", advisory):
            for version in ["^1.0.0", "latest", "https://user:secret@example.invalid/a", "1.0.0 || 3.0.0"]:
                result = self.call(desktop_packages, self.file("package.json", json.dumps({"dependencies": {"fixture": version}})))
                self.assertEqual(result["total_vulnerable"], 0)
                self.assertNotIn("user:secret", json.dumps(result))
            result = self.call(desktop_packages, self.file("requirements.txt", "fixture==1.0.0"))
            self.assertEqual(result["total_vulnerable"], 0)

    def test_packages_invalid_manifests_not_clean(self):
        for data in ["{", "[]", '{"dependencies": []}', '{"dependencies":{"fixture":null}}']:
            result = self.call(desktop_packages, self.file("package.json", data))
            self.assertTrue(result.get("error") or result.get("errors"))
            self.assertNotEqual(result.get("risk"), "INFO")

    def test_packages_duplicate_sections_are_not_silently_overwritten(self):
        path = self.file('package.json', '{"dependencies":{"fixture":"1.0.0"},"dependencies":{}}')
        result = self.call(desktop_packages, path)
        self.assertTrue(result.get('error') or result.get('errors'))

    def test_packages_invalid_semver_not_a_release(self):
        advisory = {'fixture': {'min_safe': '2.0.0', 'cve': 'SYNTHETIC-ADVISORY'}}
        with patch('cyber_tools.desktop_packages.KNOWN_VULN_PACKAGES', advisory):
            result = self.call(desktop_packages, self.file('package.json', '{"dependencies":{"fixture":"01.0.0"}}'))
        self.assertEqual(result['total_vulnerable'], 0)

    def test_directory_file_budgets_and_package_pruning(self):
        for i in range(101):
            self.file(f'{i}.plist', plistlib.dumps({}))
        result = self.call(desktop_entitlements, str(self.root))
        self.assertEqual(len(result['entitlements_checked']), 100)
        self.assertTrue(result['errors'])
        modules = self.root / 'node_modules'
        modules.mkdir()
        (modules / 'package.json').write_text('{"dependencies":{"fixture":"1.0.0"}}')
        result = self.call(desktop_packages, str(self.root))
        self.assertEqual(result['packages_scanned'], 0)
        self.assertTrue(result['skipped'])

    def test_packages_manifest_symlink_is_skipped(self):
        external = self.file('outside.json', '{"dependencies":{"lodash":"1.0.0"}}')
        directory = self.root / 'manifests'
        directory.mkdir()
        os.symlink(external, directory / 'package.json')
        result = self.call(desktop_packages, str(directory))
        self.assertEqual(result['total_vulnerable'], 0)
        self.assertTrue(result['errors'])


if __name__ == "__main__":
    unittest.main()
