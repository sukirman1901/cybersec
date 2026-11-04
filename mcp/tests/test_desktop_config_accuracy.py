"""Local configuration observations: redaction, scope and bounded reads."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyber_tools.desktop_config import desktop_config


class DesktopConfigAccuracy(unittest.IsolatedAsyncioTestCase):
    async def test_symlink_swap_between_stat_and_open_not_followed(self):
        import builtins
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as other:
            file = Path(folder)/'.env'
            file.write_text('safe')
            outside = Path(other)/'secret'
            outside.write_text('PASSWORD=synthetic-private-value')
            original = builtins.open
            def swapped(path, *args, **kwargs):
                file.unlink()
                file.symlink_to(outside)
                return original(path, *args, **kwargs)
            with patch('builtins.open', side_effect=swapped):
                result = await desktop_config(str(file))
            self.assertFalse(result['findings'])
            self.assertFalse(result['coverage_complete'])

    async def test_private_key_structure_not_public_certificate(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'private.pem').write_text('-----BEGIN PRIVATE KEY-----\nsynthetic-key-material\n-----END PRIVATE KEY-----\n')
            (root/'cert.pem').write_text('-----BEGIN CERTIFICATE-----\npublic-certificate-material\n-----END CERTIFICATE-----\n')
            result = await desktop_config(folder)
            self.assertEqual(len(result['findings']), 1)
            self.assertEqual(result['findings'][0]['file'], 'private.pem')
            self.assertNotIn('synthetic-key-material', json.dumps(result))

    async def test_json_env_candidates_without_secret_values(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'config.json').write_text('{"password":"synthetic-private-value"}')
            (root/'.env').write_text('API_KEY=synthetic-private-value\n')
            result = await desktop_config(folder)
            self.assertEqual(len(result['findings']), 2)
            self.assertNotIn('synthetic-private-value', json.dumps(result))
            self.assertTrue(result['coverage_complete'])
            self.assertEqual(result['files_scanned'], 2)

    async def test_filename_alone_is_not_high_risk(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder)/'config.json').write_text('{"theme":"dark"}')
            result = await desktop_config(folder)
            self.assertEqual(result['risk'], 'NO_EVIDENCE')
            self.assertFalse(result['findings'])
            self.assertTrue(result['observations'])

    async def test_external_symlink_not_read(self):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as other:
            outside = Path(other)/'secret'
            outside.write_text('PASSWORD=synthetic-private-value')
            (Path(folder)/'.env').symlink_to(outside)
            result = await desktop_config(folder)
            self.assertEqual(result['files_scanned'], 0)
            self.assertFalse(result['findings'])
            self.assertFalse(result['coverage_complete'])
            self.assertNotIn('synthetic-private-value', json.dumps(result))

    async def test_read_failure_not_silently_clean(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder)/'.env'
            file.write_text('PASSWORD=synthetic-private-value')
            with patch('builtins.open', side_effect=PermissionError):
                result = await desktop_config(str(file))
            self.assertFalse(result['coverage_complete'])
            self.assertEqual(result['files_scanned'], 0)
            self.assertEqual(result['risk'], 'INCONCLUSIVE')

    async def test_large_file_bounded_and_incomplete(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder)/'.env'
            file.write_text('x' * 262145)
            result = await desktop_config(str(file))
            self.assertFalse(result['coverage_complete'])
            self.assertIn('file_byte_limit', result['errors'])

    async def test_nonrecursive_and_actual_files_scanned_count(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'README.md').write_text('hello')
            (root/'config.json').write_text('{}')
            (root/'nested').mkdir()
            (root/'nested'/'.env').write_text('PASSWORD=synthetic-private-value')
            result = await desktop_config(folder, recursive=False)
            self.assertEqual(result['files_scanned'], 1)
            self.assertFalse(result['findings'])


if __name__ == '__main__':
    unittest.main()
