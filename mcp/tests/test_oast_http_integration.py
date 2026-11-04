"""Actual loopback callback round trip; no external OOB service."""
import importlib
import json
import sys
import unittest
from pathlib import Path
from urllib.request import urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class OastIntegration(unittest.TestCase):
    def test_callback_roundtrip_and_shutdown(self):
        m = importlib.import_module('cyber_tools.oast_callback_server')
        try:
            started = json.loads(m.oast_callback_server('start'))
            self.assertEqual(started.get('status'), 'listening')
            entry = json.loads(m.oast_callback_server('generate'))
            self.assertNotIn('dns', entry['oob_urls'])
            self.assertEqual(entry['reachability'], 'loopback_only')
            with urlopen(entry['oob_urls']['http'], timeout=2) as response:
                self.assertEqual(response.status, 204)
            result = json.loads(m.oast_callback_server('poll', callback_id=entry['callback_id'], max_wait=0))
            self.assertTrue(result['received'])
            self.assertEqual(result['hits'][0]['callback_id'], entry['callback_id'])
        finally:
            m.oast_callback_server('stop')
        self.assertEqual(json.loads(m.oast_callback_server('status'))['status'], 'stopped')


if __name__ == '__main__':
    unittest.main()
