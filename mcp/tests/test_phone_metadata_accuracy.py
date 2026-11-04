"""Offline numbering-plan metadata; no identity lookup or service requests."""
import importlib
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
module = importlib.import_module('cyber_tools.phone_osint')


@unittest.skipUnless(module._HAS_PHONENUMBERS, 'Optional phonenumbers metadata unavailable')
class PhoneMetadataAccuracy(unittest.TestCase):
    def test_line_type_uses_library_enum_values(self):
        pn = module.phonenumbers
        for kind in (pn.PhoneNumberType.FIXED_LINE, pn.PhoneNumberType.MOBILE,
                     pn.PhoneNumberType.TOLL_FREE, pn.PhoneNumberType.PREMIUM_RATE):
            with self.subTest(kind=kind):
                example = pn.example_number_for_type('GB', kind)
                number = pn.format_number(example, pn.PhoneNumberFormat.E164)
                result = module.phone_osint(number)
                self.assertEqual(result['line_type'], pn.PhoneNumberType.to_string(kind))

    def test_country_is_country_not_area_description(self):
        result = module.phone_osint('+12025550100')
        self.assertEqual(result['country'], 'United States')
        self.assertEqual(result['assessment'], 'numbering_plan_metadata_only')
        self.assertFalse(result['identity_verified'])

    def test_invalid_number_has_no_lookup_links(self):
        result = module.phone_osint('+1202555')
        self.assertFalse(result['valid'])
        self.assertFalse(result['lookup_urls'])

    def test_invalid_input_and_oversize_never_parse(self):
        for value in (12, None, 'x' * 129):
            with self.subTest(kind=type(value).__name__), patch.object(module.phonenumbers, 'parse') as parse:
                result = module.phone_osint(value)
                self.assertIsNotNone(result['error'])
                parse.assert_not_called()

    def test_lookup_links_use_canonical_e164(self):
        result = module.phone_osint('+1 (202) 555-0100')
        self.assertTrue(result['valid'])
        for item in result['lookup_urls']:
            self.assertNotIn('(', item['url'])
            self.assertNotIn(')', item['url'])
        self.assertEqual(result['external_requests'], 0)

    def test_metadata_failure_is_structured_without_raw_error(self):
        with patch.object(module.ph_carrier, 'name_for_number', side_effect=RuntimeError('synthetic-private-value')):
            result = module.phone_osint('+12025550100')
        self.assertIsNotNone(result['error'])
        self.assertNotIn('synthetic-private-value', str(result))
        self.assertFalse(result['coverage_complete'])


if __name__ == '__main__':
    unittest.main()
