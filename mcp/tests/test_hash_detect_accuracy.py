"""Offline hash shape recognition without exposing supplied material."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyber_tools.hash_detect import hash_detect


class HashDetectAccuracy(unittest.IsolatedAsyncioTestCase):
    async def test_sha_crypt_rounds_and_salt_alphabet(self):
        for prefix, size, name in (('5', 43, 'SHA256_crypt'), ('6', 86, 'SHA512_crypt')):
            with self.subTest(prefix=prefix):
                valid = await hash_detect(f'${prefix}$rounds=5000$./salt$' + 'a' * size)
                self.assertIn(name, {item['type'] for item in valid['possible_types']})
                invalid = await hash_detect(f'${prefix}$bad_salt$' + 'a' * size)
                self.assertEqual(invalid['count'], 0)

    async def test_argon2_variants_recognized_without_guessing_cracker_mode(self):
        for variant in ('argon2id','argon2i','argon2d'):
            with self.subTest(variant=variant):
                result = await hash_detect(f'${variant}$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2g')
                self.assertEqual(result['possible_types'][0]['type'], 'argon2')
                self.assertIsNone(result['possible_types'][0]['hashcat_mode'])

    async def test_hex_ambiguity_and_no_raw_input(self):
        value = 'ABCDEF0123456789' * 2
        result = await hash_detect(value)
        self.assertEqual({v['type'] for v in result['possible_types']}, {'MD5','NTLM','LM'})
        self.assertNotIn(value, str(result))
        self.assertIn('character', result['entropy_assessment'])

    async def test_invalid_bcrypt_cost_rejected(self):
        result = await hash_detect('$2b$99$' + 'a' * 53)
        self.assertEqual(result['count'], 0)

    async def test_invalid_type_and_oversize_structured(self):
        for value in (None, 12, 'a' * 4097):
            with self.subTest(value_type=type(value).__name__):
                result = await hash_detect(value)
                self.assertIn('error', result)
                self.assertNotIn('a' * 80, str(result))


if __name__ == '__main__':
    unittest.main()
