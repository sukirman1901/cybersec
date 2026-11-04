"""Offline regressions; all credentials and token claims are synthetic."""
import asyncio
import base64
import json
import unittest
from unittest.mock import patch

from cyber_tools.jwt_analyze import jwt_analyze
from cyber_tools.hash_analyze import hash_analyze


def token(header, payload, signature="c2ln"):
    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    return f"{encode(header)}.{encode(payload)}.{signature}"


class OfflineCryptoAccuracy(unittest.TestCase):
    def test_oversize_jwt_stops_before_split_or_decode(self):
        class UnsplitString(str):
            def split(self, *args, **kwargs):
                raise AssertionError("Oversize input must not be split")

        with patch("cyber_tools.jwt_analyze._decode", side_effect=AssertionError("Must not decode")) as decode:
            result = asyncio.run(jwt_analyze(UnsplitString("x" * (65536 + 1))))
        self.assertEqual(result.get("error_code"), "input_too_large")
        self.assertNotIn("x" * 20, json.dumps(result))
        decode.assert_not_called()

    def test_oversize_hash_stops_before_strip_or_regex(self):
        class UnstrippedString(str):
            def strip(self, *args, **kwargs):
                raise AssertionError("Oversize input must not be stripped")

        with patch("cyber_tools.hash_analyze.re.fullmatch", side_effect=AssertionError("Must not match")) as match:
            result = asyncio.run(hash_analyze(UnstrippedString("x" * (4096 + 1))))
        self.assertEqual(result.get("error_code"), "input_too_large")
        self.assertNotIn("x" * 20, json.dumps(result))
        match.assert_not_called()

    def test_size_limits_are_inclusive(self):
        for function, limit in [(jwt_analyze, 65536), (hash_analyze, 4096)]:
            with self.subTest(function=function.__name__):
                result = asyncio.run(function("x" * limit))
                self.assertNotEqual(result.get("error_code"), "input_too_large")

    def test_each_jwt_issue_is_scoped_observation(self):
        for payload in [{}, {"exp": 0, "nbf": 9999999999, "iat": 9999999999},
                        {"exp": "invalid", "iat": False, "nbf": None}]:
            with self.subTest(payload=payload):
                result = self.jwt(header={"alg": "none"}, payload=payload, signature="")
                self.assertTrue(result["issues"])
                for issue in result["issues"]:
                    self.assertEqual(issue.get("assessment"), "observation")
                    self.assertIn(issue.get("confidence"), {"low", "medium", "high"})
                    self.assertIn("server acceptance not tested", issue.get("coverage", ""))

    def jwt(self, header=None, payload=None, signature="c2ln"):
        return asyncio.run(jwt_analyze(token(
            {"alg": "HS256"} if header is None else header,
            {"exp": 2000, "iat": 0} if payload is None else payload,
            signature,
        )))

    def test_decoding_is_not_verification(self):
        result = self.jwt()
        self.assertIs(result.get("signature_verified"), False)
        self.assertNotIn("confusion", json.dumps(result["issues"]).lower())

    def test_non_object_json_is_rejected(self):
        for h, p in [([], {}), ({}, []), (None, None), ("secret", {})]:
            with self.subTest(h=h, p=p):
                result = asyncio.run(jwt_analyze(token(h, p)))
                self.assertIn("error", result)

    def test_invalid_encoding_is_rejected(self):
        valid = token({"alg": "HS256"}, {})
        for value in ["!" + valid, valid + "!", valid.rsplit(".", 1)[0] + ".a"]:
            with self.subTest(value=value):
                self.assertIn("error", asyncio.run(jwt_analyze(value)))

    def test_errors_do_not_echo_token(self):
        result = asyncio.run(jwt_analyze("synthetic-sensitive-token"))
        self.assertNotIn("synthetic-sensitive-token", json.dumps(result))

    def test_duplicate_claims_are_rejected(self):
        raw = base64.urlsafe_b64encode(b'{"exp":0,"exp":9999999999}').decode().rstrip("=")
        header = token({"alg": "HS256"}, {}).split(".")[0]
        self.assertIn("error", asyncio.run(jwt_analyze(f"{header}.{raw}.c2ln")))

    def test_nonstandard_json_constants_are_rejected(self):
        self.assertIn("error", self.jwt(payload={"custom": float("nan")}))

    def test_invalid_input_types(self):
        for function in [jwt_analyze, hash_analyze]:
            for value in [None, 123, [], b"secret"]:
                with self.subTest(function=function.__name__, value=value):
                    self.assertIn("error", asyncio.run(function(value)))

    def test_numeric_dates_and_boundary(self):
        with patch("time.time", return_value=1000):
            result = self.jwt(payload={"exp": 1000, "iat": 0, "nbf": 1001})
        issues = json.dumps(result["issues"]).lower()
        self.assertIn("expired", issues)
        self.assertIn("not yet", issues)
        self.assertNotIn("no issued", issues)

    def test_zero_exp_is_present_and_expired(self):
        result = self.jwt(payload={"exp": 0, "iat": 0})
        issues = json.dumps(result["issues"]).lower()
        self.assertIn("expired", issues)
        self.assertNotIn("no expiration", issues)

    def test_invalid_numeric_dates(self):
        for value in [True, "2000", None, [], float("inf"), float("nan")]:
            with self.subTest(value=value):
                result = self.jwt(payload={"exp": value})
                self.assertTrue("error" in result or "invalid" in json.dumps(result["issues"]).lower())

    def test_future_iat_and_valid_fractional_dates(self):
        with patch("time.time", return_value=1000):
            result = self.jwt(payload={"exp": 1000.5, "iat": 1001})
        self.assertIn("future", json.dumps(result["issues"]).lower())
        self.assertNotIn("expired", json.dumps(result["issues"]).lower())

    def test_redacts_claims_and_signature(self):
        result = self.jwt(header={"alg": "HS256", "kid": "private-key-id"},
                          payload={"email": "fixture@example.invalid", "nested": {"access_token": "secret-value"}})
        serialized = json.dumps(result)
        for secret in ["fixture@example.invalid", "secret-value", "private-key-id", "c2ln"]:
            self.assertNotIn(secret, serialized)
        self.assertIn("header", result)
        self.assertIn("payload", result)

    def test_algorithm_structure(self):
        for header, signature in [({}, "c2ln"), ({"alg": []}, "c2ln"), ({"alg": "HS256"}, ""), ({"alg": "none"}, "c2ln")]:
            with self.subTest(header=header, signature=signature):
                self.assertIn("error", self.jwt(header=header, signature=signature))
        self.assertTrue(self.jwt(header={"alg": "none"}, signature="")["issues"])

    def test_hex_is_ambiguous_and_case_insensitive(self):
        result = asyncio.run(hash_analyze("A" * 32))
        types = {m["type"] for m in result["matches"]}
        self.assertTrue({"md5", "ntlm", "lm"}.issubset(types))
        self.assertTrue(all(m["confidence"] != "high" for m in result["matches"]))
        self.assertEqual(result["crack_command"], "")

    def test_crypt_formats_accept_variable_salts_and_rounds(self):
        for value, expected in [("$1$s$" + "a" * 22, "md5-crypt"),
                                ("$5$rounds=5000$salt$" + "a" * 43, "sha256-crypt"),
                                ("$6$s$" + "a" * 86, "sha512-crypt"),
                                ("$2b$12$" + "a" * 53, "bcrypt")]:
            with self.subTest(expected=expected):
                self.assertEqual(asyncio.run(hash_analyze(value))["matches"][0]["type"], expected)

    def test_malformed_hashes_have_no_cracking_default(self):
        for value in ["?" * 32, "$NT$" + "z" * 32, "$2b$12$" + "a" * 53 + "junk", "a" * 41]:
            with self.subTest(value=value):
                result = asyncio.run(hash_analyze(value))
                self.assertEqual(result["matches"][0]["type"], "unknown")
                self.assertEqual(result["hashcat_mode"], [])
                self.assertEqual(result["crack_command"], "")

    def test_hash_and_key_evidence_is_redacted(self):
        for value in ["ghp_" + "A" * 36, "a" * 32, "AKIA" + "A" * 16]:
            with self.subTest(value=value):
                result = asyncio.run(hash_analyze(value))
                self.assertNotIn(value[:20], json.dumps(result))


if __name__ == "__main__":
    unittest.main()
