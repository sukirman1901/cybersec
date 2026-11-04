"""Offline boundary checks for legacy detector HTTP observations."""
import asyncio
import importlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import httpx

NAMES = (
    "cmd_injection", "graphql_depth_bypass", "graphql_injection", "ldap_inject",
    "lfi_detect", "log4j_scan", "nosql_inject", "ssti_detect", "xxe_detect",
    "prototype_pollution", "mass_assignment", "idor_detect",
)
CLIENT = httpx.AsyncClient


class DetectorFailureBoundaries(unittest.TestCase):
    def run_detector(self, name, handler, target="https://example.test/api", **kwargs):
        module = importlib.import_module("cyber_tools." + name)
        requests = []

        def receive(request):
            requests.append(request)
            return handler(request)

        def factory(*args, **options):
            options["transport"] = httpx.MockTransport(receive)
            return CLIENT(*args, **options)

        with patch.object(module.httpx, "AsyncClient", factory), patch.object(
            module, "GuardedAsyncClient", factory, create=True
        ):
            result = asyncio.run(getattr(module, name)(target, **kwargs))
        return result, requests

    def test_malformed_target_is_rejected_without_io(self):
        for name in NAMES:
            for target in ("", "https://[bad", "ftp://example.test", "https://user:secret@example.test", "https://example.test:bad", None):
                with self.subTest(name=name, target=target):
                    result, requests = self.run_detector(name, lambda r: httpx.Response(200), target)
                    self.assertEqual(requests, [])
                    self.assertEqual(result["execution_status"], "invalid_input")
                    self.assertIsNone(result["vulnerable"])

    def test_transport_failure_is_not_clean_negative(self):
        def fail(request):
            raise httpx.ConnectError("secret-token user@example.test", request=request)
        for name in NAMES:
            with self.subTest(name=name):
                result, requests = self.run_detector(name, fail)
                self.assertEqual(len(requests), 1)
                self.assertFalse(result["coverage_complete"])
                self.assertEqual(result["execution_status"], "partial")
                self.assertIn("ConnectError", result["errors"])
                self.assertNotIn("secret-token", json.dumps(result))
                self.assertIsNone(result["vulnerable"])

    def test_reflection_is_observed_but_not_confirmation(self):
        def reflect(request):
            return httpx.Response(200, text='{"data":{"isAdmin":true,"polluted":"polluted_test","token":"secret-token","email":"user@example.test"},"echo":' + json.dumps(request.content.decode()) + '}')
        for name in NAMES:
            with self.subTest(name=name):
                result, requests = self.run_detector(name, reflect)
                self.assertTrue(result["observations"])
                self.assertEqual(result["observations"][0]["status"], 200)
                self.assertGreater(result["observations"][0]["response_bytes"], 0)
                self.assertLessEqual(len(requests), 32)
                self.assertEqual(result["confirmed_findings"], 0)
                self.assertEqual(result["verification"], "unsupported")
                self.assertIsNone(result["vulnerable"])
                self.assertNotIn("secret-token", json.dumps(result))
                self.assertNotIn("user@example.test", json.dumps(result))

    def test_truncation_discards_incomplete_body(self):
        for name in NAMES:
            with self.subTest(name=name):
                result, requests = self.run_detector(name, lambda r: httpx.Response(200, content=b"x" * 262145))
                self.assertEqual(len(requests), 1)
                self.assertIn("body_limit_exceeded", result["errors"])
                self.assertEqual(result["observations"], [])
                self.assertFalse(result["coverage_complete"])

    def test_blocking_status_stops_without_following_redirect(self):
        for name in NAMES:
            for status in (302, 403, 429, 500):
                with self.subTest(name=name, status=status):
                    result, requests = self.run_detector(name, lambda r: httpx.Response(status, headers={"location": "https://other.test/secret"}))
                    self.assertEqual(len(requests), 1)
                    self.assertFalse(result["coverage_complete"])
                    self.assertEqual(result["confirmed_findings"], 0)

    def test_unremarkable_responses_do_not_prove_absence(self):
        for name in NAMES:
            with self.subTest(name=name):
                result, requests = self.run_detector(name, lambda r: httpx.Response(404, text="not found"))
                self.assertLessEqual(len(requests), 32)
                self.assertIsNone(result["vulnerable"])
                self.assertEqual(result["total_findings"], 0)
                self.assertTrue(result["observations"])

    def test_unbounded_arguments_are_rejected(self):
        for name, kwargs in (("idor_detect", {"ids": ",".join(map(str, range(1000)))}), ("ssti_detect", {"param": "x" * 10000}), ("xxe_detect", {"oob_domain": "x" * 10000})):
            with self.subTest(name=name):
                result, requests = self.run_detector(name, lambda r: httpx.Response(200), **kwargs)
                self.assertEqual(requests, [])
                self.assertEqual(result["execution_status"], "invalid_input")

    def test_partial_run_retains_unverified_heuristic_observations(self):
        # This JSON is reflection/static content, not proof of persistent state.
        result, requests = self.run_detector("prototype_pollution", lambda r: httpx.Response(
            200, json={"isAdmin": True, "polluted": "polluted_test", "token": "secret-token"}))
        self.assertEqual(len(requests), 32)
        self.assertIn("budget_exhausted", result["errors"])
        self.assertIn("url_param_pollution", [s["technique"] for s in result["heuristic_signals"]])
        self.assertTrue(all(s["verification"] == "unsupported" for s in result["heuristic_signals"]))
        self.assertNotIn("secret-token", json.dumps(result))

    def test_midstream_error_closes_response_and_discards_partial_evidence(self):
        class BrokenStream(httpx.AsyncByteStream):
            closed = False

            async def __aiter__(self):
                yield b"secret-token"
                raise httpx.ReadError("sensitive body interrupted")

            async def aclose(self):
                self.closed = True

        for name in NAMES:
            with self.subTest(name=name):
                stream = BrokenStream()
                result, requests = self.run_detector(name, lambda r: httpx.Response(200, stream=stream))
                self.assertEqual(len(requests), 1)
                self.assertTrue(stream.closed)
                self.assertIn("ReadError", result["errors"])
                self.assertEqual(result["observations"], [])
                self.assertNotIn("secret-token", json.dumps(result))

    def test_deadline_exhaustion_makes_no_request(self):
        from cyber_tools.surface_probe import SurfaceProbe
        original = SurfaceProbe.__init__

        def expired(probe, *args, **kwargs):
            original(probe, *args, **kwargs)
            probe.deadline = 0

        for name in NAMES:
            with self.subTest(name=name), patch.object(SurfaceProbe, "__init__", expired):
                result, requests = self.run_detector(name, lambda r: httpx.Response(200))
                self.assertEqual(requests, [])
                self.assertIn("budget_exhausted", result["errors"])
                self.assertEqual(result["execution_status"], "partial")

    def test_external_cancellation_propagates(self):
        def cancelled(request):
            raise asyncio.CancelledError

        for name in NAMES:
            with self.subTest(name=name), self.assertRaises(asyncio.CancelledError):
                self.run_detector(name, cancelled)

    def test_graphql_malformed_success_is_incomplete(self):
        for name in ("graphql_injection", "graphql_depth_bypass"):
            for body in ("{data", "null", "42", '"data"', '[]'):
                with self.subTest(name=name, body=body):
                    result, requests = self.run_detector(name, lambda r: httpx.Response(200, text=body))
                    self.assertEqual(len(requests), 1)
                    self.assertIn("malformed_response", result["errors"])
                    self.assertFalse(result["coverage_complete"])

    def test_static_indicator_is_retained_without_claiming_execution(self):
        cases = (
            ("cmd_injection", "uid=1000(test)", "basic_injection", {"param": "q"}),
            ("ssti_detect", "49", "engine_detection", {"param": "q"}),
            ("lfi_detect", "root:x:0:0:root:/root:/bin/bash", "path_traversal", {"param": "q"}),
            ("ldap_inject", "welcome", "auth_bypass", {}),
            ("nosql_inject", "welcome admin", "mongodb_json_injection", {}),
            ("xxe_detect", "root:x:0:0:root:/root:/bin/bash", "inband_xxe", {}),
            ("graphql_injection", '{"data":{"__typename":"Query"}}', "endpoint_discovery", {}),
            ("graphql_depth_bypass", '{"data":{"__typename":"Query"}}', "endpoint_detection", {}),
            ("mass_assignment", '{"role":"admin"}', "json_param_overwrite", {}),
            ("idor_detect", '{"email":"user@example.test"}', "path_idor", {}),
        )
        for name, body, signal, options in cases:
            with self.subTest(name=name):
                result, _ = self.run_detector(name, lambda r: httpx.Response(200, text=body), **options)
                self.assertIn(signal, [s["technique"] for s in result["heuristic_signals"]])
                self.assertEqual(result["confirmed_findings"], 0)
                self.assertIsNone(result["vulnerable"])
                self.assertNotIn("user@example.test", json.dumps(result))

    def test_log4j_body_boundary_is_observation_not_callback_evidence(self):
        body = b"x" * 262144
        result, requests = self.run_detector("log4j_scan", lambda r: httpx.Response(200, content=body))
        self.assertEqual(len(requests), 16)
        self.assertTrue(result["coverage_complete"])
        self.assertEqual(result["observations"][0]["response_bytes"], len(body))
        self.assertEqual(result["heuristic_signals"], [])
        self.assertEqual(result["verification"], "unsupported")
        self.assertEqual(result["confirmed_findings"], 0)


if __name__ == "__main__":
    unittest.main()
