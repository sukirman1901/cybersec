"""Offline failure-boundary regressions; all external execution is mocked."""

import importlib
import sys
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

NAMES = (
    "ad_enum", "bloodhound_collect", "ad_asrep_roast", "ad_kerberoast",
    "ad_certipy", "ad_dcsync", "ad_ntlm_relay", "ad_passthehash", "ad_spray",
)
MODULES = {name: importlib.import_module(f"cyber_tools.{name}") for name in NAMES}
SECRET = "SYNTHETIC_SECRET_SENTINEL"
DOMAIN = "synthetic.invalid"
HOST = "dc.synthetic.invalid"


class ADFailureBoundaries(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Unexpected execution must fail without opening a socket or child.
        self.guards = []
        for name in ("asyncio.create_subprocess_exec", "socket.socket.connect"):
            guard = patch(name, side_effect=AssertionError("External access forbidden"))
            guard.start()
            self.guards.append(guard)
        self.addCleanup(lambda: [guard.stop() for guard in reversed(self.guards)])

    async def test_native_bind_failure_is_secret_safe(self):
        for name in ("ad_enum", "ad_asrep_roast", "ad_kerberoast"):
            with self.subTest(module=name):
                module = MODULES[name]
                with patch.object(module, "ldap_login", side_effect=RuntimeError(SECRET)) as login:
                    result = await getattr(module, name)(DOMAIN, HOST, "synthetic-user", SECRET)
                login.assert_called_once()
                self.assertTrue(result["error"])
                self.assertFalse(result["authenticated"])
                self.assertNotIn(SECRET, str(result))

    async def test_native_empty_inputs_do_not_bind(self):
        for name in ("ad_enum", "ad_asrep_roast", "ad_kerberoast"):
            with self.subTest(module=name):
                module = MODULES[name]
                with patch.object(module, "ldap_login") as login:
                    result = await getattr(module, name)(" ", HOST)
                login.assert_not_called()
                self.assertTrue(result["error"])

    async def test_enum_partial_search_failure_is_not_clean(self):
        module = MODULES["ad_enum"]
        conn = Mock()
        conn.search.side_effect = RuntimeError(SECRET)
        with patch.object(module, "ldap_login", return_value=conn):
            result = await module.ad_enum(DOMAIN, HOST, "synthetic-user", SECRET)
        self.assertTrue(result["error"])
        self.assertNotIn(SECRET, str(result))
        conn.close.assert_called_once()

    async def test_roast_partial_ldap_response_is_marked_incomplete(self):
        for name in ("ad_asrep_roast", "ad_kerberoast"):
            with self.subTest(module=name):
                module = MODULES[name]
                class LimitedSearch(Exception):
                    def getAnswers(self):
                        return []
                conn = Mock()
                conn.search.side_effect = LimitedSearch("sizeLimitExceeded " + SECRET)
                with patch.object(module, "ldap_login", return_value=conn), patch.object(module.ldap, "LDAPSearchError", LimitedSearch):
                    result = await getattr(module, name)(DOMAIN, HOST)
                self.assertIn("incomplete", result["error"])
                self.assertEqual(result["count"], 0)
                self.assertNotIn(SECRET, str(result))
                conn.close.assert_called_once()

    async def test_roast_invalid_format_does_not_bind(self):
        for name in ("ad_asrep_roast", "ad_kerberoast"):
            module = MODULES[name]
            with self.subTest(module=name), patch.object(module, "ldap_login") as login:
                with self.assertRaises(ValueError):
                    await getattr(module, name)(DOMAIN, HOST, output_format="synthetic-unsupported")
                login.assert_not_called()

    async def test_dcsync_auth_failure_is_secret_safe_and_closes(self):
        module = MODULES["ad_dcsync"]
        conn = Mock()
        conn.login.side_effect = RuntimeError(SECRET)
        with patch.object(module, "SMBConnection", return_value=conn):
            result = await module.ad_dcsync(DOMAIN, HOST, "synthetic-user", SECRET)
        self.assertTrue(result["error"])
        self.assertNotIn(SECRET, str(result))
        conn.logoff.assert_called_once()

    async def test_dcsync_invalid_inputs_do_not_connect(self):
        module = MODULES["ad_dcsync"]
        for domain, username in (("", "synthetic-user"), (DOMAIN, "")):
            with patch.object(module, "SMBConnection") as connect:
                result = await module.ad_dcsync(domain, HOST, username)
                connect.assert_not_called()
                self.assertTrue(result["error"])

    async def test_spray_invalid_bounds_do_not_authenticate(self):
        module = MODULES["ad_spray"]
        for kwargs in ({"delay": -1}, {"delay": float("nan")}, {"max_attempts": -1}, {"max_attempts": True}):
            with self.subTest(kwargs=kwargs), patch.object(module.ldap, "LDAPConnection") as connect:
                result = await module.ad_spray(DOMAIN, HOST, SECRET, usernames="synthetic-user", **kwargs)
                connect.assert_not_called()
                self.assertTrue(result["error"])
                self.assertNotIn(SECRET, str(result))

    async def test_spray_failure_and_missing_file_redact_secrets(self):
        module = MODULES["ad_spray"]
        conn = Mock()
        conn.login.side_effect = RuntimeError(SECRET)
        with patch.object(module.ldap, "LDAPConnection", return_value=conn):
            result = await module.ad_spray(DOMAIN, HOST, SECRET, usernames="synthetic-user")
        self.assertEqual(result["attempted_count"], 1)
        self.assertEqual(result["valid_count"], 0)
        self.assertTrue(result["results"][0]["error"])
        self.assertNotIn(SECRET, str(result))
        conn.close.assert_called_once()
        with patch("builtins.open", side_effect=OSError(SECRET)):
            result = await module.ad_spray(DOMAIN, HOST, SECRET, username_file="synthetic.txt")
        self.assertTrue(result["error"])
        self.assertNotIn(SECRET, str(result))

    async def test_cli_failures_never_report_success_or_live_socks(self):
        for name in ("bloodhound_collect", "ad_certipy", "ad_ntlm_relay"):
            module = MODULES[name]
            for kind, code, truncated in ((None, 3, False), ("timeout", -1, False), ("spawn_error", -1, False), ("output_limit", -1, True), (None, 0, True)):
                with self.subTest(module=name, kind=kind, code=code, truncated=truncated):
                    run = {"exit_code": code, "stdout": "Done " + SECRET, "stderr": "", "error_kind": kind, "output_truncated": truncated}
                    with patch.object(module, "_run_cli", AsyncMock(return_value=run)) as runner, patch("cyber_tools.tool_paths.which_cli", return_value="synthetic-cli"), patch("shutil.which", return_value="synthetic-cli"):
                        if name == "bloodhound_collect":
                            result = await module.bloodhound_collect(DOMAIN, "synthetic-user", SECRET, "bloodhound-python")
                        elif name == "ad_certipy":
                            result = await module.ad_certipy("find", HOST, "synthetic-user", SECRET)
                        else:
                            result = await module.ad_ntlm_relay(HOST, socks_mode=True)
                    runner.assert_awaited_once()
                    self.assertFalse(result.get("success", result.get("executed")))
                    self.assertFalse(result.get("socks_active", False))
                    self.assertTrue(result["error"])
                    self.assertNotIn(SECRET, str(result))

    async def test_cli_invalid_inputs_do_not_execute(self):
        cases = (
            ("bloodhound_collect", {"domain": DOMAIN, "collector": "synthetic-unsupported"}),
            ("bloodhound_collect", {"domain": ""}),
            ("ad_certipy", {"action": "synthetic-unsupported", "target": HOST}),
            ("ad_certipy", {"action": "find", "target": ""}),
            ("ad_ntlm_relay", {"target": HOST, "timeout": 0}),
            ("ad_ntlm_relay", {"target": HOST, "timeout": float("inf")}),
            ("ad_ntlm_relay", {"target": HOST, "timeout": True}),
        )
        for name, kwargs in cases:
            with self.subTest(module=name, kwargs=kwargs), patch.object(MODULES[name], "_run_cli", AsyncMock()) as runner:
                result = await getattr(MODULES[name], name)(**kwargs)
                runner.assert_not_awaited()
                self.assertTrue(result["error"])

    async def test_missing_cli_dependency_is_not_success(self):
        with patch("cyber_tools.tool_paths.which_cli", return_value=None):
            result = await MODULES["ad_certipy"].ad_certipy("find", HOST)
            self.assertFalse(result["executed"])
            self.assertTrue(result["error"])
        with patch("shutil.which", return_value=None):
            result = await MODULES["ad_ntlm_relay"].ad_ntlm_relay(HOST, socks_mode=True)
            self.assertFalse(result["executed"])
            self.assertFalse(result["socks_active"])
            self.assertTrue(result["error"])
        module = MODULES["ad_passthehash"]
        with patch.object(module.shutil, "which", return_value=None), patch.object(module.os.path, "isfile", return_value=False):
            result = await module.ad_passthehash(HOST, "synthetic-user", SECRET, command="synthetic-command")
            self.assertFalse(result["executed"])
            self.assertTrue(result["error"])

    async def test_passthehash_nonzero_empty_stderr_is_failure(self):
        module = MODULES["ad_passthehash"]
        proc = Mock(returncode=7)
        proc.communicate = AsyncMock(return_value=(SECRET.encode(), b""))
        with patch.object(module, "_find_script", return_value="synthetic-cli"), patch.object(module.asyncio, "create_subprocess_exec", AsyncMock(return_value=proc)):
            result = await module.ad_passthehash(HOST, "synthetic-user", SECRET, command="synthetic-command")
        self.assertFalse(result["executed"])
        self.assertTrue(result["error"])
        self.assertNotIn(SECRET, str(result))


if __name__ == "__main__":
    unittest.main()
