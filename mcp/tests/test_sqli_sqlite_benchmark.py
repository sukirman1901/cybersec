"""Actual SQLite behind localhost HTTP: no keyword-simulated SQL execution."""

import json
import sqlite3
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyber_tools.sqli_detect import sqli_detect


class SQLiteHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        parsed = urlsplit(self.path)
        params = parse_qs(parsed.query, keep_blank_values=True)
        value = params.get("id", ["7"])[0]
        string_context = "string" in parsed.path
        safe = parsed.path.startswith("/safe")
        blind = "blind" in parsed.path
        status = 200
        with sqlite3.connect(":memory:") as db:
            db.execute("CREATE TABLE items (id INTEGER, name TEXT)")
            db.executemany("INSERT INTO items VALUES (?, ?)", [(7, "alpha"), (8, "bravo")])
            column = "name" if string_context else "id"
            try:
                if safe:
                    rows = db.execute(f"SELECT id, name FROM items WHERE {column} = ?", (value,)).fetchall()
                else:
                    literal = "'" + value + "'" if string_context else value
                    rows = db.execute(f"SELECT id, name FROM items WHERE {column} = {literal}").fetchall()
                body = json.dumps({"rows": rows})
                if "equal" in parsed.path:
                    body = "record found: AAAA" if rows else "record empty: BBBB"
            except sqlite3.Error as exc:
                status = 200 if blind else 500
                body = json.dumps({"rows": []}) if blind else "[SQLITE_ERROR] " + str(exc)
        if params.get("tenant") != ["qa team"]:
            status, body = 403, "wrong tenant context"
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body.encode())


class TestSQLiteBenchmark(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), SQLiteHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    async def scan(self, path, value="7", preset="observe-first"):
        return await sqli_detect(f"{self.base}{path}?id={value}&tenant=qa%20team", "id", preset)

    async def test_real_numeric_error_is_confirmed(self):
        out = await self.scan("/unsafe-numeric")
        self.assertIn("error_based", out["techniques_found"])

    async def test_real_string_error_is_confirmed(self):
        out = await self.scan("/unsafe-string", "alpha")
        self.assertIn("error_based", out["techniques_found"])

    async def test_real_numeric_blind_is_confirmed_without_error_output(self):
        out = await self.scan("/unsafe-numeric-blind")
        self.assertEqual(out["techniques_found"], ["boolean_blind"])

    async def test_real_string_blind_is_confirmed_without_error_output(self):
        out = await self.scan("/unsafe-string-blind", "alpha")
        self.assertEqual(out["techniques_found"], ["boolean_blind"])

    async def test_equal_length_boolean_content_is_detected(self):
        self.assertEqual(len("record found: AAAA"), len("record empty: BBBB"))
        out = await self.scan("/unsafe-numeric-equal-blind")
        self.assertIn("boolean_blind", out["techniques_found"])

    async def test_parameterized_numeric_query_is_not_flagged(self):
        out = await self.scan("/safe-numeric")
        self.assertFalse(out["vulnerable"])
        self.assertTrue(out["coverage_complete"])

    async def test_parameterized_string_query_is_not_flagged(self):
        out = await self.scan("/safe-string", "alpha")
        self.assertFalse(out["vulnerable"])
        self.assertTrue(out["coverage_complete"])

    async def test_empty_baseline_does_not_claim_boolean_confirmation(self):
        out = await self.scan("/unsafe-numeric-blind", "999")
        self.assertFalse(out["vulnerable"])

    async def test_deep_preset_uses_real_database_with_bounded_requests(self):
        out = await self.scan("/unsafe-string-blind", "alpha", "staging-deep")
        self.assertTrue(out["vulnerable"])
        self.assertLessEqual(out["requests_sent"], out["request_budget"])
