"""End-to-end loopback-only website audit tests (no external targets)."""
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCANNER = ROOT / "decrypto_assumption_scan.py"


class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Set-Cookie", "sessionid=synthetic; Path=/")
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.send_header("Set-Cookie", "sessionid=synthetic; Path=/")
        if self.headers.get("Origin"):
            self.send_header("Access-Control-Allow-Origin", self.headers["Origin"])
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(b"synthetic fixture; never copied into findings")

    def log_message(self, *_args):
        pass


class TestWebsiteCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.url = "http://127.0.0.1:%d/" % cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=3)

    def test_authorized_scan_and_redacted_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            prefix = Path(tmp) / "report"
            run = subprocess.run(
                [sys.executable, str(SCANNER), "--url", self.url,
                 "--authorized", "--cors", "--out", str(prefix)],
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            data = json.loads(prefix.with_suffix(".json").read_text(encoding="utf-8"))
            markdown = prefix.with_suffix(".md").read_text(encoding="utf-8")
            self.assertEqual(data["total_requests"], 2)
            self.assertEqual(len(data["observations"]), 2)
            rules = {finding["rule"] for finding in data["findings"]}
            self.assertIn("SESSION-COOKIE-1", rules)
            self.assertIn("CORS-TRUST", rules)
            self.assertNotIn("synthetic fixture", str(data) + markdown)
            self.assertNotIn("sessionid=synthetic", str(data) + markdown)

    def test_live_scan_requires_authorization(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = subprocess.run(
                [sys.executable, str(SCANNER), "--url", self.url,
                 "--out", str(Path(tmp) / "report")],
                capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(run.returncode, 0)
            self.assertFalse((Path(tmp) / "report.json").exists())


if __name__ == "__main__":
    unittest.main()
