"""End-to-end tests against the bundled sample logs."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from loganalyzer.cli import main

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
AUTH, ACCESS = str(SAMPLES / "auth.log"), str(SAMPLES / "access.log")


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(list(args))
        except SystemExit as exc:  # argparse errors
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_json_report_finds_every_planted_attack(self):
        code, out, _ = run(AUTH, ACCESS, "--report", "json")
        self.assertEqual(code, 0)
        report = json.loads(out)
        found = {(f["rule"], f["ip"]) for f in report["findings"]}
        expected = {
            ("ssh_bruteforce", "203.0.113.45"),
            ("ssh_bruteforce_success", "203.0.113.45"),
            ("user_enumeration", "198.51.100.23"),
            ("web_scan", "192.0.2.77"),
            ("http_bruteforce", "198.51.100.200"),
            ("web_attack", "192.0.2.150"),
            ("web_attack", "203.0.113.99"),
        }
        self.assertLessEqual(expected, found)
        self.assertEqual({f["format"] for f in report["files"]}, {"auth", "web"})
        # nobody from the ordinary visitor range should be flagged
        self.assertFalse([f for f in report["findings"] if (f["ip"] or "").startswith("198.18.")])

    def test_text_report(self):
        code, out, _ = run(AUTH, "--no-color", "-v")
        self.assertEqual(code, 0)
        self.assertIn("[CRITICAL] Successful login after brute force from 203.0.113.45", out)
        self.assertIn("| auth.log:", out)  # evidence lines in verbose mode
        self.assertNotIn("\033[", out)

    def test_html_report_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "report.html"
            code, _, err = run(AUTH, ACCESS, "-o", str(target))
            self.assertEqual(code, 0)
            page = target.read_text(encoding="utf-8")
        self.assertIn("<!doctype html>", page)
        self.assertIn("Web login brute force", page)
        self.assertNotIn("<script>alert", page)  # payloads in evidence must be escaped
        self.assertIn("Report written", err)

    def test_fail_on_and_min_severity(self):
        self.assertEqual(run(AUTH, "-r", "json", "--fail-on", "critical")[0], 1)
        code, out, _ = run(AUTH, "-r", "json", "--min-severity", "high", "--rules", "off_hours_login")
        self.assertEqual((code, json.loads(out)["findings"]), (0, []))

    def test_bad_arguments(self):
        self.assertEqual(run(AUTH, "--rules", "nope")[0], 2)
        self.assertEqual(run("does-not-exist.log")[0], 2)
        self.assertEqual(run(AUTH, "--work-hours", "25-3")[0], 2)


if __name__ == "__main__":
    unittest.main()
