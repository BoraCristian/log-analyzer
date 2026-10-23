import gzip
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from loganalyzer.parsers import detect_format, parse_auth_line, parse_file, parse_web_line

NOW = datetime(2026, 10, 22, 12, 0)


class AuthParserTests(unittest.TestCase):
    def parse_one(self, line):
        events = parse_auth_line(line, now=NOW)
        self.assertEqual(len(events), 1, events)
        return events[0]

    def test_failed_password(self):
        e = self.parse_one("Oct 21 03:12:04 web01 sshd[4609]: Failed password for root from 203.0.113.45 port 50971 ssh2")
        self.assertEqual((e.action, e.user, e.ip), ("ssh_failed", "root", "203.0.113.45"))
        self.assertEqual(e.timestamp, datetime(2026, 10, 21, 3, 12, 4))
        self.assertFalse(e.extra["invalid_user"])
        self.assertEqual(e.extra["host"], "web01")

    def test_failed_password_invalid_user(self):
        e = self.parse_one("Oct 21 03:12:04 web01 sshd[1]: Failed password for invalid user oracle from 2001:db8::7 port 22 ssh2")
        self.assertEqual((e.user, e.ip), ("oracle", "2001:db8::7"))
        self.assertTrue(e.extra["invalid_user"])

    def test_accepted_publickey(self):
        e = self.parse_one("Oct  1 09:02:11 web01 sshd[77]: Accepted publickey for alice from 10.0.0.12 port 51122 ssh2: ED25519 SHA256:abc")
        self.assertEqual((e.action, e.user, e.extra["method"]), ("ssh_success", "alice", "publickey"))
        self.assertEqual(e.timestamp.day, 1)

    def test_invalid_user(self):
        e = self.parse_one("Oct 21 01:36:05 web01 sshd[9]: Invalid user test from 198.51.100.23 port 40000")
        self.assertEqual((e.action, e.user), ("ssh_invalid_user", "test"))

    def test_message_repeated_expands(self):
        events = parse_auth_line(
            "Oct 21 03:18:00 web01 sshd[9]: message repeated 3 times: [ Failed password for admin from 1.2.3.4 port 5 ssh2]",
            now=NOW)
        self.assertEqual([e.action for e in events], ["ssh_failed"] * 3)

    def test_sudo_command(self):
        e = self.parse_one("Oct 21 03:20:43 web01 sudo:    admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash")
        self.assertEqual((e.action, e.user), ("sudo", "admin"))
        self.assertEqual(e.extra["target_user"], "root")
        self.assertEqual(e.extra["command"], "/bin/bash")

    def test_sudo_failure(self):
        e = self.parse_one("Oct 21 14:02:31 web01 sudo:  bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/bob ; "
                           "USER=root ; COMMAND=/usr/bin/vim /etc/hosts")
        self.assertEqual(e.action, "sudo_failed")
        self.assertEqual(e.extra["command"], "/usr/bin/vim /etc/hosts")

    def test_rfc3339_timestamp(self):
        e = self.parse_one("2026-10-21T03:12:04.123456+02:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2")
        self.assertEqual(e.timestamp, datetime(2026, 10, 21, 3, 12, 4, 123456))
        self.assertIsNone(e.timestamp.tzinfo)

    def test_year_rollover_guess(self):
        # December entries read in January belong to the previous year
        e = parse_auth_line("Dec 31 23:59:00 h sshd[1]: Failed password for x from 1.2.3.4 port 5 ssh2",
                            now=datetime(2027, 1, 2))[0]
        self.assertEqual(e.timestamp.year, 2026)

    def test_explicit_year(self):
        e = parse_auth_line("Dec 31 23:59:00 h sshd[1]: Failed password for x from 1.2.3.4 port 5 ssh2", year=2020)[0]
        self.assertEqual(e.timestamp.year, 2020)

    def test_uninteresting_lines(self):
        self.assertEqual(parse_auth_line("Oct 21 00:00:00 web01 CRON[1]: pam_unix(cron:session): session opened", now=NOW), [])
        self.assertEqual(parse_auth_line("not a log line"), [])


class WebParserTests(unittest.TestCase):
    def test_combined_format(self):
        line = ('203.0.113.99 - - [21/Oct/2026:15:20:12 +0000] "GET /products.php?id=3%27 HTTP/1.1" 500 210 '
                '"-" "sqlmap/1.8.9#stable (https://sqlmap.org)"')
        (e,) = parse_web_line(line)
        self.assertEqual((e.ip, e.method, e.path, e.status), ("203.0.113.99", "GET", "/products.php?id=3%27", 500))
        self.assertEqual(e.user_agent, "sqlmap/1.8.9#stable (https://sqlmap.org)")
        self.assertEqual(e.timestamp, datetime(2026, 10, 21, 15, 20, 12))

    def test_common_format_without_agent(self):
        (e,) = parse_web_line('10.0.0.1 - bob [21/Oct/2026:10:00:00 -0500] "POST /login HTTP/1.0" 302 -')
        self.assertEqual((e.user, e.method, e.status, e.user_agent), ("bob", "POST", 302, None))

    def test_escaped_quote_in_user_agent(self):
        (e,) = parse_web_line('1.2.3.4 - - [21/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "evil \\"agent\\""')
        self.assertEqual(e.user_agent, 'evil "agent"')

    def test_malformed_request_line(self):
        (e,) = parse_web_line('1.2.3.4 - - [21/Oct/2026:10:00:00 +0000] "\\x16\\x03\\x01" 400 0 "-" "-"')
        self.assertIsNone(e.method)
        self.assertEqual(e.status, 400)

    def test_garbage(self):
        self.assertEqual(parse_web_line("hello world"), [])


class FileTests(unittest.TestCase):
    AUTH = "Oct 21 03:12:04 web01 sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2\n"
    WEB = '1.2.3.4 - - [21/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "curl/8"\n'

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_detect_format(self):
        self.assertEqual(detect_format([self.AUTH] * 3), "auth")
        self.assertEqual(detect_format(["", self.WEB]), "web")
        self.assertIsNone(detect_format(["nothing to see"]))

    def test_parse_file_counts_and_locations(self):
        path = self.dir / "auth.log"
        path.write_text(self.AUTH + "garbage line\n\n" + self.AUTH, encoding="utf-8")
        result = parse_file(path)
        self.assertEqual((result.fmt, result.total_lines, result.unparsed_lines), ("auth", 3, 1))
        self.assertEqual([e.line_no for e in result.events], [1, 4])
        self.assertEqual(result.events[0].file, "auth.log")

    def test_parse_gzip(self):
        path = self.dir / "access.log.gz"
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            fh.write(self.WEB * 4)
        self.assertEqual(len(parse_file(path).events), 4)

    def test_undetectable_file(self):
        path = self.dir / "x.log"
        path.write_text("nope\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            parse_file(path)


if __name__ == "__main__":
    unittest.main()
