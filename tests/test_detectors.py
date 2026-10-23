import unittest
from datetime import datetime, timedelta

from loganalyzer.detectors import Config, busiest_window, run_rules
from loganalyzer.models import Event, Severity

T0 = datetime(2026, 10, 21, 3, 0)


def ssh(action, ip, user="root", minutes=0.0, **extra):
    return Event(T0 + timedelta(minutes=minutes), "auth", action, ip=ip, user=user, extra=extra, raw=f"{action} {ip}")


def sudo(user, command, minutes=0.0, action="sudo", target="root"):
    return Event(T0 + timedelta(minutes=minutes), "auth", action, user=user,
                 extra={"command": command, "target_user": target})


def web(ip, path, status=200, method="GET", ua="Mozilla/5.0", seconds=0):
    return Event(T0 + timedelta(seconds=seconds), "web", "http", ip=ip, method=method, path=path,
                 status=status, user_agent=ua)


def rules_hit(findings):
    return sorted((f.rule, f.ip) for f in findings)


class HelperTests(unittest.TestCase):
    def test_busiest_window(self):
        evs = [ssh("ssh_failed", "x", minutes=m) for m in (0, 1, 2, 30, 31, 32, 33)]
        count, start, end = busiest_window(evs, timedelta(minutes=5))
        self.assertEqual(count, 4)
        self.assertEqual(start, T0 + timedelta(minutes=30))


class SshRuleTests(unittest.TestCase):
    def test_bruteforce_needs_threshold_inside_window(self):
        slow = [ssh("ssh_failed", "1.1.1.1", minutes=m * 20) for m in range(10)]  # 10 fails, 20 min apart
        fast = [ssh("ssh_failed", "2.2.2.2", minutes=m * 0.5) for m in range(5)]
        findings = run_rules(slow + fast, only={"ssh_bruteforce"})
        self.assertEqual(rules_hit(findings), [("ssh_bruteforce", "2.2.2.2")])
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_success_after_bruteforce_is_critical(self):
        evs = [ssh("ssh_failed", "6.6.6.6", minutes=m * 0.2) for m in range(8)]
        evs.append(ssh("ssh_success", "6.6.6.6", user="admin", minutes=3))
        evs.append(ssh("ssh_success", "10.0.0.1", user="alice", minutes=4))  # unrelated, legit
        findings = run_rules(evs, only={"ssh_bruteforce_success"})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertIn("admin", findings[0].description)

    def test_success_before_bruteforce_is_ignored(self):
        evs = [ssh("ssh_success", "6.6.6.6", minutes=0)]
        evs += [ssh("ssh_failed", "6.6.6.6", minutes=10 + m * 0.2) for m in range(8)]
        self.assertEqual(run_rules(evs, only={"ssh_bruteforce_success"}), [])

    def test_user_enumeration(self):
        users = ["test", "oracle", "git", "ftp", "pi"]
        evs = [ssh("ssh_invalid_user", "7.7.7.7", user=u, minutes=i * 60) for i, u in enumerate(users)]
        evs += [ssh("ssh_failed", "8.8.8.8", user="root", minutes=i) for i in range(4)]
        self.assertEqual(rules_hit(run_rules(evs, only={"user_enumeration"})), [("user_enumeration", "7.7.7.7")])

    def test_off_hours(self):
        evs = [ssh("ssh_success", "1.1.1.1", minutes=0),  # 03:00
               ssh("ssh_success", "2.2.2.2", minutes=7 * 60)]  # 10:00
        self.assertEqual(rules_hit(run_rules(evs, only={"off_hours_login"})), [("off_hours_login", "1.1.1.1")])

    def test_off_hours_overnight_shift(self):
        # night shift: working hours 22-06, so 03:00 is fine and 10:00 is not
        evs = [ssh("ssh_success", "1.1.1.1", minutes=0), ssh("ssh_success", "2.2.2.2", minutes=7 * 60)]
        findings = run_rules(evs, Config(work_hours=(22, 6)), only={"off_hours_login"})
        self.assertEqual(rules_hit(findings), [("off_hours_login", "2.2.2.2")])


class SudoRuleTests(unittest.TestCase):
    def test_root_shell(self):
        evs = [sudo("eve", "/bin/bash"), sudo("eve", "/usr/bin/su -"), sudo("bob", "/usr/bin/apt update"),
               sudo("bob", "/bin/bash", target="postgres")]
        findings = run_rules(evs, only={"sudo_root_shell"})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].count, 2)

    def test_failures(self):
        evs = [sudo("bob", "/bin/ls", minutes=i, action="sudo_failed") for i in range(3)]
        self.assertEqual(len(run_rules(evs, only={"sudo_failures"})), 1)
        self.assertEqual(run_rules(evs[:2], only={"sudo_failures"}), [])


class WebRuleTests(unittest.TestCase):
    def categories(self, path, ua="Mozilla/5.0"):
        findings = run_rules([web("1.1.1.1", path, ua=ua)], only={"web_attack"})
        return {f.title.split(" from ")[0] for f in findings}

    def test_sql_injection(self):
        self.assertIn("SQL injection", self.categories("/p.php?id=1%20UNION%20ALL%20SELECT%20NULL--"))
        self.assertIn("SQL injection", self.categories("/p.php?id=1'%20OR%20'1'='1"))
        self.assertIn("SQL injection", self.categories("/p.php?id=1%20AND%20SLEEP(5)"))

    def test_double_encoded_traversal(self):
        self.assertIn("Path traversal / file inclusion", self.categories("/dl?f=%252e%252e%252f%252e%252e%252fetc%252fpasswd"))

    def test_xss_and_command_injection(self):
        self.assertIn("Cross-site scripting (XSS)", self.categories("/s?q=%3Cscript%3Ealert(1)%3C/script%3E"))
        self.assertIn("OS command injection", self.categories("/ping?h=127.0.0.1%3B%20cat%20/etc/passwd"))

    def test_log4shell_in_user_agent(self):
        self.assertIn("Log4Shell (CVE-2021-44228)", self.categories("/", ua="${jndi:ldap://x/a}"))

    def test_benign_urls_are_clean(self):
        for path in ["/", "/blog/union-station-selection", "/search?q=rock+and+roll", "/products.php?id=3",
                     "/static/app.js", "/api/items?order=asc&limit=10", "/docs/select-a-plan"]:
            self.assertEqual(self.categories(path), set(), path)

    def test_exposed_sensitive_file_is_high(self):
        findings = run_rules([web("1.1.1.1", "/.git/config", 404), web("1.1.1.1", "/.env", 200)], only={"web_attack"})
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("/.env", findings[0].description)

    def test_scan_counts_distinct_404_paths(self):
        scanner = [web("9.9.9.9", f"/probe{i}", 404, seconds=i) for i in range(25)]
        refresher = [web("5.5.5.5", "/missing", 404, seconds=i) for i in range(50)]
        self.assertEqual(rules_hit(run_rules(scanner + refresher, only={"web_scan"})), [("web_scan", "9.9.9.9")])

    def test_scanner_user_agents(self):
        evs = [web("1.1.1.1", "/", ua="Mozilla/5.00 (Nikto/2.5.0)"), web("2.2.2.2", "/", ua="curl/8.5.0"),
               web("3.3.3.3", "/", ua=None), web("4.4.4.4", "/")]
        by_ip = {f.ip: f.severity for f in run_rules(evs, only={"suspicious_user_agent"})}
        self.assertEqual(by_ip, {"1.1.1.1": Severity.MEDIUM, "2.2.2.2": Severity.INFO, "3.3.3.3": Severity.INFO})

    def test_http_bruteforce_with_success(self):
        evs = [web("6.6.6.6", "/wp-login.php", 200, "POST", seconds=i * 3) for i in range(12)]
        self.assertEqual(run_rules(evs, only={"http_bruteforce"})[0].severity, Severity.HIGH)
        evs.append(web("6.6.6.6", "/wp-login.php", 302, "POST", seconds=40))
        self.assertEqual(run_rules(evs, only={"http_bruteforce"})[0].severity, Severity.CRITICAL)

    def test_normal_login_is_not_bruteforce(self):
        evs = [web("6.6.6.6", "/login", 200, "POST"), web("6.6.6.6", "/login", 302, "POST", seconds=20)]
        self.assertEqual(run_rules(evs, only={"http_bruteforce"}), [])


class OrderingTests(unittest.TestCase):
    def test_findings_sorted_by_severity(self):
        evs = [ssh("ssh_success", "1.1.1.1")]  # low (off hours)
        evs += [ssh("ssh_failed", "2.2.2.2", minutes=m * 0.1) for m in range(6)]  # high
        severities = [f.severity for f in run_rules(evs)]
        self.assertEqual(severities, sorted(severities, reverse=True))


if __name__ == "__main__":
    unittest.main()
