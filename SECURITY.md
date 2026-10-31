# Security Policy

If you find a vulnerability in this project, thank you for taking the time to report it responsibly.

## Supported versions

Only the latest code on the `main` branch is maintained. There are no releases or older versions receiving fixes.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub instead:

1. Go to the [**Security** tab](https://github.com/BoraCristian/log-analyzer/security) of this repository.
2. Click **Report a vulnerability**.
3. Include:
   - which file is affected
   - what the issue is and what an attacker could do with it
   - steps to reproduce, or a minimal proof of concept
   - any suggested fix, if you have one

The report is visible only to you and the maintainer until it is resolved.

## What to expect

- An acknowledgement within **7 days**.
- An assessment and, for confirmed issues, a fix on `main` as soon as practical. This is a personal project maintained in spare time, so timelines are best-effort.
- Credit in the fix commit or advisory, if you would like it.

## Scope

In scope: the code in this repository, for example a log line that hides an attack from the detectors, a crafted request that crashes the analyzer or makes it hang (for example catastrophic regex backtracking), or unescaped content in the HTML report.

Out of scope:

- the sample logs in `samples/`, which contain **fictional** attack traffic on purpose
- findings that need an already-compromised machine or administrator access to the host
- missing hardening that the README already lists as a known limitation

## Testing guidelines

Test only against your own local copy. Do not attack third-party systems, and do not access data that isn't yours.
