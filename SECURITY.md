# Security policy

Skill X-Ray reads untrusted skill packages, so a bug in its parsers or its report writer is a security bug.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability. Use GitHub's private vulnerability reporting on this repository's Security tab, which reaches the maintainers privately. Include the input that triggers the problem, or a description precise enough to rebuild it, and the version from `skill-xray version`.

You will get an acknowledgement within five working days. Fixes ship as a new release with the advisory published once the release is out.

## Scope

In scope: anything that makes the scanner execute, fetch or write something it should not while scanning a package; a crafted package that hides a finding the rules document; a report that leaks data from outside the scanned package. Out of scope: findings the rules do not claim to detect, which are welcome as ordinary issues.
