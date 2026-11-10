# Security Register

Findings from the security scans added on branch `devsecops-scans` (PR #1 in
Phillip-mulindwa/devops-2025S-demo). Every count and ID below is copied from the CI logs.

| Scan | CI run | Result before fixes | Result after fixes (gated run 42842883539) |
|---|---|---|---|
| gitleaks (secrets) | 42816297657 | no leaks, 3 commits scanned | no leaks, 9 commits scanned |
| Bandit (code) | 42816297657 | 1 issue: Low 1, Medium 0, High 0 (815 LOC) | no issues identified |
| Trivy (image, HIGH+CRITICAL) | 42819649293 | debian 13.7: 49 (HIGH 49, CRITICAL 0); Django 5.2.7: 8 (HIGH 7, CRITICAL 1) | CRITICAL gate: debian 0, Django 5.2.19 0 |
| Checkov (terraform) | 42836789981 | passed 3, failed 1 | passed 4, failed 0 |

Trivy note: Trivy's own total for the debian layer is 49, but its table lists 48 rows
covering 13 unique CVEs. Each CVE appears once below, and the affected packages are listed in its row.

| ID | Tool | Finding | Severity | Location | Decision | Justification | Owner | Revisit date |
|---|---|---|---|---|---|---|---|---|
| SEC-01 | Bandit | B105 hardcoded_password_string: `SECRET_KEY` assigned a string literal (CWE-259) | Low (confidence Medium) | `campus_notifier/settings.py:27` | remediate | Key now read from `DJANGO_SECRET_KEY` in a gitignored `.env`; fails loudly if unset. The old `django-insecure-` key is still in git history, so any environment that used it must be given a new key. | Phillip Mulindwa | 2026-12-10 |
| SEC-02 | Trivy | CVE-2025-64459 Django SQL injection | CRITICAL | Django 5.2.7 (`requirements.txt`) | remediate | Upgraded to Django 5.2.19 (fixed in 5.2.8). Gated run reports 0 CRITICAL for Django. | Phillip Mulindwa | 2026-12-10 |
| SEC-03 | Trivy | CVE-2025-64458 Django denial of service on Windows | HIGH | Django 5.2.7 | remediate | Upgraded to Django 5.2.19 (fixed in 5.2.8). | Phillip Mulindwa | 2026-12-10 |
| SEC-04 | Trivy | CVE-2026-1207 SQL injection via RasterField band index | HIGH | Django 5.2.7 | remediate | Upgraded to Django 5.2.19 (fixed in 5.2.11). | Phillip Mulindwa | 2026-12-10 |
| SEC-05 | Trivy | CVE-2026-1287 SQL injection via crafted column aliases | HIGH | Django 5.2.7 | remediate | Upgraded to Django 5.2.19 (fixed in 5.2.11). | Phillip Mulindwa | 2026-12-10 |
| SEC-06 | Trivy | CVE-2026-15307 remote code execution via GeoDjango spatial | HIGH | Django 5.2.7 | remediate | Upgraded to Django 5.2.19 (fixed in 5.2.17). | Phillip Mulindwa | 2026-12-10 |
| SEC-07 | Trivy | CVE-2026-25673 denial of service via slow URL normalization | HIGH | Django 5.2.7 | remediate | Upgraded to Django 5.2.19 (fixed in 5.2.12). | Phillip Mulindwa | 2026-12-10 |
| SEC-08 | Trivy | CVE-2026-33034 denial of service via missing or understated … | HIGH | Django 5.2.7 | remediate | Upgraded to Django 5.2.19 (fixed in 5.2.13). | Phillip Mulindwa | 2026-12-10 |
| SEC-09 | Trivy | CVE-2026-3902 header spoofing via ambiguous header mapping | HIGH | Django 5.2.7 | remediate | Upgraded to Django 5.2.19 (fixed in 5.2.13). | Phillip Mulindwa | 2026-12-10 |
| SEC-10 | Trivy | CVE-2026-85091 zlib heap buffer overflow in gz_vacate() | HIGH (status: fixed) | zlib1g 1:1.3.dfsg+really1.3.1-1+b1 (base image) | remediate | Dockerfile now runs `apt-get upgrade`; rebuilt image has zlib1g 1:1.3.dfsg+really1.3.1-1+deb13u1 (the fixed version). | Phillip Mulindwa | 2026-12-10 |
| SEC-11 | Trivy | CVE-2026-76844 (Trivy's title reads "webpack-dev-middleware information disclosure via path traversal", which looks like a mis-mapped advisory title) | HIGH (status: fixed) | zlib1g 1:1.3.dfsg+really1.3.1-1+b1 (base image) | remediate | Same fix as SEC-10: zlib1g upgraded to 1:1.3.dfsg+really1.3.1-1+deb13u1. | Phillip Mulindwa | 2026-12-10 |
| SEC-12 | Trivy | CVE-2026-9538 perl Archive::Tar denial of service | HIGH (status: fix_deferred) | perl-base 5.40.1-6+deb13u1 (base image) | accept | Debian has deferred the fix. The app never runs perl or extracts tar archives. Excluded from the gate by `ignore-unfixed`. | Phillip Mulindwa | 2026-12-10 |
| SEC-13 | Trivy | CVE-2026-76642 util-linux: failed external mount helper still runs privileged X-mount post-hooks | HIGH (no fix) | util-linux 2.41.5-0+deb13u1: bsdutils, libblkid1, liblastlog2-2, libmount1, libsmartcols1, libuuid1, login, mount, util-linux | accept | No Debian fix yet. Needs mount operations; the container runs as the non-root `app` user without mount capabilities. | Phillip Mulindwa | 2026-12-10 |
| SEC-14 | Trivy | CVE-2026-78408 util-linux: nsenter --join-cgroup leaks root cgroup migration authority | HIGH (no fix) | util-linux 2.41.5-0+deb13u1 (same 9 packages as SEC-13) | accept | No Debian fix yet. Requires running nsenter with privileges; not used by the app, non-root container. | Phillip Mulindwa | 2026-12-10 |
| SEC-15 | Trivy | CVE-2026-78409 util-linux: X-mount.subdir detached-tree resolution can escape via intermediate symlinks | HIGH (no fix) | util-linux 2.41.5-0+deb13u1 (same 9 packages as SEC-13) | accept | No Debian fix yet. Mount-only path; non-root container without mount capabilities. | Phillip Mulindwa | 2026-12-10 |
| SEC-16 | Trivy | CVE-2026-78410 util-linux: restricted bind mounts do not pin the source | HIGH (no fix) | util-linux 2.41.5-0+deb13u1 (same 9 packages as SEC-13) | accept | No Debian fix yet. Mount-only path; non-root container without mount capabilities. | Phillip Mulindwa | 2026-12-10 |
| SEC-17 | Trivy | CVE-2026-119373 sqlite denial of service via heap-based buffer … | HIGH (no fix) | libsqlite3-0 3.46.1-7+deb13u2 | accept | No Debian fix yet. The app's default DB is SQLite, but it only opens its own database file, never untrusted ones. Re-check at revisit; switching to Postgres (`DB_ENGINE`) removes the exposure. | Phillip Mulindwa | 2026-12-10 |
| SEC-18 | Trivy | CVE-2026-119374 sqlite arbitrary code execution via corrupted FTS5 … | HIGH (no fix) | libsqlite3-0 3.46.1-7+deb13u2 | accept | No Debian fix yet. Needs a crafted database or FTS5 data; the app doesn't use FTS5 or load untrusted databases. | Phillip Mulindwa | 2026-12-10 |
| SEC-19 | Trivy | CVE-2026-119379 sqlite arbitrary code execution via crafted session … | HIGH (no fix) | libsqlite3-0 3.46.1-7+deb13u2 | accept | No Debian fix yet. The app doesn't use the SQLite session extension. | Phillip Mulindwa | 2026-12-10 |
| SEC-20 | Trivy | CVE-2025-69720 ncurses buffer overflow vulnerability may lead to … | HIGH (no fix) | libncursesw6, libtinfo6, ncurses-base (base image) | accept | No Debian fix yet. Terminal library only; the web app never uses it. | Phillip Mulindwa | 2026-12-10 |
| SEC-21 | Trivy | CVE-2026-16742 systemd-homed local privilege escalation via … | HIGH (no fix) | libsystemd0, libudev1 (base image) | accept | No Debian fix yet. No systemd or systemd-homed runs in the container; only the libraries are present. | Phillip Mulindwa | 2026-12-10 |
| SEC-22 | Trivy | CVE-2026-54369 acl: symlink traversal privilege escalation via libacl functions | HIGH (no fix) | libacl1 2.3.2-2+b1 (base image) | accept | No Debian fix yet. Requires local access to manipulate ACLs; non-root container, app does not set ACLs. | Phillip Mulindwa | 2026-12-10 |
| SEC-23 | Checkov | CKV_AWS_136 Ensure that ECR repositories are encrypted using KMS | Failed check (Checkov gives no severity in the free tier) | `terraform/main.tf:2-19`, `aws_ecr_repository.devops_repo` | remediate | Added `encryption_configuration { encryption_type = "KMS" }` (AWS-managed `aws/ecr` key, so no extra key to run). Checkov now 4 passed / 0 failed. Note: changing encryption on an already-applied repo forces Terraform to replace it, which deletes stored images. Re-push images after applying. | Phillip Mulindwa | 2026-12-10 |

## Notes

- gitleaks found no leaks in CI (Drills 2–5), so it has no rows. On `pull_request` events
  gitleaks-action scans only the PR's commit range (`ea9dcda^..HEAD`), not the full history,
  even with `fetch-depth: 0`. A full-history scan runs on `push` or `workflow_dispatch`.
- Locally, the pre-commit hook blocked a commit containing a generated hex key
  (`generic-api-key`, exit 1). That key was never committed.
- The image also includes dev-only tools from `requirements.txt` (pre-commit, virtualenv).
  Trivy reports 0 vulnerabilities in them, but splitting runtime and dev requirements would shrink the image.
- The `.github/workflows/linting.yml` workflow is an empty file and fails on every push. That
  predates this work and is unrelated to the security gates.
- CI Checkov (via checkov-action v12.1347.0) reports version 2.0.930, which is much older than
  the local 3.4.3. Both gave identical results here.
