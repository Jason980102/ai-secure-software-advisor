# AI Secure Software Advisor

An AI-powered software dependency and security analysis platform that identifies known vulnerabilities, evaluates dependency risks, and recommends safer software versions with developer-friendly explanations.

## Overview

AI Secure Software Advisor helps developers analyze project dependencies before deployment. The platform scans dependency versions against known vulnerability data, identifies security risks, recommends safer versions, and uses AI to explain findings and remediation steps.

The initial MVP focuses on Python projects using `requirements.txt`.

## MVP Features

- Parse and analyze Python `requirements.txt` dependencies
- Detect known vulnerabilities using the OSV vulnerability database
- Identify affected dependency versions
- Recommend safer or fixed package versions
- Calculate a security risk score based on detected vulnerabilities
- Generate AI-powered explanations and remediation guidance
- Store scan history and findings for later review
- Provide a web dashboard for viewing security reports

## Planned Architecture

```text
Next.js Frontend
       |
       | REST API
       v
FastAPI Backend
       |
       +---- Dependency Parser
       |
       +---- Vulnerability Scanner ---- OSV API
       |
       +---- Risk Scoring Engine
       |
       +---- Recommendation Engine
       |
       +---- AI Advisor ------------ LLM API
       |
       v
PostgreSQL
```

## Tech Stack

**Frontend**
- Next.js
- TypeScript

**Backend**
- FastAPI
- Python
- Pydantic
- SQLAlchemy

**Database**
- PostgreSQL

**Security Intelligence**
- OSV API

**AI**
- LLM API for security explanations and remediation guidance

**DevOps**
- Docker
- GitHub Actions
- Automated testing and CI/CD

## MVP Workflow

```text
requirements.txt
       ↓
Dependency Parsing
       ↓
Vulnerability Analysis
       ↓
Risk Assessment
       ↓
Version Recommendation
       ↓
AI Explanation
       ↓
Security Report
```

## Project Status

🚧 **Under active development**

Current milestone:

**v0.1 — Python Dependency Security Scanner**

The first version focuses on building the core dependency parsing and vulnerability analysis pipeline before expanding to additional package ecosystems.

## Roadmap

- [ ] Build FastAPI backend foundation
- [ ] Implement `requirements.txt` parser
- [ ] Integrate OSV vulnerability scanning
- [ ] Implement risk scoring
- [ ] Implement secure version recommendations
- [ ] Add PostgreSQL persistence
- [ ] Build Next.js security dashboard
- [ ] Add AI-generated security explanations
- [ ] Add automated tests
- [ ] Containerize services with Docker
- [ ] Configure GitHub Actions CI/CD
- [ ] Deploy public demo

### Future

- npm / `package.json` support
- GitHub repository scanning
- Additional vulnerability intelligence sources
- SBOM analysis
- Docker image analysis
- Automated pull request recommendations

## Disclaimer

This project provides software security recommendations based on publicly available vulnerability data. It is intended as a developer assistance tool and should not be treated as a replacement for professional security auditing.

## Implemented: batch scan API

`POST /api/v1/scan` scans an entire text input against OSV, one PyPI
package/version at a time. Existing `/health`, `/api/v1/scan/parse`, and
single-package vulnerability endpoints remain available.

From the repository root (Python 3.11+):

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --reload
```

Open http://127.0.0.1:8000/docs, or use PowerShell:

```powershell
$body = @{ requirements = "requests==2.19.0`nflask==2.0.0`nnumpy==1.21.0" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/scan -ContentType 'application/json' -Body $body
```

Response fields: `total_packages`, `vulnerable_packages`,
`total_vulnerabilities`, and `results`. Each result has `package`,
`installed_version`, and `vulnerabilities`; each finding includes its canonical
ID (preferring CVE), aliases, summary, severity, and `fixed_versions`.

- Counts use unique normalized package names; duplicate identical pins are scanned once.
- `total_vulnerabilities` sums deduplicated findings per package. A shared CVE
  affecting two packages counts twice.
- Blank lines, comments, inline comments, and extras are supported. Only exact
  `==` versions are accepted. Version ranges, wildcards, markers, URLs, hashes,
  include files, and conflicting pins return 422 with the offending line.
  No dependencies are installed and no include files are opened.
- Empty inputs and more than 100 unique packages return 422; input is limited to
  100,000 characters. The legacy parse endpoint still skips unsupported lines.
- OSV pagination is followed. Any upstream HTTP, timeout, or malformed-response
  failure returns 502 instead of an incomplete clean-looking report.
- Withdrawn records are omitted; records sharing aliases are merged transitively.
- Fixed versions come only from matching PyPI package ECOSYSTEM/SEMVER ranges;
  Git commit hashes are excluded and versions are sorted numerically.
  These are source-reported fix boundaries across release branches, not a verified
  safe upgrade recommendation. No release compatibility analysis is performed.
- Severity uses the highest valid CVSS score when available, falling back to
  database/ecosystem severity labels; absent data is `UNKNOWN`.

OSV references: https://google.github.io/osv.dev/post-v1-query/ and
https://ossf.github.io/osv-schema/.

Tests (offline, OSV HTTP responses mocked):

```powershell
$env:PYTHONPATH = 'backend'
.\.venv\Scripts\python.exe -m pytest backend/tests -q
```

Next milestone: calculate CVSS severity and choose upgrade candidates across
release branches, then add a small CI workflow. Frontend, persistence, and agents
are outside this milestone.


## Implemented: CVSS and upgrade candidates

Each finding now includes `cvss_score`, `cvss_vector`, `cvss_type`, and
`severity_source`. CVSS v2/v3/v4 vectors are calculated with cvss==3.6.
The highest valid base score across matching records is used, then explicit
severity labels are the fallback. Invalid vectors are ignored.
Library: https://github.com/RedHatProductSecurity/cvss.

Each package now includes `upgrade_recommendation`: `status`,
`recommended_version`, `checked_versions`, `major_upgrade`, and `reason`.
Candidates are stable, newer fix boundaries, at or above one reported fix per
finding; up to five are re-queried against OSV in ascending version order.
The first candidate with no known OSV findings is returned. This is not proof
of release availability or compatibility with your Python/application.
Statuses: `not_needed`, `candidate`, `manual_review`, `verification_failed`.
Failed candidate checks do not discard the installed-version report.

After updating, install dependencies again and restart the server:

```powershell
.\.venv-mvp\Scripts\python.exe -m pip install -r backend/requirements.txt
.\.venv-mvp\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --reload
```

Request format and endpoint remain unchanged. This milestone includes 39 offline
tests. Next: verify candidate release/Python compatibility and add CI.


## Implemented: PyPI candidate verification and CI

Optional scan input `target_python` accepts a full Python 3 version:

```json
{"requirements": "requests==2.19.0\nflask==2.0.0\nnumpy==1.21.0", "target_python": "3.12.0"}
```

Every upgrade candidate is checked against the PyPI release JSON API before
OSV verification. A release must have at least one non-yanked file. With a
target Python version, at least one non-yanked file must declare a matching
Requires-Python specifier. Missing/invalid metadata is unknown and cannot
qualify a candidate when a target is specified. Omitting target_python skips
this compatibility check (python_compatible=null); the server's Python version
is never assumed to be the user's target.

`upgrade_recommendation.release_checks` records version, status,
requires_python and python_compatible. Statuses include available, not_found,
no_files, yanked, python_incompatible and python_unknown. Upstream failures
return verification_failed while preserving installed-version findings.
The maximum remains five candidate versions, including rejected releases.
This checks metadata only, not wheel tags, OS/architecture, transitive
dependencies, build success or application compatibility. Only source-reported
fix boundaries are considered, so newer eligible releases may not be explored.

GitHub Actions workflow `.github/workflows/backend-tests.yml` runs offline
tests on Python 3.11 and 3.12 for pushes, pull requests and manual dispatch.
61 local tests pass; the remote workflow will run after the changes are pushed.
No secrets or live OSV/PyPI calls are required in tests.

References: https://docs.pypi.org/api/json/ and
https://docs.github.com/en/actions/tutorials/build-and-test-code/python.


## Implemented: CPython wheel compatibility

Optional `target_platform` requires `target_python`. Supported targets:
`win_amd64`, `win_arm64`, `manylinux_2_17_x86_64`,
`manylinux_2_17_aarch64`. Linux targets explicitly mean glibc 2.17 and the
specified CPU; do not use them for Alpine/musl. Conventional CPython only,
not PyPy or free-threaded CPython.

```json
{"requirements":"requests==2.19.0\nflask==2.0.0\nnumpy==1.21.0","target_python":"3.12.0","target_platform":"win_amd64"}
```

The same non-yanked wheel must match Python/ABI/platform tags and its
Requires-Python metadata. Results add `wheel_compatible` and
`compatible_wheels`. `no_compatible_wheel` rejects a candidate; malformed
wheel metadata is `wheel_unknown`. Source-only releases require manual review.
Omitting target_platform preserves metadata-only checks and reports
wheel_compatible=null. No package is downloaded, installed or built.
Matching tags do not prove dependency resolution or runtime compatibility.
Only existing fix-boundary candidates are explored (maximum five); no matching
candidate is not proof that no compatible newer version exists.

CI now uses ubuntu-24.04 and checkout/setup-python v7. It must run on GitHub
after pushing these changes; local tests: 76 passed.
References: https://packaging.pypa.io/en/stable/tags.html,
https://github.com/actions/checkout, https://github.com/actions/setup-python.


## Implemented: expanded stable-release search

After fix-boundary candidates fail, the remaining verification budget is used
to search PyPI's JSON Simple Index. Non-yanked files are grouped by normalized
version; prerelease, development, local, older and below-fix-boundary versions
are excluded. Requested Python constraints and wheel tags prefilter releases.
Eligible releases are considered in ascending order to minimize version jumps.
Already-checked versions are skipped. Release metadata is fetched again before
OSV verification, so index results alone never qualify a recommendation.

The two stages share five candidate verifications per package. The index is
queried at most once, only on fallback with budget remaining. It returns file
metadata only; nothing is downloaded or installed. HTTP calls have 10-second
timeouts, but there is no whole-scan deadline; OSV may require extra pages.

New fields: `candidate_source` (fix_boundary/pypi_release), `expanded_search`,
and `release_checks[].remaining_vulnerability_ids`. Null vulnerability IDs
means no successful OSV check was performed; an empty list means OSV returned
no findings. Candidate lookup/search errors preserve installed-version findings
and return verification_failed. Missing fix boundaries still require manual
review; exceeding the budget does not prove no compatible version exists.

API input is unchanged. Test count: 88 passing offline tests.
Reference: https://docs.pypi.org/api/index-api/.
