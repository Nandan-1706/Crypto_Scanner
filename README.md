# SIH26164 - Cryptographic Discovery & Post-Quantum Migration Assistant

A Smart India Hackathon (problem statement SIH26164) prototype that scans a
Python codebase, builds a cryptographic inventory, explains the risk of what
it finds, suggests a post-quantum migration direction, and tracks whether a
finding was actually fixed - by rescanning and verifying, not by trusting a
status label alone.

## Problem statement / project purpose

Organizations often don't know where cryptography is used in their own
codebases, which of those usages are weak or quantum-vulnerable, or which
ones should be fixed first. Existing tools can provide cryptographic
discovery/inventory capabilities. This project's contribution is not "we can
find RSA" - it's connecting discovery to an **explainable, evidence-based
risk assessment**, **prioritization**, a **purpose-aware migration
direction**, and **migration tracking with rescan-based verification**, in
one lightweight, locally-runnable workflow:

```
DISCOVER -> INVENTORY -> ASSESS -> PRIORITIZE -> RECOMMEND -> MIGRATE -> VERIFY
```

## Architecture overview

```
Project directory (ANY local path, not hard-coded to sample_project)
        |
        v
   Phase 1: scanner/            "WHERE is cryptography used?"
   (file discovery, pattern matching, AST analysis, normalization)
        |
        v
   CryptoAsset inventory (evidence: file, line, algorithm, confidence)
        |
        +---------------------------+
        v                           v
   Phase 2: risk_engine/       risk_engine/cvss.py
   "HOW RISKY is it?"          (SEPARATE module - see below)
   (algorithm/quantum risk,
    business criticality,
    data lifetime, Mosca-style
    urgency, project-specific
    risk score/level/priority)
        |
        v
   Phase 3: recommendation/    "WHAT should we do about it?"
   (purpose-aware PQC direction - ML-KEM / ML-DSA / SLH-DSA - or an
    honest "cannot determine" / "not applicable" answer)
        |
        v
   Phase 4: migration/          "DID WE ACTUALLY FIX IT?"
   (migration_state.json tracking, --set-status, --verify rescan-and-compare)
        |
        v
   main.py: JSON report + human-readable terminal report
```

## Phase 1 - Cryptographic discovery (`scanner/`)

Detects, via two independent methods:

| Method | Module | What it sees | Confidence |
|---|---|---|---|
| Pattern matching | `pattern_detector.py` | Raw text/keywords | LOW or MEDIUM |
| AST analysis | `ast_analyzer.py` | Actual function/attribute calls in parsed code | HIGH |

Both can flag the same line - this is intentional and not deduplicated (see
`normalizer.py`); correlating confidence across methods is a risk-engine
concern, not a discovery-time decision.

**Algorithms/APIs detected:** MD5, SHA-1, SHA-224/256/384/512, AES, DES,
3DES/Triple DES, RSA, DSA, ECDSA, ECC, DH, ECDH, plus `hashlib`,
`cryptography` (including `cryptography.hazmat`), and PyCryptodome
(`Crypto.*`) library usage.

**Security of discovery:** `.pem`/`.key`/`.pfx`/`.p12` files are never
opened or read - excluded entirely at the file-discovery stage, before any
content is touched. Files over 2MB are skipped. Nothing is uploaded
anywhere; everything runs locally.

**Documented limitations (not hidden):** Python source only; static
analysis only (dynamically-built crypto calls, e.g. via `getattr`, can be
missed); no binary, container, HSM, or cloud-KMS coverage; no claim of 100%
detection. See the JSON report's `coverage` block, which states plainly
what is/isn't scanned on every run.

## Phase 2 - Risk engine (`risk_engine/`)

Produces, per asset: `classical_risk` and `quantum_risk` (from
`rules.py`/`engine.py`, cited to NIST SP 800-131A Rev. 2 and NIST IR 8547 -
the latter is an unfinalized draft, and every output says so), combined
with user-supplied `business_criticality` and `data_lifetime_years`
(`context.py`, default `UNKNOWN` - never guessed) and a Mosca-style
migration-urgency heuristic (`mosca.py` - explicitly NOT a prediction of
when quantum computers will exist) into one final:

```
risk_score = round(min(100, A + B + C) x confidence_multiplier)
```

- **A (0-40):** algorithm + quantum risk (NIST-cited)
- **B (0-25):** business criticality (user-supplied; UNKNOWN = 10, a
  visible neutral default, never silently LOW or HIGH)
- **C (0-15):** data-lifetime migration urgency (Mosca-style heuristic)
- **confidence_multiplier:** HIGH = 1.0, MEDIUM = 0.85 (LOW-confidence
  findings are never scored at all - flagged for manual review instead)

`risk_level` buckets (80-100 CRITICAL / 60-79 HIGH / 35-59 MEDIUM / 0-34
LOW) and `priority` (1-4) are **this project's own documented
methodology** - explicitly not an official NIST or CVSS classification.
See `risk_engine/scorer.py` for the full formula and `risk_engine/rules.py`
for every algorithm's cited rationale.

`migration_effort_hint` (LOW/MEDIUM/HIGH) is a real, evidence-based signal
(how many times the same algorithm appears project-wide) but is
**excluded from the numeric score** - it's a planning/tie-breaker signal,
not a risk factor.

## CVSS - kept strictly separate (`risk_engine/cvss.py`)

CVSS scores a specific, contextualized *vulnerability instance* (e.g. a
CVE with a known exploit path) - not the abstract presence of an algorithm
in code. This project's own risk score (above) is a **different,
non-CVSS, crypto-migration-specific methodology**.

`risk_engine/cvss.py` is a standalone module with one entry point,
`assess()`. In this phase it **always returns `applies=False`** with an
explanation - it does not fabricate a CVSS score, severity, or vector for
a bare "this code uses MD5" finding, because that isn't the kind of thing
CVSS is designed to score. Nothing else in the codebase depends on this
module's internals; a future phase that cross-references discovered
library *versions* against a real CVE database could populate real
CVSS data here without changing how the rest of the system calls it.

## Phase 3 - PQC recommendation (`recommendation/`)

Purpose-aware, not algorithm-aware: RSA used for signing needs a different
replacement than RSA used for key establishment, and Phase 1's evidence
often can't tell which one it is - when it can't, `recommendation/rules.py`
says so explicitly rather than guessing.

| Purpose | Recommendation | Standard |
|---|---|---|
| Digital signatures (RSA/DSA/ECDSA signing; DSA key generation, which is unambiguous) | ML-DSA, with SLH-DSA as a conservative alternative | FIPS 204; FIPS 205 |
| Key establishment (ECDH, DH, or RSA/ECC key generation whose actual use is confirmed) | ML-KEM | FIPS 203 |
| Ambiguous key generation (RSA/ECC alone - could be either) | **No recommendation given** - explicitly flagged as needing manual review | - |
| Symmetric encryption (AES) | Not part of the PQC family swap - ensure sufficient key length (e.g. AES-256) instead | NIST IR 8547 (draft), Grover's-algorithm guidance |
| Hashing (SHA-2 family) | Already currently approved, not part of PQC migration | - |
| Broken/disallowed classically (MD5, SHA-1, DES, 3DES) | Replace for classical reasons - unrelated to quantum computing | - |

SHA-256 is never described as a post-quantum replacement for RSA/ECC -
it's a different kind of algorithm addressing a different kind of risk.
Every recommendation is a **migration direction**, never an automatic code
change - this tool does not rewrite source code.

## Phase 4 - Migration tracking & verification (`migration/`)

Statuses: `NOT_STARTED -> PLANNED -> IN_PROGRESS -> MIGRATED -> VERIFIED`.

**Why `CryptoAsset.asset_id` can't be used for tracking:** it's a fresh
random UUID on every scan, so it can't identify "the same finding" across
separate tool invocations. Phase 4 instead uses a **stable `tracking_id`**
- a fingerprint of `(file_path, line_number, algorithm)` - computed by
`risk_engine.migration.compute_tracking_id()`. This is a heuristic
identity, not a guarantee: inserting/removing lines earlier in a file
shifts every subsequent finding's tracking_id (a documented limitation).

**State persistence (`migration/state.py`):** a flat `migration_state.json`
file inside the *scanned* project's directory (no database) - so tracking
state travels with whichever project is being tracked.

**Status transitions (`migration/tracker.py`):** skipping forward is
allowed (e.g. `NOT_STARTED -> MIGRATED` directly, since a developer may fix
something without ever running `--set-status` along the way); moving
*backward* is rejected except an explicit reset to `NOT_STARTED`.
`VERIFIED` **cannot be set directly by the user at all** - see below.

**Verification (`migration/verifier.py`, triggered by `--verify`):**
rescans the project and only promotes a `MIGRATED` record to `VERIFIED` if
the rescan shows real evidence:
1. **`verified_removed`** - the original finding's tracking_id no longer
   appears at all (the code was removed/replaced), OR
2. **`verified_risk_reduced`** - the finding is still there, but its
   `risk_level` measurably dropped compared to what was last recorded.

If neither is true, the record **stays `MIGRATED`, not `VERIFIED`** -
setting a status is never, by itself, treated as proof of a real fix.

Phase 4 reuses Phase 1/2/3 entirely - there is no second scanner. Every
`--verify` run is a completely normal scan + score, just compared against
the previous state.

## Installation

```bash
pip install -r requirements.txt
```

Only the standard library is used for Phase 1-4 logic; `pytest` is for
running tests, and `cryptography` is only relevant if you want to actually
execute the sample project's code (the scanner itself never imports or runs
scanned code - it only parses it statically). Tested against Python 3.12 in
this environment; written to be Python 3.14 / Windows compatible (pure
standard library: `pathlib`, `argparse`, `json`, `hashlib`, `datetime`,
`dataclasses`, `enum`, `ast`, `re` - no OS-specific code paths).

## Usage

**Scan any local project (not hard-coded to sample_project):**
```bash
python main.py "/path/to/your/project"
python main.py "D:\some\real\project"          # Windows-style path works identically
python main.py sample_project --context sample_context/critical_long_lifetime.json
```

By default this prints a human-readable report to the terminal AND writes
a machine-readable JSON report (`report.json` by default, or `--output
PATH`). Use `--json-only` to suppress the human-readable output.

**Update a finding's migration status** (TRACKING_ID comes from a fresh
scan's report/JSON - it's stable across scans, unlike the internal
per-run `asset_id`):
```bash
python main.py PROJECT_PATH --set-status TRACKING_ID MIGRATED
```

**Rescan and check whether MIGRATED findings can be promoted to VERIFIED:**
```bash
python main.py PROJECT_PATH --verify
```

**Supply business context** (optional; both default to `UNKNOWN` and this
is made visible in the output, never silently guessed):
```json
{
  "business_criticality": "CRITICAL",
  "data_lifetime_years": 15
}
```
```bash
python main.py PROJECT_PATH --context context.json
```
See `sample_context/` for example files at different criticality/lifetime
levels.

## Example output (abridged, from a real run)

```
==================================================
CRYPTOGRAPHIC RISK REPORT
==================================================

Project: sample_project

Assets Found: 65

CRITICAL: 1
HIGH: 6
MEDIUM: 30
LOW: 0

---

## TOP PRIORITIES

Asset: asset-10bda27c9e41
Tracking ID: 8db5f50caf216fd6
Algorithm: RSA
Key Size: 1024
File: sample_project/weak_examples.py:24
Risk Score: 80
Risk Level: CRITICAL
Priority: 1
Quantum Risk: high
Business Criticality: CRITICAL
Data Lifetime: 15 years

Migration Recommendation:
  'RSA' key generation was detected, but the scanner cannot determine
  whether the key is used for signing or key establishment. Manual
  review needed.

Migration Status:
  NOT_STARTED

---

## MIGRATION SUMMARY

NOT_STARTED: 65
PLANNED: 0
IN_PROGRESS: 0
MIGRATED: 0
VERIFIED: 0

---

## COVERAGE

Python source: SCANNED
Other programming languages: NOT SCANNED
Certificates and key files: NOT SCANNED
Binary files and compiled artifacts: NOT SCANNED
Container images: NOT SCANNED
Hardware security modules: NOT SCANNED
Cloud KMS: NOT SCANNED
```

## Testing

```bash
pytest -q
```

18 test files, covering Phase 1 (file discovery, pattern detection, AST
analysis, normalization, plus the expanded algorithm set), Phase 2 (risk
rules, context, Mosca heuristic, scorer, CVSS separation), Phase 3
(purpose-based recommendations), and Phase 4 (migration state persistence,
status-transition rules, rescan verification, and CLI integration tests
that actually invoke `main.py` as a subprocess against custom project
paths - not just sample_project).

## Security / privacy

- Runs entirely locally - no source code is uploaded anywhere, no cloud AI
  service is called, no telemetry.
- `.pem`/`.key`/`.pfx`/`.p12` files are never opened or read.
- The scanner never prints secret material, private keys, or passwords.
- Automatic code rewriting is explicitly out of scope - every
  recommendation is a migration *direction*, never an automatic change.
- CVSS scores are never fabricated for a bare algorithm-usage finding
  without real vulnerability-instance data (see the CVSS section above).

## Project structure

```
scanner/
    file_discovery.py       - finds safe, relevant files to scan
    pattern_detector.py     - regex/keyword-based detection (low/medium confidence)
    ast_analyzer.py          - AST-based detection of real API usage (high confidence)
    models.py                 - RawFinding and CryptoAsset data shapes
    normalizer.py              - converts RawFindings into report-ready CryptoAssets
    external/
        base.py                  - adapter INTERFACE for future external scanners (not implemented)
risk_engine/
    rules.py                  - classical/quantum risk rule table, NIST-cited
    engine.py                   - applies rules.py to CryptoAssets -> RiskAssessment
    context.py                    - BusinessCriticality/DataLifetime, user-supplied via context.json
    mosca.py                        - Mosca-style migration urgency heuristic
    scorer.py                         - combines engine + context + mosca into final RiskScore
    migration.py                       - MigrationStatus/MigrationRecord data model + compute_tracking_id
    coverage.py                          - what is/isn't scanned, reported honestly
    cvss.py                                - SEPARATE CVSS module (see above)
    models.py                                - RiskAssessment data shape
recommendation/
    models.py                  - PQCRecommendation data shape
    rules.py                     - purpose-based PQC direction mapping, NIST-cited
migration/
    state.py                    - migration_state.json load/save
    tracker.py                    - sync records against fresh scans, validated status transitions
    verifier.py                     - rescan-based VERIFIED promotion logic
report.py                     - human-readable terminal report builder
main.py                        - CLI entry point, orchestrates the full pipeline
sample_project/                 - safe, synthetic code used for demos and tests
sample_context/                  - example context.json files
tests/                             - one or more test files per module (18 files total)
```
