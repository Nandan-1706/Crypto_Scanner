# SIH26164 - Cryptographic Discovery Tool: Scanner Core (Phase 1)

This is Phase 1 of a larger Cryptographic Discovery and Quantum Risk
Assessment Tool built for Smart India Hackathon problem statement SIH26164.

Phase 1 delivers **only the scanner core**: given a Python project directory,
it discovers cryptographic indicators and produces a structured JSON
inventory. It does **not** include a web dashboard, API server, database,
risk scoring, or PQC migration recommendations - those are later phases.

## What it does

```
project directory
    -> file discovery (safe, relevant files only)
    -> pattern detection (regex/keyword based, low/medium confidence)
    -> AST analysis (real code-structure based, high confidence)
    -> normalization (unified CryptoAsset records)
    -> risk engine (deterministic, standards-cited classical + quantum risk scoring)
    -> JSON report
```

## Risk scoring (Phase 2)

Every scored asset gets TWO separate, independently-labeled risk verdicts:

- **`classical_risk`** - is this weak/broken *today*, ignoring quantum computers? Based on **NIST SP 800-131A Rev. 2** (finalized, 2019).
- **`quantum_risk`** - will this need to change *because of* quantum computers? Based on **NIST IR 8547** (Initial Public Draft, Nov 2024 - not yet a finalized standard; the JSON output always says so in `standard_reference`).

Every scored asset's `rule_id` and `standard_reference` trace back to `risk_engine/rules.py`, which is plain, reviewable data - not hidden logic. There is no code path that produces a risk level without a cited source.

**LOW-confidence findings are never risk-scored.** Since Phase 1's pattern detector can match keywords inside comments/docstrings, scoring those as if they were real risky code would be an invented security claim. They're returned with `scoring_status: "skipped_low_confidence"` and a note recommending manual review instead.

**Unrecognized algorithms are never given a fabricated verdict.** If the rule table doesn't cover something (or it's a generic import indicator with no specific algorithm), the result is `unknown_insufficient_data` with an explicit rationale - not a guess.

Recommendation/migration-path guidance (i.e., *what to migrate to*) is intentionally **not** part of the risk engine - that's planned as a separate, later phase.

## Running it

```bash
pip install -r requirements.txt
python main.py sample_project
```

Or write the report to a file:

```bash
python main.py sample_project --output report.json
```

## Running the tests

```bash
pip install -r requirements.txt
pytest
```

## Detection methods and confidence

| Method | Module | What it sees | Confidence |
|---|---|---|---|
| Pattern matching | `scanner/pattern_detector.py` | Raw text/keywords (e.g. "MD5" appears in a line) | LOW or MEDIUM |
| AST analysis | `scanner/ast_analyzer.py` | Actual function/attribute calls in parsed code | HIGH |

**Both methods can flag the same line - this is intentional.** The
normalizer does not deduplicate across methods; correlating/reconciling
findings from different detectors is treated as a risk-engine concern for a
later phase, not something the scanner core silently decides.

## Known limitations (please read before trusting the output)

This is a Phase 1 prototype. It has real, documented gaps:

- **Python only.** No support yet for other languages.
- **Static analysis only.** Cannot detect crypto usage that's built
  dynamically (e.g. via `getattr`, string-built imports, or heavy
  metaprogramming).
- **No certificate parsing yet.** `.pem`/`.key`/`.pfx`/`.p12` files are
  intentionally excluded entirely (not read at all) until a dedicated,
  careful certificate-metadata module is built.
- **Pattern matching produces false positives by design.** A comment
  mentioning "AES" or a variable named `rsa_backup_flag` will be flagged.
  This is why confidence levels exist - low-confidence findings are hints,
  not conclusions.
- **AST analysis can produce false negatives.** Unusual code styles,
  dynamic dispatch, or unrecognized library aliases can cause real crypto
  usage to be missed entirely.
- **No dependency-file analysis yet** (e.g. checking `requirements.txt` for
  known-weak crypto libraries) - planned for a later phase.
- **No risk scoring or recommendations.** This tool only reports evidence
  of what it found and how confident it is - it does not judge whether
  anything is "safe" or "unsafe." That judgment belongs to the (not yet
  built) risk engine, which will use transparent, documented rules.

## Security notes

- Files with extensions `.pem`, `.key`, `.pfx`, `.p12` are never opened or
  read by this scanner - they are skipped entirely at the file-discovery
  stage.
- Files over 2MB are skipped (unlikely to be genuine small source files).
- Evidence snippets stored in the report are capped at 200 characters and
  are single lines - never a full file dump.

## Risk scoring methodology (Phase 2)

`risk_score = round(min(100, A + B + C) × confidence_multiplier)`

| Component | Range | Meaning | Source |
|---|---|---|---|
| A | 0-40 | Algorithm + quantum risk | `risk_engine/engine.py` + `rules.py` (NIST SP 800-131A Rev. 2, NIST IR 8547 draft) |
| B | 0-25 | Business criticality | User-supplied via `context.json`, default `UNKNOWN` = 10 pts (never silently LOW/HIGH) |
| C | 0-15 | Data-lifetime migration urgency | `risk_engine/mosca.py` - a simplified Mosca-style planning heuristic |
| multiplier | ×0.85 or ×1.0 | Evidence confidence | MEDIUM vs HIGH (LOW-confidence assets are never scored at all) |

`risk_level` buckets (**our own project's documented thresholds, not an official NIST classification**): 80-100 CRITICAL, 60-79 HIGH, 35-59 MEDIUM, 0-34 LOW.

`priority` (1-4, deterministic):
1. CRITICAL business criticality + quantum-vulnerable + data lifetime ≥ 10 years
2. (CRITICAL or HIGH business criticality) + quantum-vulnerable
3. risk_level is MEDIUM or HIGH
4. everything else

`migration_effort_hint` (LOW/MEDIUM/HIGH) is a real, evidence-based signal - the number of times the same algorithm appears project-wide - but it is **not** part of the numeric score. It's a tie-breaker/planning signal only.

### On the Mosca-style urgency calculation (`risk_engine/mosca.py`)

This is a deliberately narrowed version of Michele Mosca's well-known "x + y > z" framework. We only have real data for one side of that comparison (the user-supplied data lifetime), so `mosca.py` does **not** attempt to estimate migration time or a quantum-threat-horizon date - doing so would mean inventing numbers we have no basis for. It only expresses relative urgency from data lifetime. **It is not a prediction of when quantum computers capable of breaking current cryptography will exist.**

### User-supplied context

Business criticality and data lifetime **cannot be determined by scanning code** - they require human knowledge of the application. Supply them via a `context.json` file:

```json
{
  "business_criticality": "CRITICAL",
  "data_lifetime_years": 15
}
```

```bash
python main.py sample_project --context sample_context/critical_long_lifetime.json
```

If omitted, both are treated as `UNKNOWN` and this is made visible in every affected asset's `reasons`. See `sample_context/` for example files at different criticality/lifetime levels. Context is currently applied project-wide; per-file/per-component context is a natural future extension, not built in this phase.

### PQC recommendation layer (`recommendation/`)

A small, deterministic, purpose-based mapping - **not wired automatically into the risk score**, but included in the JSON output as `pqc_recommendation` per asset:

- Digital signatures → **ML-DSA** (NIST FIPS 204), with SLH-DSA (FIPS 205) noted as a conservative hash-based alternative
- Key establishment/exchange → **ML-KEM** (NIST FIPS 203)
- Ambiguous cases (e.g. `rsa.generate_private_key()` alone, which could be used for either signing or encryption) → **no recommendation given**, with an explicit rationale that guessing here would be bad advice
- Symmetric encryption (AES) and hashing (SHA-256) → explained as **not** part of the PQC family swap (see `recommendation/rules.py` for why)

### Migration tracking (architecture only)

`risk_engine/migration.py` defines `MigrationStatus` (NOT_STARTED / PLANNED / IN_PROGRESS / MIGRATED / VERIFIED) and a `MigrationRecord` shape. There is no persistence layer yet, so every asset in this phase's output is honestly reported as `NOT_STARTED` - this is architecture for a future phase (FastAPI + Supabase), not a working tracker yet.

### Quantum Readiness Score (documented, not computed)

A future project-level score (e.g. "42/100 before migration, 81/100 after") would be calculated as a criticality-weighted aggregate of `risk_score` across all non-MIGRATED/VERIFIED assets, inverted to a 0-100 "readiness" number. This is **not implemented in Phase 2** - with every asset currently `NOT_STARTED`, any number shown today would just be an inverse of total risk, not a real readiness measurement, so we're not fabricating one until migration tracking is real.

### Coverage / blind-spot reporting (`risk_engine/coverage.py`)

Every report includes a `coverage` block stating plainly what is and isn't scanned (Python source only; not certificates, binaries, containers, HSMs, cloud KMS, other languages) - so the tool never implies broader coverage than it has.

### External scanner adapter (architecture only)

`scanner/external/base.py` defines an `ExternalScannerAdapter` interface (one method: `run(project_path) -> list[CryptoAsset]`). No concrete adapter (e.g. CodeQL) is implemented. The rule that matters: **an external adapter only produces discovery findings in our `CryptoAsset` shape - it never produces its own risk score.** All risk scoring stays in `risk_engine/`, applied uniformly regardless of which scanner produced a finding. `main.py` does not import this module, so the project's behavior is unchanged whether or not this is ever implemented.

## Project structure

```
scanner/
    file_discovery.py   - finds safe, relevant files to scan
    pattern_detector.py - regex/keyword-based detection (low/medium confidence)
    ast_analyzer.py      - AST-based detection of real API usage (high confidence)
    models.py             - RawFinding and CryptoAsset data shapes
    normalizer.py         - converts RawFindings into report-ready CryptoAssets
    external/
        base.py             - adapter INTERFACE for future external scanners (not implemented)
risk_engine/
    rules.py              - classical/quantum risk rule table, NIST-cited
    engine.py               - applies rules.py to CryptoAssets -> RiskAssessment
    context.py                - BusinessCriticality/DataLifetime, user-supplied via context.json
    mosca.py                    - Mosca-style migration urgency heuristic (planning aid, not a prediction)
    scorer.py                     - combines engine + context + mosca into final RiskScore
    migration.py                    - MigrationStatus data model (architecture only, no persistence)
    coverage.py                      - what is/isn't scanned, reported honestly
    models.py                          - RiskAssessment data shape
recommendation/
    models.py              - PQCRecommendation data shape
    rules.py                 - purpose-based PQC direction mapping, NIST-cited
sample_context/           - example context.json files (critical/high/low criticality + lifetime)
tests/                    - one test file per module
sample_project/            - safe, synthetic code used for demos and tests
main.py                     - CLI entry point, orchestrates the full pipeline
```
