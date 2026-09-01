"""
normalizer.py

Converts RawFinding objects (from pattern_detector.py and ast_analyzer.py)
into the final CryptoAsset records used in the JSON report.

This is the ONLY module that:
  - assigns asset_id values
  - decides the asset_type label
  - attaches the project name

Keeping this logic in one place means the detectors never have to agree on
ID formats or report structure - they just produce RawFindings, and this
module is the single source of truth for turning those into report data.
"""

from __future__ import annotations

import uuid

from scanner.models import CryptoAsset, RawFinding

# Simple, explicit mapping from algorithm name to a human-readable asset
# type category. Kept as a plain dict (not inferred/guessed) so it's easy to
# review and extend.
_ASSET_TYPE_BY_ALGORITHM: dict[str, str] = {
    "RSA": "asymmetric_key_usage",
    "ECC": "asymmetric_key_usage",
    "ECDSA": "signature_usage",
    "ECDH": "key_exchange_usage",
    "AES": "symmetric_encryption_usage",
    "SHA-256": "hash_usage",
    "SHA-1": "hash_usage",
    "MD5": "hash_usage",
    "cryptography_library": "library_import",
    "cryptography.hazmat": "library_import",
    "hashlib": "library_import",
}

_DEFAULT_ASSET_TYPE = "cryptographic_indicator"


def normalize(findings: list[RawFinding], project_name: str) -> list[CryptoAsset]:
    """
    Convert a flat list of RawFindings (mixed sources - pattern and AST)
    into a list of CryptoAsset records, each with a unique asset_id.

    No deduplication is performed here in Phase 1: if both the pattern
    detector and the AST analyzer flag the same line, BOTH findings are kept
    as separate assets. This is a deliberate, documented choice - collapsing
    them would require deciding which one "wins," and that's a risk-engine
    style judgment call we're not making inside the normalizer.
    """
    assets: list[CryptoAsset] = []

    for finding in findings:
        asset_type = _ASSET_TYPE_BY_ALGORITHM.get(finding.algorithm, _DEFAULT_ASSET_TYPE)

        assets.append(CryptoAsset(
            asset_id=f"asset-{uuid.uuid4().hex[:12]}",
            project=project_name,
            file_path=finding.file_path,
            asset_type=asset_type,
            algorithm=finding.algorithm,
            key_size=finding.key_size,
            cryptographic_purpose=finding.cryptographic_purpose,
            detection_method=finding.detection_method,
            evidence=finding.evidence,
            confidence=finding.confidence,
            line_number=finding.line_number,
        ))

    return assets
