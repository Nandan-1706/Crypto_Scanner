"""
models.py

Defines the shapes of data that flow through the scanner pipeline.

Two shapes matter here:

1. RawFinding - what pattern_detector.py and ast_analyzer.py each produce.
   It's intentionally minimal: "I saw something, here's what and how."

2. CryptoAsset - the final, normalized record that goes into the JSON report.
   normalizer.py is the ONLY module that creates these.

Keeping RawFinding and CryptoAsset separate (instead of one big class) means
the detectors stay simple and don't need to know about asset_id generation,
confidence policy, or the final report shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class DetectionMethod(str, Enum):
    """How a finding was detected. Kept explicit so the report never hides
    *why* the tool believes something - evidence traceability matters for
    a security tool."""
    PATTERN_MATCH = "pattern_match"
    AST_ANALYSIS = "ast_analysis"


class Confidence(str, Enum):
    """
    How much we trust a given finding.

    LOW    - a raw text/keyword match (e.g. the word "AES" appears somewhere).
              Could easily be a comment, a variable name, or a string unrelated
              to real usage.
    MEDIUM - a more specific text pattern (e.g. "hashlib.md5(" as a substring)
              that looks like real code but wasn't confirmed via AST.
    HIGH   - confirmed via AST analysis as an actual function/attribute call,
              so we know it's real code, not a comment or coincidental text.
    """
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class RawFinding:
    """
    A single, unprocessed detection from either pattern_detector.py or
    ast_analyzer.py. Both modules return a list of these in the same shape,
    so normalizer.py can treat them identically regardless of source.
    """
    file_path: str
    line_number: int | None
    algorithm: str                 # e.g. "MD5", "RSA", "AES"
    detection_method: DetectionMethod
    evidence: str                  # short, safe snippet - never a full file dump
    confidence: Confidence
    cryptographic_purpose: str | None = None  # e.g. "hashing", "key_generation" - only if we can actually tell
    key_size: int | None = None    # only set when explicitly present in code (e.g. key_size=2048) - never guessed


@dataclass
class CryptoAsset:
    """
    The normalized, report-ready record for one cryptographic finding.
    This is the ONLY shape that ends up in the final JSON output.
    """
    asset_id: str
    project: str
    file_path: str
    asset_type: str                # e.g. "algorithm_usage", "hash_usage"
    algorithm: str
    key_size: int | None
    cryptographic_purpose: str | None
    detection_method: DetectionMethod
    evidence: str
    confidence: Confidence
    line_number: int | None = None

    def to_dict(self) -> dict:
        """Convert to a plain dict of JSON-safe values (Enums -> their string value)."""
        return {
            "asset_id": self.asset_id,
            "project": self.project,
            "file_path": self.file_path,
            "asset_type": self.asset_type,
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "cryptographic_purpose": self.cryptographic_purpose,
            "detection_method": self.detection_method.value,
            "evidence": self.evidence,
            "confidence": self.confidence.value,
            "line_number": self.line_number,
        }
