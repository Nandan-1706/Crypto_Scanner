"""
risk_engine/coverage.py

Reports what this prototype actually scans vs. what it does not, so the
tool never implies broader coverage than it has. This is intentionally
static, hand-maintained data for Phase 2 - a future phase could compute
this dynamically as more scanners/adapters are added, but for now the
truth is simple enough to state directly.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CoverageReport:
    scanned: list[str]
    not_scanned: list[str]

    def to_dict(self) -> dict:
        return {"scanned": self.scanned, "not_scanned": self.not_scanned}


def current_coverage() -> CoverageReport:
    return CoverageReport(
        scanned=[
            "Python source code (.py) - pattern matching + AST analysis",
        ],
        not_scanned=[
            "Other programming languages (Java, C/C++, Go, JavaScript, etc.)",
            "Certificates and key files (.pem, .key, .pfx, .p12) - deliberately excluded, not read at all",
            "Binary files and compiled artifacts",
            "Container images",
            "Hardware security modules (HSMs)",
            "Cloud KMS (AWS KMS, Azure Key Vault, GCP KMS, etc.)",
            "Third-party dependency source code (only import statements are inspected, not dependency internals)",
        ],
    )
