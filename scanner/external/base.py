"""
scanner/external/base.py

The interface a future external scanner adapter (e.g. CodeQL) would
implement. NOT implemented here - this is architecture only, per the spec:
"Do NOT implement CodeQL yet."

Design rule that must never be violated by any future adapter:
An external adapter's job is DISCOVERY ONLY. It converts whatever an
external tool found into our own CryptoAsset shape (scanner/models.py) -
the SAME shape our own scanner produces. It must never attach a risk score,
risk level, or any risk_engine output. All risk scoring happens in
risk_engine/, applied uniformly to CryptoAssets regardless of which
scanner (ours or external) produced them.

Because main.py does not import anything from this module today, the
project's behavior is completely unchanged whether or not a future adapter
gets implemented here.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from scanner.models import CryptoAsset


class ExternalScannerAdapter(ABC):
    """
    Any future external-tool integration implements this one method.
    Example (not implemented): a CodeQLAdapter that runs a CodeQL query
    pack against the project and maps CodeQL results into CryptoAssets.
    """

    @abstractmethod
    def run(self, project_path: str | Path) -> list[CryptoAsset]:
        """
        Run the external tool against `project_path` and return findings
        already converted into our CryptoAsset shape.

        Implementations MUST NOT:
          - set any risk_engine field (there is none on CryptoAsset - by
            design, risk is computed later, uniformly, by risk_engine/)
          - invent key_size, cryptographic_purpose, or any other field the
            external tool didn't actually determine (same "no invented
            values" rule that applies to our own scanner)
        """
        raise NotImplementedError
