"""skill-xray: read a skill package into a file inventory and a coverage ledger.

This version does ingest only: it walks a package and reports what it read and
what it did not. It does not yet parse file contents or report findings.
"""

from __future__ import annotations

from .ingest import (
    Artifact,
    Package,
    build_ledger,
    build_package,
    discover_skill_packages,
)
from .resolve import (
    IngestLimitExceededError,
    UnsafeInputError,
    resolved_input,
)

__version__ = "0.1.0"

__all__ = [
    "Artifact",
    "Package",
    "build_package",
    "build_ledger",
    "discover_skill_packages",
    "resolved_input",
    "IngestLimitExceededError",
    "UnsafeInputError",
    "__version__",
]
