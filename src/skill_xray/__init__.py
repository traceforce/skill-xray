"""skill-xray: read a skill package into a shared IR, and check it.

Ingest walks a package into files + decoded text; parse turns each file into one
shared representation (the IR) that later checks read; the checks report findings.
"""

from __future__ import annotations

from .checks import run_checks
from .findings import Finding, findings_to_dicts, vector_registry
from .ingest import (
    Artifact,
    Package,
    build_ledger,
    build_package,
    discover_skill_packages,
)
from .parse import (
    ParsedArtifact,
    ParsedPackage,
    parse_package,
)
from .resolve import (
    IngestLimitExceededError,
    Resolved,
    UnsafeInputError,
    resolved_input,
)
from .scan import scan

__version__ = "0.1.0"

__all__ = [
    "Artifact",
    "Package",
    "build_package",
    "build_ledger",
    "discover_skill_packages",
    "parse_package",
    "ParsedPackage",
    "ParsedArtifact",
    "run_checks",
    "scan",
    "vector_registry",
    "findings_to_dicts",
    "Finding",
    "resolved_input",
    "Resolved",
    "IngestLimitExceededError",
    "UnsafeInputError",
    "__version__",
]
