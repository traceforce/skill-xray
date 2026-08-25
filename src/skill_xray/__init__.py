"""skill-xray: read a skill package into a shared IR and a coverage ledger.

Ingest walks a package into files + decoded text; parse turns each file into one
shared representation (the IR) that later checks read. It does not yet report findings.
"""

from __future__ import annotations

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
    "resolved_input",
    "Resolved",
    "IngestLimitExceededError",
    "UnsafeInputError",
    "__version__",
]
