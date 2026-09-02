"""Opt-in LLM adjudication layer (off by default; the operator's own API key).

Adds the one detection the deterministic engines cannot generalise to -- semantic prompt
injection in skill text -- as an advisory, fail-closed pass over the instruction files.
"""

from __future__ import annotations

from .adjudicate import INSTRUCTION_KINDS, adjudicate, coverage_summary
from .client import HTTPLLMClient, LLMClient, LLMError, LLMResponseError, build_client
from .config import LLMConfig, LLMConfigError, from_env

__all__ = [
    "adjudicate",
    "coverage_summary",
    "INSTRUCTION_KINDS",
    "LLMClient",
    "HTTPLLMClient",
    "build_client",
    "LLMError",
    "LLMResponseError",
    "LLMConfig",
    "LLMConfigError",
    "from_env",
]
