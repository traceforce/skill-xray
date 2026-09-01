"""Configuration for the opt-in LLM adjudication layer.

The layer is OFF by default and only turns on when the operator sets it up with THEIR
OWN API key. Everything is read from the environment; a key is never taken from a scanned
package, never logged, and never defaulted. Provider-agnostic: Anthropic (Claude), OpenAI,
and any OpenAI-compatible endpoint (opencode, OpenRouter, a local model, ...) via a base URL.

Env:
  SKILLXRAY_LLM_PROVIDER = anthropic | openai | openai-compatible   (required to enable)
  SKILLXRAY_LLM_MODEL    = model id            (default for anthropic/openai; required otherwise)
  SKILLXRAY_LLM_API_KEY  = the key                                  (on the vendor's own default
                           host only, falls back to ANTHROPIC_API_KEY / OPENAI_API_KEY; a custom
                           SKILLXRAY_LLM_BASE_URL always needs this key set explicitly)
  SKILLXRAY_LLM_BASE_URL = https origin[/path]  (required for openai-compatible; default otherwise)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from urllib.parse import urlsplit

__all__ = ["LLMConfig", "from_env", "LLMConfigError"]

_PROVIDERS = ("anthropic", "openai", "openai-compatible")
# Current-generation, classifier-grade defaults. These date -- the operator should set
# SKILLXRAY_LLM_MODEL for anything pinned; a retired id surfaces here as an endpoint error.
_DEFAULT_MODEL = {"anthropic": "claude-haiku-4-5", "openai": "gpt-5-mini"}
_DEFAULT_BASE = {"anthropic": "https://api.anthropic.com",
                 "openai": "https://api.openai.com/v1"}
_KEY_FALLBACK = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY",
                 "openai-compatible": "OPENAI_API_KEY"}


class LLMConfigError(Exception):
    """The LLM layer was asked for but is misconfigured (bad provider, missing key/url)."""


@dataclass(frozen=True)
class LLMConfig:
    provider: str
    model: str
    api_key: str = field(repr=False)   # keep the key out of the auto-generated repr (no log leak)
    base_url: str
    max_tokens: int = 1024
    timeout: int = 30

    def __post_init__(self):
        # Enforce the invariants on EVERY construction path, not just from_env(): LLMConfig/
        # build_client are public, so a direct LLMConfig(base_url="http://...") must not ship the
        # key and text over cleartext, and an unknown provider must not silently fall through to
        # the OpenAI-compatible protocol (HTTPLLMClient treats every non-anthropic value that way).
        object.__setattr__(self, "provider", (self.provider or "").strip().lower())
        if self.provider not in _PROVIDERS:
            raise LLMConfigError(
                "LLMConfig.provider must be one of %s (got %r)"
                % (", ".join(_PROVIDERS), self.provider))
        try:
            parts = urlsplit(self.base_url)
        except ValueError:
            raise LLMConfigError(
                "LLMConfig.base_url is not a valid URL (got %r)" % self.base_url) from None
        if (parts.scheme != "https" or not parts.netloc
                or "?" in self.base_url or "#" in self.base_url):
            # Test the RAW string for ?/#, not parts.query/fragment: a URL ending in a bare `?`
            # or `#` parses to an EMPTY (falsy) query/fragment but still mangles the appended path.
            raise LLMConfigError(
                "LLMConfig.base_url must be an https URL with a host and no query/fragment "
                "(got %r)" % self.base_url)
        object.__setattr__(self, "base_url", self.base_url.rstrip("/"))   # normalise on a frozen dc


def from_env(env=None):
    """Return an LLMConfig if the layer is enabled and fully configured, or None if it is
    not enabled (no provider set). Raises LLMConfigError when enabled but misconfigured, so
    a user who asks for --llm with a bad setup gets a clear error, never a silent no-op."""
    env = os.environ if env is None else env
    provider = (env.get("SKILLXRAY_LLM_PROVIDER") or "").strip().lower()
    if not provider:
        return None                              # layer not enabled: deterministic scan only
    if provider not in _PROVIDERS:
        raise LLMConfigError(
            "SKILLXRAY_LLM_PROVIDER must be one of %s" % ", ".join(_PROVIDERS))
    base_url = (env.get("SKILLXRAY_LLM_BASE_URL") or _DEFAULT_BASE.get(provider) or "").strip()
    if not base_url:
        raise LLMConfigError(
            "openai-compatible needs SKILLXRAY_LLM_BASE_URL (the endpoint origin)")
    try:
        parts = urlsplit(base_url)
    except ValueError:
        raise LLMConfigError("SKILLXRAY_LLM_BASE_URL is not a valid URL") from None
    # Require https + a real host, and no query/fragment: a cleartext scheme would send the key
    # and text in the clear, `https://` alone has no host to reach, and a query/fragment would be
    # mangled when a path like /chat/completions is appended. Test the RAW string for ?/# so a URL
    # ending in a bare `?`/`#` (empty, falsy query/fragment, not stripped by rstrip) is also caught.
    if parts.scheme != "https" or not parts.netloc or "?" in base_url or "#" in base_url:
        raise LLMConfigError(
            "SKILLXRAY_LLM_BASE_URL must be an https URL with a host and no query/fragment")
    base_url = base_url.rstrip("/")
    api_key = (env.get("SKILLXRAY_LLM_API_KEY") or "").strip()
    if not api_key:
        # The vendor-var fallback (ANTHROPIC_API_KEY/OPENAI_API_KEY) is used ONLY when the
        # request goes to the vendor's own default host; never hand a vendor key to a custom
        # SKILLXRAY_LLM_BASE_URL (which could be an attacker-chosen or openai-compatible endpoint).
        default_base = (_DEFAULT_BASE.get(provider) or "").rstrip("/")
        if default_base and base_url == default_base:
            api_key = (env.get(_KEY_FALLBACK[provider]) or "").strip()
        if not api_key:
            raise LLMConfigError(
                "no API key: set SKILLXRAY_LLM_API_KEY (the %s fallback applies only to the "
                "vendor's own host, not a custom SKILLXRAY_LLM_BASE_URL)" % _KEY_FALLBACK[provider])
    model = (env.get("SKILLXRAY_LLM_MODEL") or _DEFAULT_MODEL.get(provider) or "").strip()
    if not model:
        raise LLMConfigError("set SKILLXRAY_LLM_MODEL (no default for this provider)")
    return LLMConfig(provider=provider, model=model, api_key=api_key, base_url=base_url)
