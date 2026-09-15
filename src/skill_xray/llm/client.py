"""Multi-vendor LLM client for the adjudication layer.

One tiny interface -- complete(system, user) -> str -- over Anthropic, OpenAI, and any
OpenAI-compatible endpoint, using only the standard library (no vendor SDK dependency).
The adjudicator depends on the interface, not this class, so tests inject a fake client
and never touch the network.

Fail-closed: any transport, HTTP, or shape error is raised as LLMError; the caller turns
that into a degraded note and keeps the deterministic findings. The API key travels only in
the request header to the operator's configured endpoint, and is never logged or echoed."""

from __future__ import annotations

import http.client
import json
import re
import time
import urllib.error
import urllib.request

from .config import LLMConfig

__all__ = ["LLMClient", "HTTPLLMClient", "build_client", "LLMError", "LLMResponseError"]

_MAX_RESPONSE_BYTES = 1 << 20   # 1 MiB: a verdict JSON is tiny; bound a hostile/faulty huge body
_READ_CHUNK = 1 << 16           # 64 KiB read granularity, so the whole-request deadline is checked
# Transient "try again later" statuses to retry, so a single 429 does not kill the whole pass:
# rate-limit, the gateway/unavailable family, and Anthropic's 529 overloaded_error (a transient
# provider overload -- this client supports Anthropic, so treat it like 503, not a hard abort).
# A 500 is often a real app error, not transient, so it is NOT retried (fails closed immediately).
_RETRY_STATUS = frozenset({429, 502, 503, 504, 529})
_MAX_RETRIES = 3
_MAX_BACKOFF = 8.0

# OpenAI reasoning-model families (o1/o3/o4.../gpt-5.x) reject the classic `max_tokens` with a 400
# and require `max_completion_tokens`. Classic chat models and most openai-COMPATIBLE endpoints
# (vLLM, llama.cpp, Together, Groq) only understand `max_tokens`, so the switch is scoped to the
# real OpenAI provider on a reasoning-model name. `[-.]` after gpt-5 so a DOTTED minor version
# (gpt-5.1, gpt-5.1-codex) matches too, not just gpt-5 / gpt-5-mini.
_OPENAI_REASONING_RE = re.compile(r"(?:o[1-9]|gpt-5)(?:[-.]|$)")


def _openai_token_field(cfg):
    if cfg.provider == "openai" and _OPENAI_REASONING_RE.match(cfg.model.lower()):
        return "max_completion_tokens"
    return "max_tokens"


# Thinking-by-default Claude families reject the sampling fields (temperature/top_p/top_k) with
# a 400; they get low effort and a 4096-token output floor so reasoning cannot truncate the JSON.
_ANTHROPIC_THINKING_FAMILY_RE = re.compile(
    r"^claude-(?:opus-(?:4-[7-9]|5)|sonnet-5|fable|mythos)")
_REASONING_MIN_OUTPUT = 4096
_REASONING_EFFORT = "low"


class LLMError(Exception):
    """An LLM call could not be completed; the caller must fail closed. A plain LLMError is a
    TRANSPORT/endpoint failure (unreachable, HTTP error) -- the caller stops, since every file
    will fail the same way."""


class LLMResponseError(LLMError):
    """The endpoint answered (2xx) but the RESPONSE was unusable (not JSON, wrong shape, non-text
    content). The endpoint is alive, so the caller notes THIS file and continues to the next."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse to follow HTTP redirects: urllib would resend the request -- including the
    Authorization / x-api-key header (the operator's key) -- to the redirect target, possibly a
    different host. A 3xx from an API endpoint is unexpected, so returning None fails closed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class LLMClient:
    """Interface the adjudicator depends on. Implementations return the model's text."""

    def complete(self, system: str, user: str) -> str:
        raise NotImplementedError


class HTTPLLMClient(LLMClient):
    def __init__(self, config: LLMConfig):
        self.cfg = config
        # No-redirect opener; see _NoRedirectHandler for why.
        self._opener = urllib.request.build_opener(_NoRedirectHandler())

    def complete(self, system: str, user: str) -> str:
        return self._complete(system, user)

    def complete_structured(self, system: str, user: str, schema: dict) -> str:
        # Existing interceptors may enforce offline operation, routing or redaction.
        if getattr(self.complete, "__func__", None) is not _ORIGINAL_HTTP_COMPLETE:
            return self.complete(system, user)
        # Do not assume another provider supports OpenAI's strict schema contract.
        return self._complete(system, user, schema if self.cfg.provider == "openai" else None)

    def _complete(self, system: str, user: str, schema=None) -> str:
        if self.cfg.provider == "anthropic":
            url = self.cfg.base_url + "/v1/messages"
            headers = {"x-api-key": self.cfg.api_key, "anthropic-version": "2023-06-01",
                       "content-type": "application/json"}
            body = {"model": self.cfg.model, "max_tokens": self.cfg.max_tokens,
                    "system": system, "messages": [{"role": "user", "content": user}]}
            if _ANTHROPIC_THINKING_FAMILY_RE.match(self.cfg.model.lower()):
                body["max_tokens"] = max(self.cfg.max_tokens, _REASONING_MIN_OUTPUT)
                body["output_config"] = {"effort": _REASONING_EFFORT}
            else:
                body["temperature"] = 0
            return self._extract(self._post(url, headers, body), "anthropic")
        # openai and openai-compatible share the chat/completions shape
        url = self.cfg.base_url + "/chat/completions"
        headers = {"authorization": "Bearer %s" % self.cfg.api_key,
                   "content-type": "application/json"}
        token_field = _openai_token_field(self.cfg)
        body = {"model": self.cfg.model, token_field: self.cfg.max_tokens,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user}]}
        if token_field == "max_tokens":
            # Greedy decoding plus OpenAI's best-effort `seed`: removes one source of run-to-run
            # variance, guarantees nothing. Reasoning models reject both fields with a 400.
            body["temperature"] = 0
            body["seed"] = 0
        else:
            # Hidden reasoning shares the output cap; keep it low and the cap large enough.
            body[token_field] = max(self.cfg.max_tokens, _REASONING_MIN_OUTPUT)
            body["reasoning_effort"] = _REASONING_EFFORT
        if schema is not None:
            body["response_format"] = {"type": "json_schema", "json_schema": {
                "name": "finding_review", "strict": True, "schema": schema}}
        return self._extract(self._post(url, headers, body), "openai")

    def _read_bounded(self, req):
        """POST once and read the body under an ABSOLUTE wall-clock deadline, not just the
        per-socket-read timeout. Uses read1 (one recv, returns whatever arrived) so a continuous
        slow trickle cannot stay inside a single blocking read past the deadline; read (which waits
        to fill the buffer) could. The total is capped at _MAX_RESPONSE_BYTES."""
        deadline = time.monotonic() + self.cfg.timeout
        with self._opener.open(req, timeout=self.cfg.timeout) as resp:
            # urllib's default HTTPErrorProcessor raises HTTPError for every non-2xx (a refused 3xx
            # redirect included), so a returned resp is always 2xx.
            read1 = getattr(resp, "read1", None) or resp.read
            chunks, total = [], 0
            while total < _MAX_RESPONSE_BYTES:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("whole-request deadline exceeded")
                # urllib wraps http.client.HTTPResponse differently across Python releases. Reach
                # its standard-library socket when present and bound THIS blocking read to the
                # remaining whole-call budget, rather than granting every read cfg.timeout again.
                stream = getattr(resp, "fp", None)
                raw = getattr(stream, "raw", None)
                if raw is None:
                    raw = getattr(getattr(stream, "fp", None), "raw", None)
                sock = getattr(raw, "_sock", None)
                if sock is not None:
                    sock.settimeout(max(remaining, 0.001))
                chunk = read1(min(_READ_CHUNK, _MAX_RESPONSE_BYTES - total))
                if time.monotonic() > deadline:
                    raise TimeoutError("whole-request deadline exceeded")
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            if total >= _MAX_RESPONSE_BYTES:
                raise LLMResponseError("LLM response exceeded byte budget")
            return b"".join(chunks)

    @staticmethod
    def _retry_delay(exc, attempt):
        """Seconds to wait before a retry: the server's Retry-After when present and sane
        (0..60s), else capped exponential backoff. Bounds a rate-limited pass, never unbounded."""
        retry_after = exc.headers.get("Retry-After") if getattr(exc, "headers", None) else None
        if retry_after:
            try:
                secs = int(retry_after)
                if 0 <= secs <= 60:
                    return secs
            except (TypeError, ValueError):
                pass
        return min(0.5 * (2 ** attempt), _MAX_BACKOFF)

    def _post(self, url, headers, body):
        data = json.dumps(body).encode("utf-8")
        last_code = None
        for attempt in range(_MAX_RETRIES + 1):
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            try:
                raw = self._read_bounded(req)
            except urllib.error.HTTPError as exc:
                # A transient rate-limit/gateway status is retried with backoff, so one 429 does not
                # kill the whole pass; a persistent one exhausts retries and then fails closed. Do
                # NOT echo the response body -- it could leak the key or prompt.
                if exc.code in _RETRY_STATUS:
                    last_code = exc.code
                    if attempt < _MAX_RETRIES:
                        time.sleep(self._retry_delay(exc, attempt))
                        continue
                    break                       # retries exhausted: fail closed after the loop
                raise LLMError("LLM endpoint returned HTTP %s" % exc.code) from None
            except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException,
                    ValueError, RecursionError) as exc:
                # http.client.HTTPException (e.g. IncompleteRead) is not an OSError, so catch it
                # too: every transport failure must surface as LLMError, per the contract.
                raise LLMError("LLM endpoint unreachable: %s" % type(exc).__name__) from None
            try:
                return json.loads(raw)
            except (ValueError, TypeError, RecursionError) as exc:
                # RecursionError: a 2xx body of deeply nested arrays makes json.loads recurse past
                # the limit -- the endpoint is alive, so it is a per-response error, not transport.
                raise LLMResponseError(
                    "LLM response was not JSON: %s" % type(exc).__name__) from None
        raise LLMError("LLM endpoint returned HTTP %s (after %d retries)"
                       % (last_code, _MAX_RETRIES))

    @staticmethod
    def _extract(payload, shape):
        try:
            if shape == "anthropic":
                if payload.get("stop_reason") == "max_tokens":
                    raise LLMResponseError("LLM response was truncated")
                parts = payload["content"]
                text = "".join(p.get("text", "") for p in parts if isinstance(p, dict))
            else:
                if payload["choices"][0].get("finish_reason") in {"length", "content_filter"}:
                    raise LLMResponseError("LLM response was truncated or filtered")
                text = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError, AttributeError) as exc:
            raise LLMResponseError("bad LLM response shape: %s" % type(exc).__name__) from None
        if not isinstance(text, str):
            # structurally present but non-text content (a list/object) from an odd endpoint: a
            # per-response error, not a transport failure -- the caller notes it and continues.
            raise LLMResponseError("LLM response content was not text (%s)" % type(text).__name__)
        return text


# Capture once: replacing the class method must not bypass an installed interceptor.
_ORIGINAL_HTTP_COMPLETE = HTTPLLMClient.complete


def build_client(config: LLMConfig) -> LLMClient:
    """Build the real HTTP client for a config. Tests inject a fake LLMClient instead."""
    return HTTPLLMClient(config)
