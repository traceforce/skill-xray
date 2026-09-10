"""One logical-call and input-byte budget shared by both LLM passes."""

import json

from .client import LLMError, LLMResponseError


class LLMBudgetError(LLMError):
    pass


class LLMSession:
    def __init__(self, client, max_calls=25, max_bytes=1 << 20):
        if (type(max_calls) is not int or max_calls < 0
                or type(max_bytes) is not int or max_bytes < 0):
            raise ValueError("LLM budgets must be non-negative integers")
        self.client, self.max_calls, self.max_bytes = client, max_calls, max_bytes
        self.calls = self.input_bytes = self.failures = 0
        self.unavailable = False

    def complete(self, system, user, *, response_schema=None):
        if self.unavailable:
            raise LLMError("session unavailable")
        size = len(system.encode("utf-8")) + len(user.encode("utf-8"))
        if response_schema is not None:
            size += len(json.dumps(response_schema, sort_keys=True, ensure_ascii=False).encode())
        if self.calls >= self.max_calls or self.input_bytes + size > self.max_bytes:
            raise LLMBudgetError("shared LLM budget exhausted")
        self.calls += 1
        self.input_bytes += size
        try:
            structured = getattr(self.client, "complete_structured", None)
            reply = (structured(system, user, response_schema)
                     if response_schema is not None and callable(structured)
                     else self.client.complete(system, user))
            if not isinstance(reply, str) or len(reply.encode("utf-8")) > 16384:
                raise LLMResponseError("response exceeds text budget")
            return reply
        except LLMResponseError:
            self.failures += 1
            raise
        except (LLMError, OSError):
            self.failures += 1
            self.unavailable = True
            raise LLMError("session transport failure") from None
        except Exception:
            self.failures += 1
            raise

    def usage(self):
        identity = {}
        for name, default in (("provider", "custom"), ("model", "unknown")):
            try:
                value = getattr(getattr(self.client, "cfg", None), name, default)
            except Exception:
                value = None
            identity[name] = (value if type(value) is str and 0 < len(value) <= 200
                              and value == value.strip() and value.isprintable() else "unknown")
        return {"calls": self.calls, "input_bytes": self.input_bytes,
                **identity,
                "failures": self.failures, "unavailable": self.unavailable,
                "max_calls": self.max_calls, "max_input_bytes": self.max_bytes,
                "unit": "logical-completions; transport retries remain separately bounded"}
