"""Structured instruction-layer identity persistence correlation."""

from __future__ import annotations

import hashlib
import re

from ..findings import Finding, cap_findings
from ..ingest import IDENTITY_FILES

_INSTRUCTION_KINDS = {"skill_manifest", "instruction", "agent_identity"}
_IDENTITY_TARGET = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])(?:%s)(?![A-Za-z0-9_/\\-]|\.[A-Za-z0-9])"
    % "|".join(re.escape(name) for name in sorted(IDENTITY_FILES, reverse=True))
)
_WRITE = re.compile(
    r"(?i)\b(?:append|write|add|insert|save|persist|store|replace|overwrite|prepend|"
    r"update|edit|copy)\w*\b"
)
_QUOTED = re.compile(r"(?P<quote>['\"])(?P<content>[^'\"\n]{1,600})(?P=quote)")
_AGGRAVATOR = re.compile(
    r"(?i)\b(?:always\s+(?:obey|follow|prioriti[sz]e)|never\s+(?:reveal|disclose|remove)|"
    r"do\s+not\s+(?:reveal|disclose|mention|remove)|don['’]t\s+(?:reveal|disclose|mention)|"
    r"secretly|without\s+(?:telling|"
    r"notifying)|(?:cannot|must\s+not|do\s+not)\s+(?:be\s+)?(?:delete|remove)|"
    r"(?:hidden|concealed)\s+(?:rule|instruction|directive|content)|"
    r"(?:hide|conceal)\s+(?:this|the)\s+(?:rule|instruction|directive|content)|"
    r"higher\s+priority|(?:ignore|override)\s+(?:other|prior|previous)\s+instructions?|"
    r"(?:load|follow)\s+(?:this|it)\s+(?:on|every)\s+(?:startup|session))\b"
)
_CONTENT_INTRO = re.compile(
    r"(?i)(?:\b(?:following|below|this)\s+(?:block|text|content|instructions?)\b|:\s*$)"
)
_BLOCK_PREFIX = re.compile(r"^\s*(?:>|[-*+]\s|\d+[.)]\s|```)")
_DEFENSIVE_DESCRIPTION = re.compile(
    r"(?i)\b(?:check|detector|rule|scanner)\s+(?:detects|flags|identifies|reports)\b"
    r"[^.\n]{0,160}\b(?:that|which)\s+[^.\n]{0,80}"
    r"\b(?:append|write|add|insert|save|persist|store|replace|overwrite|prepend|"
    r"update|edit|copy)\w*\b"
)
_EVIDENCE_LIMIT = 400


def _clause_ends(text):
    quote = None
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote:
            escaped = True
            continue
        if char in "'\"" and not (
            char == "'" and index and index + 1 < len(text)
            and text[index - 1].isalnum() and text[index + 1].isalnum()
        ):
            quote = None if quote == char else char if quote is None else quote
            continue
        if quote is None and (
            char in ";!?" or (char == "." and (index + 1 == len(text) or text[index + 1].isspace()))
        ):
            yield index + 1


def _target_attached_before_write(clause, target, write):
    before = clause[:target.start()]
    between = clause[target.end():write.start()]
    introduced = re.search(r"(?i)\b(?:in|into|to|within)\s+[^;.!?]{0,200}$", before)
    connector = re.fullmatch(
        r"(?i)\s*,?\s*(?:(?:must|should|will|shall|is|be)\s+)*", between,
    )
    return bool(introduced and re.fullmatch(r"\s*,?\s*", between) or connector)


def _target_attached_after_write(clause, target, write):
    between = clause[write.end():target.start()]
    return bool(
        re.search(r"(?i)\b(?:to|into|in|within)\s+[`'\"]?(?:[~./\\\w-]+[/\\])?$", between)
        or re.fullmatch(r"(?i)\s+(?:the\s+)?(?:[~./\\\w-]+[/\\])?", between)
    )


def _operation_text(clause, write):
    tail = clause[write.start():]
    boundary = re.search(
        r"(?i)\s+\b(?:and|then)\s+(?:note|mention|describe|explain|report|"
        r"append|write|add|insert|save|persist|store|replace|overwrite|prepend|update|edit|copy)\b",
        tail,
    )
    return tail[:boundary.start()] if boundary else tail


def check(parsed) -> list[Finding]:
    findings = []
    for artifact in parsed.artifacts:
        if artifact.kind not in _INSTRUCTION_KINDS or not artifact.text:
            continue
        lines = artifact.text.splitlines()
        spans = artifact.markdown.prose_spans if artifact.markdown else ()
        for index, (start, end) in enumerate(spans):
            block = "\n".join(lines[start - 1:end])
            block = _DEFENSIVE_DESCRIPTION.sub(
                lambda match: "".join(
                    "\n" if char == "\n" else " " for char in match.group(0)
                ),
                block,
            )
            next_block = ""
            if index + 1 < len(spans) and spans[index + 1][0] - end <= 2:
                next_start, next_end = spans[index + 1]
                next_block = "\n".join(lines[next_start - 1:next_end])
            operation = None
            clause_start = 0
            boundaries = list(_clause_ends(block))
            for clause_end in (*boundaries, len(block)):
                clause = block[clause_start:clause_end]
                for write in _WRITE.finditer(clause):
                    target = _IDENTITY_TARGET.search(clause, write.end())
                    if target is not None and not _target_attached_after_write(
                        clause, target, write,
                    ):
                        target = None
                    if target is None:
                        preceding = list(_IDENTITY_TARGET.finditer(clause, 0, write.start()))
                        candidate = preceding[-1] if preceding else None
                        target = (
                            candidate
                            if candidate and _target_attached_before_write(clause, candidate, write)
                            else None
                        )
                    if target is None:
                        continue
                    persisted = _operation_text(clause, write)
                    introduced_block = bool(
                        next_block and _CONTENT_INTRO.search(persisted)
                        and _BLOCK_PREFIX.search(next_block)
                    )
                    correlated = persisted + ("\n" + next_block if introduced_block else "")
                    content = next(
                        (match.group("content") for match in _QUOTED.finditer(correlated)
                         if _AGGRAVATOR.search(match.group("content"))),
                        None,
                    )
                    if content is None and _AGGRAVATOR.search(persisted):
                        content = persisted
                    elif content is None and introduced_block and _AGGRAVATOR.search(next_block):
                        content = next_block
                    if content is not None:
                        operation = clause_start, target, write, content
                        break
                if operation is not None:
                    break
                clause_start = clause_end
            if operation is None:
                continue
            clause_start, target, write, content = operation
            before_target = block[:clause_start + target.start()]
            line = start + before_target.count("\n")
            column = clause_start + target.start() - before_target.rfind("\n")
            shown = content[:_EVIDENCE_LIMIT]
            findings.append(Finding(
                vector="SXV-005", rule="identity-persistence-write", severity="critical",
                path=artifact.rel, line=line, column=column,
                message=("instructs the agent to persist concealed or priority instructions "
                         "in `%s`" % target.group(0)),
                evidence={
                    "identity_target": target.group(0),
                    "persisted_content": shown,
                    "content_length": len(content),
                    "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                    "truncated": len(content) > _EVIDENCE_LIMIT,
                    "write_verb": write.group(0),
                },
            ))
    return cap_findings(findings)
