"""Instruction-lane text attacks over the IR's markdown/raw text.

Three engines that all read the instruction lane -- artifacts whose kind is skill_manifest,
instruction, or agent_identity and whose text is present (README/doc and configs are out of
scope). Every finding is a directive addressed to the model rather than to the task:

  - SXV-027 (hidden agent directive): a directive to the agent hidden in an HTML comment.
    A markdown renderer drops `<!-- ... -->`, so a human reviewer sees a clean page while
    the model reads and follows the comment. Scanned on the RAW text -- markdown-it drops
    the comment, so .markdown carries nothing usable here.
  - SXV-028/029/030/031 (injected model-directives): instruction-override/jailbreak,
    anti-refusal, cross-session memory-persistence, and covert behaviour-manipulation
    directives in prose. Fenced code is skipped (an example, not live prose), and a
    line that DESCRIBES the attack for detection or defence is suppressed, not reported,
    so a legitimate security skill does not trip the check.
  - SXV-011 (credential read directed to egress): the instruction lane directing the agent
    to READ a high-specificity credential artifact AND send it to a network destination,
    but only when the governing skill grant can actually reach the network and the governing
    imperative is positive (an instruction to do it, not a prohibition or anti-pattern).
  - SXV-041 (remote instruction loading): the instruction lane directing the agent to FETCH
    remote content at runtime and FOLLOW/EXECUTE it as instructions (progressive disclosure).
    The package scans clean because the real directives live at a URL the reviewer never sees.
    Fires only when the fetched content is characterised AS instructions to obey (not a plain
    "see the docs at <url>" pointer); a fenced install one-liner is treated as an example.

Reads the IR only: raw .text, shared .markdown prose/code spans, and the governing
skill_manifest's .frontmatter/.grants. Never re-parses, never touches the fs."""

from __future__ import annotations

import hashlib
import re

from ..findings import Finding

# Standing agent instructions are part of the instruction lane.
_LANE_KINDS = {"skill_manifest", "instruction", "agent_identity"}
# Referenced prose is lifted; scripts/configs remain in their own lanes.
_LIFTABLE_KINDS = {"doc", "other"}

# --- hidden HTML comment (SXV-027) -------------------------------------------
def _html_comments(text):
    """Yield ``(start, body)`` in one forward pass; repeated unclosed openers stay linear."""
    cursor = 0
    while True:
        start = text.find("<!--", cursor)
        if start < 0:
            return
        end = text.find("-->", start + 4)
        if end < 0:                              # unterminated: CommonMark hides it to end-of-file
            yield start, text[start + 4:]
            return
        yield start, text[start + 4:end]
        cursor = end + 3


# Hidden comments need an addressed action, executable signal, or strong injection phrase.
_COMMENT_ADDRESSEE_RE = re.compile(
    r"\b(?:you|your|yourself|the model|system prompt)\b|"
    r"(?<![/\w-])(?:assistant|agent|claude|gpt)\b", re.I)
_COMMENT_ACTION_RE = re.compile(
    r"\b(?:ignore|disregard|forget|override|must|always|never|do not|don'?t|"
    r"run|execute|install|download|fetch|send|upload|post|exfiltrat\w*|"
    r"read|delete|remove|follow|obey|comply|reply|respond)\b", re.I)
# Bare tool names and URLs are insufficient; executable shapes stand alone.
_COMMENT_EXEC_RE = re.compile(
    r"\b(?:curl|wget|bash|zsh|eval|exec|chmod|sudo|scp|ncat|"
    r"python|pip|npm|npx|node|base64|powershell|iwr|irm)\b"
    r"\s+(?:-{1,2}\w|\.?/|~/|https?://|['\"]|\S+\.(?:sh|py|js|rb|pl|ps1|exe|bat)\b)|"
    r"\brm\s+-|\|\s*(?:ba|z)?sh\b|"
    r"\b(?:curl|wget|fetch|download|source|load|run|execute|import)\b[^\n]{0,24}https?://", re.I)
# Strong standalone directives need no addressee.
_COMMENT_STRONG_RE = re.compile(
    r"\b(?:ignore|disregard|forget|override)\b[^\n]{0,24}"
    r"\b(?:instruction|rule|guideline|prompt|context|directive)s?\b|"
    r"\bjailbreak\b|\bdeveloper mode\b|\bDAN\b|"
    r"\b(?:never|do not|don'?t)\s+refuse\b|\bno disclaimers?\b", re.I)


def _comment_is_directive(body):
    return bool(_COMMENT_EXEC_RE.search(body) or _COMMENT_STRONG_RE.search(body)
                or (_COMMENT_ADDRESSEE_RE.search(body) and _COMMENT_ACTION_RE.search(body)))

# --- injected model-directives (SXV-028/029/030/031) -------------------------
_DIRECTIVE_RULES = (
    ("SXV-028", "instruction-override", "high", re.compile(
        r"\b(?:ignore|disregard|forget|override|overrule|supersede|replace|reset|wipe)\s+"
        r"(?:all\s+|any\s+|every\s+|each\s+|the\s+|your\s+|my\s+|our\s+|"
        r"(?:the\s+)?(?:previous|prior|above|earlier|preceding|system|current|initial|original)"
        r"\s+)*"
        r"(?:instruction|rule|guideline|prompt|directive|constraint|direction|command|order|"
        r"message)s?\b|"
        r"\b(?:enter|enable|activate|switch to|into)\s+\w{0,12}\s*jailbreak\b|"
        r"\bjailbreak mode\b|\bdeveloper mode\b|\bDAN mode\b|"
        r"\byou are now\b[^.\n]{0,24}\b(?:DAN|unrestricted|jailbroken|an ai with no)\b|"
        r"\b(?:act as|pretend (?:to be|you are|you have)|roleplay as|behave as)\b[^.\n]{0,40}"
        r"\b(?:no|without|free of|zero)\b[^.\n]{0,16}"
        r"\b(?:restrictions?|rules?|limits?|filters?|guidelines?|constraints?|guardrails?)\b",
        re.I)),
    ("SXV-029", "anti-refusal", "medium", re.compile(
        r"\b(?:never|not|un(?:able|allowed)|cannot|can'?t|must not|may not|shall not|"
        r"(?:do|does|will|should|would)\s+not|don'?t|are\s+not\s+(?:to|allowed))"
        r"\s+(?:to\s+|ever\s+)*refuse\b|"
        r"\balways\s+comply\b|\bcomply with (?:every|any|all)\b|\banswer (?:every|any|all)\b|"
        r"\bno disclaimers?\b|\bwithout (?:any )?disclaimers?\b|"
        r"\bwithout (?:any )?(?:safety|security|ethical|content) warnings?\b|"
        r"\b(?:answer|respond|reply|comply|proceed|continue|act|do so)\b[^.\n]{0,24}"
        r"\bwithout (?:any )?warnings?\b|"
        r"\b(?:skip|omit|remove|drop|strip)\s+(?:the\s+|any\s+|all\s+)?(?:disclaimer|warning)s?\b|"
        r"\bignore (?:your |the )?(?:safety |content |ethical )?(?:guideline|policy|policies|rule)"
        r"s?\b|"
        r"\b(?:bypass|circumvent|disable|ignore)\s+(?:the |your )?"
        r"(?:safety|content|refusal|filter|restriction|guardrail|limit)s?\b", re.I)),
    ("SXV-030", "memory-persistence", "medium", re.compile(
        r"\balways remember\b[^.\n]{0,60}(?:future|forever|permanent|from now on|every session)|"
        r"\b(?:remember|keep|retain|memori[sz]e)\s+(?:this|that|it|the following)\b[^.\n]{0,40}"
        r"(?:for )?(?:all |every |the )?(?:upcoming|future|subsequent|later) "
        r"(?:chats?|conversations?|sessions?|interactions?)|"
        r"\b(?:remember|keep|retain|memori[sz]e)\s+(?:this|that|it|the following)\b[^.\n]{0,24}"
        r"(?:forever|permanently|from now on|for good|indefinitely)|"
        r"\b(?:remember|persist|retain|keep)\s+(?:this|it|these|the following)\s+"
        r"across\s+(?:all\s+|future\s+)*sessions\b|"
        r"\b(?:persist|store|save|write|commit|memori[sz]e)\s+"
        r"(?:this|it|these|the following|everything|all of this|what i tell you)\b[^.\n]{0,30}"
        r"(?:in|to|into) "
        r"(?:your (?:long[- ]?term |persistent |durable )?memory|long[- ]?term memory)\b", re.I)),
    ("SXV-031", "behavior-manipulation", "medium", re.compile(
        # Ambiguous manipulation remains in the semantic lane.
        r"\bmanipulat\w*\s+(?:the\s+)?"
        r"(?:users?|operator|human|customer|reader|audience|them|victim)\b"
        r"(?!\s+(?:interface|object|record|profile|session|account|data|table|row|cart|id|agent|"
        r"input|list|array|string|dom|element|settings?|prefs?)\b|['’]s)|"
        r"\b(?:covertly|secretly|surreptitiously|stealthily|clandestinely|deceptively)\b"
        r"[^.\n]{0,20}\b(?:steer|influence|manipulat\w*|coerc\w*|deceiv\w*|mislead\w*)\b|"
        r"\b(?:steer|influence|manipulat\w*|coerc\w*|deceiv\w*|mislead\w*)\b[^.\n]{0,20}"
        r"\b(?:covertly|secretly|surreptitiously|stealthily|clandestinely|deceptively)\b",
        re.I)),
)
# Defensive suppression requires security-specific framing before the match.
_DEFENSIVE_RE = re.compile(
    r"\b(?:detect\w*|prevent\w*|guard(?:ing)? against|defend(?:ing)? against|"
    r"block(?:list|s|ed|ing)?|flag(?:s|ged|ging)?|reject(?:s|ed|ing)?|warn(?:s|ed|ing)? about|"
    r"mitigat\w*|red[- ]?team\w*)\b[^.;\n]{0,100}\b(?:prompt injection|jailbreaks?|"
    r"instruction injection|credential[- ]exfil(?:tration)?|exfiltration|remote (?:content|"
    r"instructions?)|malicious (?:skill|prompt|instruction|directive|payload)|unsafe "
    r"(?:prompt|instruction|directive|payload)|attack(?:s|er)?|abuse|"
    # framing that DESCRIBES an injection rather than naming it: "flags any document/input/prompt
    # that tells/instructs the model to ...", so a scanner SKILL.md does not report itself
    r"(?:untrusted |malicious |hostile |any )*(?:document|input|prompt|instruction|text|"
    r"content|message|payload|file|skill)s?\s+(?:that|which)\s+"
    r"(?:tells?|instructs?|asks?|directs?|tries?|attempts?|says?|orders?|commands?))\b[^.;\n]*$|"
    r"\b(?:is an? (?:example|attempt|indicator) of|do not follow|never comply with)\b[^.;\n]*$",
    re.I)
_DEFENSIVE_DETAIL_RE = re.compile(
    r"\b(?:such as|for example|the following|following|(?:skills?|prompts?|instructions?|"
    r"payloads?|jailbreaks?|prompt injection|remote instructions?|attacks?|abuse|documents?|"
    r"inputs?|texts?|contents?|messages?|files?) (?:that|which)|"
    r"is an? (?:example|indicator) of|do not follow|never comply with)\b", re.I)


def _is_defensive_frame(text):
    match = _DEFENSIVE_RE.search(text or "")
    frame = text[match.start():] if match else ""
    return bool(match and _DEFENSIVE_DETAIL_RE.search(frame))
# Third-person service claims and product/license copy are not model directives.
_ANTIREFUSAL_BENIGN_RE = re.compile(
    r"\b(?:the|this|that|our|a|an|it|its|they|their)\s+\w+\s+"
    r"(?:will|would|does|can|shall|may)\s+never\s+refuse\b|"
    r"\bno disclaimers?\s+(?:or|and|,)\s*(?:no\s+)?(?:warrant|liabilit|guarantee)", re.I)
# A prohibition on an attack action is defensive guidance, not the attack.  Keep this
# action-specific: ``never refuse`` is itself an anti-refusal directive and must still fire.
_NEGATED_ATTACK_ACTION_RE = re.compile(
    r"\b(?:do not|don'?t|never|must not|must never|cannot|can'?t|will not|won'?t|"
    r"should not|shouldn'?t)\s+(?:ever\s+|attempt to\s+|try to\s+)*"
    r"(?:ignore|disregard|override|overrule|supersede|bypass|circumvent|disable|"
    r"skip|omit|remove|drop|strip|enable|activate)\b", re.I)
# Example framing must precede the directive.
_EXAMPLE_INTRO_RE = re.compile(
    r"\b(?:such as|e\.?g\.?|i\.?e\.?|for example|for instance|a typical|an example|"
    r"example|payload|looks? like|reads?|the following|as follows|shown below|"
    r"the one (?:below|above)|like this|as shown|below(?: this)?|"
    r"might (?:say|write|include|contain|read)|would (?:say|write|read))\b\s*:?|"
    r":\s*[\"']", re.I)
_DEFENSIVE_WINDOW = 2       # SXV-011 only: lines each side searched for a defensive context

# --- credential-read directed to egress (SXV-011) ----------------------------
_CRED_HIGH = [
    (r"~?/?\.aws/credentials", "aws_credentials"),
    (r"~?/?\.ssh/id_(?:rsa|ed25519|ecdsa|dsa)\b(?!\.pub)", "ssh_private_key"),
    (r"\bid_(?:rsa|ed25519)\b(?!\.pub)", "ssh_private_key"),   # .pub is a PUBLIC key, not a secret
    (r"~?/?\.netrc\b", "netrc"),
    (r"~?/?\.config/gh/hosts\.ya?ml", "gh_token_store"),
    (r"~?/?\.claude/settings(?:\.local)?\.json", "agent_settings"),
    (r"~?/?\.docker/config\.json", "docker_registry_auth"),
    (r"~?/?\.kube/config\b", "kubeconfig"),
    (r"~?/?\.gnupg/", "gpg_keyring"),
    # kept in sync with ingest's SECRET_FILES set -- these are all first-class credential stores.
    (r"~?/?\.git-credentials\b", "git_credentials"),
    (r"~?/?\.npmrc\b", "npm_authtoken"),
    (r"~?/?\.pypirc\b", "pypi_credentials"),
    (r"~?/?\.config/gcloud/(?:application_default_credentials|credentials)\.\w+", "gcp_adc"),
    (r"~?/?\.config/gcloud/legacy_credentials", "gcp_gcloud"),
    (r"~?/?\.azure/(?:accessTokens\.json|azureProfile\.json|msal_token_cache\.\w+)", "azure_token"),
    (r"/var/run/secrets/kubernetes\.io/serviceaccount/token", "kube_sa_token"),
]
# Generic PEM files are too common to count as high-specificity credentials.
_CRED_HIGH_RX = [(re.compile(p, re.I), k) for p, k in _CRED_HIGH]
_CRED_CORROB_RX = re.compile(r"(?<![\w./-])\.env(?:\.local|\.production)?\b", re.I)
# Split reads and egresses must share a secret identifier or credential-specific back-reference.
_LINK_WINDOW = 10           # sanity bound on the split-line linkage distance
_CRED_BACKREF_RE = re.compile(
    r"\bthe (?:key|keys|private key|credential|credentials|secret|secrets|"
    r"token|tokens|password|passwords|api key)\b|\b(?:its|their) (?:contents?|value)\b|"
    r"\bwhat (?:you|we)(?:'ve| have)? read\b|\bwhat was read\b|"
    r"\b(?:everything|all|the (?:contents?|files?|data|output|snapshot)) "
    r"(?:you|we)(?:'ve| have)? read\b", re.I)
_VARLINK_RE = re.compile(r"\$\w+|\b[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]*\b")
# Destination hosts do not link; URL path, query, and userinfo can carry a secret.
_URL_HOST_RE = re.compile(r"://(?:[^/@?#\s]*@)?([^/?#\s]+)")


def _egress_host_tokens(url):
    m = _URL_HOST_RE.search(url or "")
    return _vartokens(m.group(1)) if m else set()


def _vartokens(s):
    """Normalised concrete identifiers on a line (leading $ stripped, case-folded)."""
    return {t.lstrip("$").lower() for t in _VARLINK_RE.findall(s)}

_EGRESS_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
_EGRESS_VERB_RE = re.compile(
    r"\bPOST(?:ing|ed)?\b|\bPUT(?:ting)?\b|--data-binary|--data\b|-d @|"
    r"\bcurl\b[^\n]*\s-T\b|\bupload(?:s|ing)?\b|\bexfiltrat|\bcurl -X POST\b|"
    # the sending verbs the negation list already knows, so a finding can be raised on the same
    # vocabulary it is suppressed on (send/transmit/share/forward/leak/email/push/deliver/relay)
    r"\b(?:send|transmit|share|forward|leak|email|mail|push|deliver|relay)\b"
    r"[^.\n]{0,30}?\b(?:it|them|its?|the(?:ir)?|to|with|at)\b", re.I)
# Bare GET exfiltration is handled separately and requires a secret-linked URL token.
_FETCH_VERB_RE = re.compile(
    r"\bcurl\b|\bwget\b|\bfetch\b|\bInvoke-WebRequest\b|\bInvoke-RestMethod\b|"
    r"\biwr\b|\birm\b|\bhttpie\b|\bhttps?\b(?!://)", re.I)
_NEG_SAME_LINE_RE = re.compile(
    r"\b(?:do not|don'?t|never|must not|refuse to|avoid)\s+"
    r"(?:read|open|access|touch|load|include|quote|print|expose|collect|"
    r"send|transmit|upload|post|share|exfiltrat\w*|leak|forward|email|expose)\b|"
    r"\bexclud(?:e|ed|ing)\b|\bblocklist\b|\bblacklist\b|\bprohibit", re.I)
_ANTIPATTERN_RE = re.compile(r"ANTI-?PATTERN|do not run|never run|bad example|"
                             r"vulnerable example|counter-?example", re.I)
_LIST_ITEM_RE = re.compile(r"^\s*(?:[-*+]\s|\d+[.)]\s)")

_BASH_TOOLS = {"Bash", "Shell", "Terminal", "Execute"}
_NETWORK_TOOLS = {"WebFetch", "WebSearch"}
# Agent tools that genuinely cannot reach the network. Anything else -- an MCP tool, Task (which
# spawns a subagent with its own tools), or an unrecognised name -- fails OPEN as network-capable,
# the way an undeclared manifest does, rather than silently switching the credential detector off.
_LOCAL_ONLY_TOOLS = {"Read", "Write", "Edit", "MultiEdit", "NotebookEdit",
                     "Glob", "Grep", "LS", "TodoWrite", "NotebookRead"}
_NETWORK_SINGLE = {"curl", "wget", "nc", "ncat", "socat", "ssh", "scp", "sftp",
                   "http", "httpie", "python", "python3", "node", "npx", "perl", "ruby",
                   "git", "gh", "hub", "pip", "pip3", "pipx", "poetry", "uv", "npm", "yarn",
                   "pnpm", "bun", "deno", "aws", "gcloud", "gsutil", "az", "kubectl", "helm",
                   "docker", "podman", "rsync", "rclone", "aria2c", "ftp", "telnet", "openssl",
                   "apt", "apt-get", "apk", "brew", "go", "cargo", "mvn", "gradle"}
# Unknown or command-delegating tools fail open as network-capable.
_LOCAL_ONLY_CMDS = {"ls", "cat", "grep", "echo", "head", "tail", "cut",
                    "sort", "uniq", "wc", "tr", "cp", "mv", "rm", "mkdir", "touch", "chmod",
                    "chown", "diff", "tee", "date", "pwd", "basename", "dirname", "test", "true",
                    "false", "sleep", "which", "printf", "jq", "yq", "gzip", "gunzip"}


def _basename_any(token):
    """Basename of a command token independent of the scanner's host OS, so
    `C:\\tools\\curl.exe` and `curl` compare equal regardless of where the scan runs."""
    tail = token.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower()
    for suffix in (".exe", ".cmd", ".bat", ".com", ".ps1"):
        if tail.endswith(suffix):
            return tail[: -len(suffix)]
    return tail


def _grant_tokens(pattern):
    """(command, tokens) from a grant paren-spec: strip trailing ':*', else take the
    substring before the first ':', then whitespace-split (monolith Grant.__init__)."""
    if pattern is None:
        return None, []
    cmd = pattern.strip()
    if cmd.endswith(":*"):
        cmd = cmd[:-2]
    elif ":" in cmd:
        cmd = cmd.split(":", 1)[0]
    cmd = cmd.strip()
    return cmd, [t for t in cmd.split() if t]


def _reaches_network(grant):
    """Reconstruct monolith Grant.reaches_network from the IR's data-only Grant."""
    if grant.tool in _NETWORK_TOOLS:
        return True
    if grant.tool not in _BASH_TOOLS:               # non-bash: known-local tools cannot reach out,
        return grant.tool not in _LOCAL_ONLY_TOOLS   # MCP / Task / unrecognised fail open
    command, tokens = _grant_tokens(grant.pattern)
    if grant.pattern is None or command in ("", "*", "**"):   # wildcard bash -> anything
        return True
    if not tokens:
        return True
    cmd0 = _basename_any(tokens[0])
    if cmd0 in _NETWORK_SINGLE:
        return True
    return cmd0 not in _LOCAL_ONLY_CMDS


def _reach_is_fail_open(grant):
    """True when a grant counts as network-capable ONLY by the fail-open rule (an unrecognized
    non-bash tool), not a proven reach (WebFetch/WebSearch or a bash network command). Used to
    grade SXV-011 severity: an unproven reach must not assert certainty at critical."""
    return (grant.tool not in _NETWORK_TOOLS and grant.tool not in _BASH_TOOLS
            and grant.tool not in _LOCAL_ONLY_TOOLS)


def _is_table_row(raw):
    s = raw.strip()
    return s.startswith("|") and s.count("|") >= 2


def _fenced_lines(markdown, raws):
    """(code lines, block start by line) from the shared CommonMark source spans."""
    in_fence = set()
    open_by_line = {}
    if markdown is None:
        return in_fence, open_by_line
    for start, end in getattr(markdown, "code_spans", ()):
        for ln in range(start, min(end, len(raws)) + 1):
            in_fence.add(ln)
            open_by_line[ln] = start
    return in_fence, open_by_line


# --- remote instruction loading (SXV-041) ------------------------------------
# Remote content must be tied to a follow or execution cue; ordinary doc links stay clean.
# URL-stripped prose prevents host punctuation from breaking bounded sentence patterns.
_RI_OBEYNOUN = (r"instructions?|directions?|steps?|commands?|orders?|directives?|"
                r"playbooks?|rulesets?|recipes?|checklists?|the\s+script")
_RI_STRONGNOUN = (r"instructions?|directions?|commands?|orders?|directives?|"
                  r"playbooks?|rulesets?")
_RI_FOLLOWVERB = r"follow|obey|comply with|adhere to|execute|run|carry out|apply|act on|perform"
_RI_FOLLOWVERB_RE = re.compile(r"\b(?:" + _RI_FOLLOWVERB + r")\b", re.I)
_RI_PIPE_RE = re.compile(
    r"\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]*\|\s*(?:ba|z)?sh\b", re.I)
_RI_PROSE_PIPE_RE = re.compile(
    r"\bpipe\b[^.\n]{0,40}\b(?:in)?to\b[^.\n]{0,14}\b(?:a\s+)?(?:ba|z)?sh(?:ell)?\b|"
    r"\bpipe\b[^.\n]{0,40}\bbash\b", re.I)
_RI_OUTPUT_RE = re.compile(
    r"\b(?:do|execute|run|perform|carry out|apply|follow|read|let)\s+(?:exactly\s+)?"
    r"(?:each\s+|every\s+|of\s+)*(?:what|whatever)\s+"
    r"(?:it|they|that\s+\w+|the\s+(?:url|link|page|file|response|document|endpoint|gist|"
    r"server|remote))\b[^.\n]{0,24}?"
    r"\b(?:says?|returns?|contains?|lists?|provides?|instructs?|spells?|prescribes?|tells?)\b",
    re.I)
_RI_TREAT_RE = re.compile(
    r"\b(?:treat|use|adopt|take)\b[^.\n]{0,40}?\bas\s+(?:your\s+|the\s+|its\s+|new\s+)*"
    r"(?:standing\s+|operating\s+)?"
    r"(?:instructions?|commands?|directives?|rules?|prompts?|system\s+(?:message|prompt)|"
    r"a\s+script)\b|"
    r"\b(?:its\s+contents?|the\s+(?:response|output|remote\s+config|returned\s+\w+)|"
    r"whatever\s+it\s+returns)\b[^.\n]{0,20}?\b(?:is|are|becomes?|become|will\s+be)\b\s+"
    r"(?:your\s+|the\s+|new\s+)*(?:standing\s+|operating\s+)?"
    r"(?:instructions?|commands?|directives?|rules?|prompts?|system\s+(?:message|prompt))\b", re.I)
_RI_FOLLOW_TIED_RE = re.compile(
    r"\b(?:" + _RI_FOLLOWVERB + r")\b[^.\n]{0,20}?\b(?:" + _RI_OBEYNOUN + r")\b[^.\n]{0,20}?"
    r"\b(?:in|from|at|on|returned by|provided by|listed (?:in|at)|contained (?:in|at)|"
    r"it\s+(?:contains?|returns?|provides?|lists?|gives?|includes?|holds?|specif\w+|states?|"
    r"prescribes?|spells?)|they\s+(?:contain|return|provide|list|give|specify|prescribe|spell))\b",
    re.I)
_RI_FOLLOW_STRONG_RE = re.compile(
    r"\b(?:" + _RI_FOLLOWVERB + r")\b[^.\n]{0,20}?\b(?:" + _RI_STRONGNOUN + r")\b", re.I)
_RI_FOLLOW_ANA_RE = re.compile(
    r"\b(?:" + _RI_FOLLOWVERB + r")\b[^.\n]{0,20}?\b(?:them|those|these)\b|"
    r"\b(?:" + _RI_FOLLOWVERB + r")\b[^.\n]{0,30}?\b(?:it|they)\s+"
    r"(?:says?|returns?|contains?|lists?|provides?|instructs?|spells?|prescribes?|"
    r"dictates?|specif\w+)\b", re.I)
_RI_NOUN_EXEC_RE = re.compile(
    r"\b(?:instructions?|commands?|directives?|orders?)\b[^.\n]{0,40}?"
    r"\b(?:execute|run|follow|obey|carry out|perform|apply)\s+(?:them|it|these|those)\b|"
    r"\b(?:execute|run|eval|exec)\s+(?:it|this|that|them|the\s+(?:response|output|reply|result))"
    r"\b[^.\n]{0,12}\bverbatim\b", re.I)
_RI_SCRIPT_EXT_RE = re.compile(r"\.(?:sh|ps1|py|rb|pl|bash|bat|cmd)\b", re.I)
_RI_RUN_IT_RE = re.compile(r"\b(?:run|execute|exec|source|\./)\s*it\b", re.I)
# A local file tie prevents an unrelated URL from becoming the instruction source.
_RI_LOCAL_AFTER_RE = re.compile(
    r"^\s*(?:in|at|from|inside|within|of)?\s*(?:the\s+|this\s+|our\s+)?(?:"
    r"[\w.-]*\.(?:md|markdown|txt|rst|adoc|mk|cfg|ini|toml|json|ya?ml|xml|py|js|ts|rb|go)\b|"
    r"readme|makefile|dockerfile|changelog|licen[sc]e|contributing|codeowners|"
    r"repo(?:sitory)?|codebase|source\s+tree|project|package(?:\.json)?)\b", re.I)
_RI_FETCHVERB_RE = re.compile(
    r"\b(?:fetch|download|retrieve|pull|load|obtain|grab|clone|consult|import|source)"
    r"(?:e?d|e?s|ing)?\b|"
    r"\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b", re.I)
_RI_URLISH_RE = re.compile(
    r"https?://|\bftps?://|\bgist\b|\bpastebin\b|\bhastebin\b|githubusercontent|"
    r"\bthe\s+(?:url|link|endpoint|gist|server|address)\b|"
    r"\bremote\s+(?:server|endpoint|url|host|source)\b", re.I)
_RI_CHARACTERIZED_SOURCE_RE = re.compile(
    r"\bremote\s+(?:instructions?|response|output|commands?|directives?|payload|content|script)\b|"
    r"\b(?:instructions?|response|output|commands?|directives?|payload|script)\s+"
    r"(?:from|returned by|provided by)\s+(?:the\s+)?remote\b", re.I)
_RI_DOC_AS_INSTRUCTION_RE = re.compile(
    r"\b(?:use|treat|adopt|take)\b[^.\n]{0,120}\b(?:documentation|docs?|guide|reference)\b"
    r"[^.\n]{0,120}\bas\s+(?:your\s+|the\s+)?remote\s+instructions?\b", re.I)
# Schemeless URLs require a known TLD and path.
_SCHEMELESS_URL_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"(?:com|net|org|io|dev|app|co|ai|gg|xyz|test|cloud|site|link|info|biz|me|ly)\b/[^\s)]+",
    re.I)
# Benign doc pointers are suppressed unless a hard execution signal is present.
_RI_BENIGN_RE = re.compile(
    r"\b(?:see|refer to|documentation|read more|for (?:more )?(?:details?|info(?:rmation)?|"
    r"reference)|learn more|as documented|docs?|readme|wiki|handbook|tutorial|reference|"
    r"setup guide|getting started|installation (?:guide|instructions?|steps?)|"
    r"official (?:docs?|guide)|user guide|man(?:ual| page)|changelog|contributing)\b", re.I)
_RI_HARDEXEC_RE = re.compile(
    r"\b(?:execute|eval|exec)\b|\|\s*(?:ba|z)?sh\b|"
    r"\b(?:do|run)\s+(?:exactly\s+)?(?:what|whatever)\b[^.\n]{0,48}"
    r"\b(?:says?|returns?|contains?)\b", re.I)
_RI_WINDOW = 2              # SXV-041: lines each side searched for the remote-source signal
_RI_WRAP_MAX = 8            # max lines a soft-wrapped directive may span (keeps the join linear)
# This omits the shared example regex's ambiguous bare "read" token.
_RI_EXAMPLE_INTRO_RE = re.compile(
    r"\b(?:such as|e\.?g\.?|i\.?e\.?|for example|for instance|for reference|"
    r"an example|example of|a sample|looks? like|like this|as shown(?: below)?|"
    r"shown below|the one (?:below|above)|might (?:say|write|include|contain))\b\s*:?|"
    r":\s*[\"']", re.I)
# Clause/sequence breaks: a frame before one of these governs an EARLIER step, not this directive.
_RI_SEQ_BREAK_RE = re.compile(r"[;,]|\.\s|\bthen\b", re.I)
# A remote-follow is STRONGLY characterized when it names an obey-noun or ties to the remote's
# returned content; a bare "follow the steps at <url>" doc pointer is weak. Graded on the matched
# text, not the rule, because "follow the instructions it contains" and "follow the steps at ..."
# share one rule but need opposite treatment under an earlier-step benign frame.
_RI_STRONG_FOLLOW_RE = re.compile(
    r"\b(?:instructions?|directions?|directives?|commands?|orders?|playbooks?|rulesets?)\b|"
    r"\b(?:it|they)\s+(?:contains?|returns?|lists?|provides?|says?|includes?|holds?|"
    r"specif\w+|prescribes?|spells?|dictates?|states?)\b|"
    r"\b(?:returned|provided|listed|contained|specified)\s+(?:by|in|at)\b|"
    # download-a-remote-script-and-run-it is unambiguous RCE, never a doc pointer
    r"\b(?:run|source|exec(?:ute)?)\s+it\b", re.I)


def _ri_governing_prefix(before):
    """`before` truncated at the last clause/sequence break, so a benign frame in an earlier step
    ('See the docs, then fetch ... and follow it') does not rescue the directive in this step."""
    last = 0
    for m in _RI_SEQ_BREAK_RE.finditer(before):
        last = m.end()
    return before[last:]


def _strip_urls(s):
    """Blank out full AND schemeless URLs so (1) the prose-intent suppressions read WORDS not URL
    substrings (a domain like 'evil.example' must not trip the 'example' frame, 'docs.evil.com'
    earns no benign pass) and (2) a rule's `[^.\n]` span is not broken by a host's dots."""
    return _SCHEMELESS_URL_RE.sub(" ", _EGRESS_URL_RE.sub(" ", s or ""))


def _ri_url_in(joined):
    return bool(_EGRESS_URL_RE.search(joined) or _SCHEMELESS_URL_RE.search(joined))


def _ri_has_remote(joined):
    """A remote-source signal in the window: any URL (schemed or schemeless), or a fetch verb
    paired with a remote-ish object."""
    return bool(_ri_url_in(joined)
                or (_RI_FETCHVERB_RE.search(joined) and _RI_URLISH_RE.search(joined)))


def _ri_fetch_and_url(joined):
    """The stricter remote test for the weaker follow shapes: an explicit fetch verb AND a URL."""
    return bool(_ri_url_in(joined) and _RI_FETCHVERB_RE.search(joined))


def _ri_characterized_remote(joined):
    """A URL explicitly labelled as remote instruction/response content on its own line."""
    for line in joined.splitlines():
        characterized = _RI_CHARACTERIZED_SOURCE_RE.search(line)
        if not characterized or not _ri_url_in(line):
            continue
        benign = _RI_BENIGN_RE.search(line)
        if not benign or characterized.start() < benign.start() \
                or _RI_DOC_AS_INSTRUCTION_RE.search(_strip_urls(line)):
            return True
    return False


def _ri_source_desc(joined):
    """A short human label for the remote source: the first URL (schemed, else schemeless), else
    the remote-ish phrase."""
    u = _EGRESS_URL_RE.search(joined) or _SCHEMELESS_URL_RE.search(joined)
    if u:
        return u.group(0)
    m = _RI_URLISH_RE.search(joined)
    return m.group(0) if m else "a remote source"


def _ri_match(sline, raw, ctx):
    """The earliest qualifying SXV-041 rule match on this line, or None. Each rule carries its own
    remote-source gate; the follow-object rules additionally reject a LOCAL-file tie so a local
    'follow the steps in RELEASE.md' next to an unrelated upload URL does not fire."""
    remote = _ri_has_remote(ctx)
    fetchurl = _ri_fetch_and_url(ctx)
    # Weak follow shapes require a tied source; FOLLOW_TIED carries its own source relation.
    strong_remote = _ri_url_in(raw) or fetchurl
    tied_remote = strong_remote or _ri_characterized_remote(ctx)
    cands = []

    def add(m, ok):
        if m and ok:
            cands.append(m)

    def not_local(m):
        return not _RI_LOCAL_AFTER_RE.match(sline[m.end():])

    pipe = _RI_PIPE_RE.search(raw)
    add(pipe, pipe is not None and _ri_has_remote(pipe.group(0)))
    add(_RI_PROSE_PIPE_RE.search(sline), tied_remote)
    add(_RI_OUTPUT_RE.search(sline), tied_remote)
    add(_RI_TREAT_RE.search(sline), tied_remote)
    add(_RI_NOUN_EXEC_RE.search(sline), tied_remote)
    mt = _RI_FOLLOW_TIED_RE.search(sline)
    add(mt, remote and mt is not None and not_local(mt))
    ms = _RI_FOLLOW_STRONG_RE.search(sline)
    add(ms, strong_remote and ms is not None and not_local(ms))
    ma = _RI_FOLLOW_ANA_RE.search(sline)
    add(ma, fetchurl and ma is not None and not_local(ma))
    if _RI_FETCHVERB_RE.search(raw) and _RI_SCRIPT_EXT_RE.search(raw):
        add(_RI_RUN_IT_RE.search(sline), tied_remote)  # download <REMOTE ...>.sh ... run it
    if not cands:
        return None
    best = min(cands, key=lambda x: x.start())
    return best.group(0).strip(), best.start() + 1


def _dir_of(rel):
    return rel.rsplit("/", 1)[0] if "/" in rel else ""


def _governing_manifest(manifest_by_dir, rel):
    """Nearest skill_manifest at or above the artifact's directory (walk up to root)."""
    d = _dir_of(rel)
    while True:
        if d in manifest_by_dir:
            return manifest_by_dir[d]
        if not d:
            return None
        nd = _dir_of(d)
        if nd == d:
            return None
        d = nd


def _list_intro_index(raws, n):
    """Index into raws of the prose line introducing the bullet list line n sits in, or None.

    A credential path in a bullet list is governed by the sentence that introduces the list,
    not the two lines above it -- this separates 'Read each of the following if it exists'
    from 'Do not read: .env, *.pem, ...'."""
    if not _LIST_ITEM_RE.match(raws[n - 1]):
        return None
    i = n - 2
    while i >= 0:
        probe = raws[i]
        if not probe.strip() or _LIST_ITEM_RE.match(probe):
            i -= 1
            continue
        return i
    return None


def _hidden_comment_findings(art):
    """SXV-027: directives in real HTML comments, excluding Markdown code examples."""
    out = []
    total = 0
    markdown = getattr(art, "markdown", None)
    if markdown is None:
        fragments = [(art.text, 1, 1)]
        comments = []
    else:
        fragments = markdown.html_uninspectable
        comments = list(markdown.html_comments)
    for fragment, base_line, base_column in fragments:
        for start, raw_body in _html_comments(fragment):
            preceding = fragment[:start]
            relative_line = preceding.count("\n")
            last_break = preceding.rfind("\n")
            column = (base_column + start) if relative_line == 0 else (start - last_break)
            comments.append((raw_body, base_line + relative_line, column))
    for raw_body, line, column in sorted(set(comments), key=lambda value: (value[1], value[2])):
        body = raw_body.strip()
        if not body or not _comment_is_directive(body):
            continue
        total += 1
        if total > _FINDING_CAP:
            continue
        one_line = body.replace("\n", " ")
        out.append(Finding(
            vector="SXV-027", rule="hidden-html-comment", severity="high",
            path=art.rel, line=line, column=column,
            message=("an HTML comment in this instruction file carries a directive to the "
                     "agent: \"%s\". A markdown renderer hides it, so a human reviewer sees a "
                     "clean page while the model still reads it" % one_line[:160]),
            evidence={"comment_body": body[:400], "line": line, "column": column,
                      "selector": "hidden-comment:%s" %
                      hashlib.sha256(body.encode("utf-8")).hexdigest()[:12],
                      "snippet": one_line[:200]}))
    if total > _FINDING_CAP:
        out.append(_cap_note(art.rel, "SXV-027", total - _FINDING_CAP))
    return out


def _flatten_prose(text, start_line):
    """Join CommonMark soft breaks with memory bounded by the source text itself."""
    del start_line
    return re.sub(r"[ \t]*\n[ \t]*", " ", text).strip()


def _source_position(text, start_line, pos):
    """Map a flattened offset lazily, preserving raw Markdown marker columns."""
    flat_start = 0
    source_start = 0
    line = start_line
    while True:
        source_end = text.find("\n", source_start)
        if source_end < 0:
            source_end = len(text)
        source = text[source_start:source_end]
        left = len(source) - len(source.lstrip())
        content_len = len(source.strip())
        if content_len and pos < flat_start + content_len:
            return line, left + pos - flat_start + 1
        if content_len:
            flat_start += content_len + 1
        if source_end == len(text):
            return line, max(1, len(source) + 1)
        source_start = source_end + 1
        line += 1


def _source_span_blocks(text, spans):
    """Slice ordered one-based line spans in one pass without a per-line string list."""
    position, line = 0, 1
    for start, end in spans:
        while line < start:
            newline = text.find("\n", position)
            if newline < 0:
                return
            position, line = newline + 1, line + 1
        block_start = position
        while line <= end:
            newline = text.find("\n", position)
            if newline < 0:
                position, line = len(text), end + 1
                break
            position, line = newline + 1, line + 1
        block_end = position - 1 if position and text[position - 1:position] == "\n" else position
        yield text[block_start:block_end], start


def _plain_prose_blocks(text):
    """Yield blank-line-delimited blocks without splitting a newline-dense file into a list."""
    position, line, block_start, block_line = 0, 1, None, 1
    while True:
        newline = text.find("\n", position)
        end = len(text) if newline < 0 else newline
        source = text[position:end]
        if source.strip():
            if block_start is None:
                block_start, block_line = position, line
        elif block_start is not None:
            yield text[block_start:max(block_start, position - 1)], block_line
            block_start = None
        if newline < 0:
            break
        position, line = newline + 1, line + 1
    if block_start is not None:
        yield text[block_start:], block_line


def _prose_blocks(art):
    """Yield exact parser-recognized source blocks; plain lifted text falls back to paragraphs."""
    spans = getattr(getattr(art, "markdown", None), "prose_spans", None)
    if spans is not None:
        wanted = []
        fm_end = getattr(art, "frontmatter_end_line", None)
        if fm_end and fm_end > 2:
            wanted.append((2, fm_end - 1))
        wanted.extend(spans)
        yield from _source_span_blocks(art.text or "", wanted)
        yield from getattr(art.markdown, "html_prose", ())
        return
    yield from _plain_prose_blocks(art.text or "")


def _directive_findings(art):
    """SXV-028/029/030/031 over CommonMark prose, including soft-wrapped directives."""
    out = []
    seen = set()
    totals = {}
    previous = ""
    for prose, start_line in _prose_blocks(art):
        raw = _flatten_prose(prose, start_line)
        if not raw:
            continue
        intro_prev = bool(_EXAMPLE_INTRO_RE.search(previous))
        for vid, tag, sev, rx in _DIRECTIVE_RULES:
            for m in rx.finditer(raw):
                key = (vid, m.group(0).strip().lower())
                if key in seen:                 # per-(vector, text) dedup within the artifact
                    continue
                before = raw[:m.start()]
                described = _EXAMPLE_INTRO_RE.search(before) or intro_prev
                described = described or _is_defensive_frame(before)
                if described:
                    continue
                context = raw[max(0, m.start() - 48):m.end()]
                if _NEGATED_ATTACK_ACTION_RE.search(context):
                    continue
                if vid == "SXV-029" and _ANTIREFUSAL_BENIGN_RE.search(raw):
                    continue                    # 3rd-person 'X will never refuse' / license copy
                seen.add(key)                   # only emitted directives consume the dedup slot
                matched = m.group(0).strip()
                totals[vid] = totals.get(vid, 0) + 1
                if totals[vid] > _FINDING_CAP:
                    continue
                line, col = _source_position(prose, start_line, m.start())
                out.append(Finding(
                    vector=vid, rule=tag, severity=sev, path=art.rel, line=line,
                    message=("instruction-file directive (%s): \"%s\". This addresses the "
                             "model's own behaviour rather than the task"
                             % (tag, matched[:100])),
                    evidence={"directive_text": matched, "rule": tag, "line": line,
                              "col": col,
                              "selector": "%s:%s" % (tag, matched.lower()[:50]),
                              "snippet": raw[:200]}))
        previous = raw
    for vector, total in totals.items():
        if total > _FINDING_CAP:
            out.append(_cap_note(art.rel, vector, total - _FINDING_CAP))
    return out


def _ri_join_wrap(raws, n, in_fence):
    """Flatten ONLY a genuine soft-wrap: continuation lines of the same sentence. Stops at a
    sentence terminator, a blank/fenced line, a new list item, or a table row -- so a directive
    that wraps across a line break matches, while two separate sentences/steps do not merge."""
    parts = [raws[n - 1]]
    j = n
    while (j < len(raws) and raws[j].strip() and (j + 1) not in in_fence
           and not _LIST_ITEM_RE.match(raws[j]) and not _is_table_row(raws[j])
           and not parts[-1].rstrip().endswith((".", "!", "?", ":", ";"))
           and j - n < _RI_WRAP_MAX):
        parts.append(raws[j])
        j += 1
    return _flatten_prose("\n".join(parts), n) if len(parts) > 1 else raws[n - 1]


def _remote_instr_findings(art):
    """SXV-041: the instruction lane directs the agent to fetch remote content and follow it as
    instructions (progressive disclosure). Fires only when the fetched content is characterised
    AS an instruction/command set to obey and a remote source sits within the window; a plain
    'see the docs at <url>' pointer, a fenced example, and a described attack stay clean."""
    out = []
    raws = art.text.split("\n")
    in_fence, _open = _fenced_lines(art.markdown, raws)
    fired = set()
    total = 0
    for n, raw in enumerate(raws, 1):
        if n in in_fence or n in fired:         # a fenced install one-liner is an example
            continue
        lo = max(0, n - 1 - _RI_WINDOW)
        hi = min(len(raws), n + _RI_WINDOW)
        ctx = "\n".join(raws[lo:hi])            # the matched line plus +/- _RI_WINDOW lines
        sline = _strip_urls(raw)                # rules match on URL-stripped text (spans + words)
        hit = _ri_match(sline, raw, ctx)
        # Only when a directive plausibly STARTS on this line (a fetch/follow cue) do we retry on
        # the soft-wrap join, so an unrelated earlier line is never merged into a later directive.
        if hit is None and (_RI_FETCHVERB_RE.search(raw) or _RI_FOLLOWVERB_RE.search(raw)):
            joined = _ri_join_wrap(raws, n, in_fence)   # the directive may wrap onto the next line,
            if joined != raw:                           # retry the follow match on the join but
                sjoined = _strip_urls(joined)           # keep the URL/pipe gate on THIS line so a
                jhit = _ri_match(sjoined, raw, ctx)     # next line's URL is not the remote source;
                # accept only when the directive STARTS on this line, else the continuation line
                # fires natively (no duplicate, correct location)
                if jhit is not None and jhit[1] <= len(_strip_urls(raw).strip()) + 1:
                    sline, hit = sjoined, jhit
        if hit is None:
            continue
        matched, col = hit
        prose = _strip_urls(ctx)
        before = sline[: max(0, col - 1)]
        # A defensive frame ("we detect X that then tells the agent to ...") is a governing clause
        # scoping the whole sentence across sequence breaks, so it is matched on the full prefix.
        if _is_defensive_frame(before):
            continue
        # A weak lead ("For example, ... then <directive>") does NOT rescue a STRONGLY characterized
        # remote-follow/RCE; it still suppresses a weak "follow the steps at <docs-url>" pointer.
        strong = bool(_RI_STRONG_FOLLOW_RE.search(matched))
        scope = _ri_governing_prefix(before) if strong else before
        if _RI_EXAMPLE_INTRO_RE.search(scope):
            continue
        if _RI_BENIGN_RE.search(scope + matched) and not _RI_HARDEXEC_RE.search(prose):
            continue
        fired.add(n)
        total += 1
        if total > _FINDING_CAP:
            continue
        src = _ri_source_desc(raw if _ri_has_remote(raw) else ctx)
        out.append(Finding(
            vector="SXV-041", rule="remote-instruction-load", severity="high",
            path=art.rel, line=n,
            message=("instruction lane tells the agent to fetch remote content and follow it as "
                     "instructions: \"%s\" (source: %s). The scanner sees the pointer, not the "
                     "payload -- the real directives load at runtime from a location a reviewer "
                     "never sees, and the remote side can change after this scan (progressive "
                     "disclosure)" % (matched[:100], src[:120])),
            evidence={"directive_text": matched, "remote_source": src, "line": n,
                      "col": col,
                      "selector": "remote-instruction-load:%s" %
                      hashlib.sha256(matched.lower().encode("utf-8")).hexdigest()[:12],
                      "snippet": raw.strip()[:200]}))
    if total > _FINDING_CAP:
        out.append(_cap_note(art.rel, "SXV-041", total - _FINDING_CAP))
    return out


def _fence_labelled_antipattern(raws, open_by_line, n):
    """True when the fence enclosing line n opens inside a 'do not run / bad example' window."""
    open_line = open_by_line.get(n, n)
    lo = max(0, open_line - 4)
    hi = min(len(raws), open_line + 3)
    return bool(_ANTIPATTERN_RE.search("\n".join(raws[lo:hi])))


_DESTINATION_LINK_RE = re.compile(
    r"\b(?:collector|endpoint|destination|receiver|server|webhook|upload|target|url)\b", re.I)


def _post_egresses(raws, markdown):
    """EVERY POST/upload egress candidate in document order: each _EGRESS_VERB_RE line carrying
    a same-line URL or a structurally adjacent destination. Shared Markdown links/code spans tie
    next-block destinations without treating an unrelated nearby documentation URL as the sink."""
    out = []
    links = getattr(markdown, "links", ()) if markdown is not None else ()
    code_spans = getattr(markdown, "code_spans", ()) if markdown is not None else ()
    for n, raw in enumerate(raws, 1):
        if not _EGRESS_VERB_RE.search(raw):
            continue
        urls = _EGRESS_URL_RE.findall(raw)
        chosen = urls[0] if urls else None          # same-line URL: destination in document order
        if chosen is None and n < len(raws):
            candidate = raws[n].strip().rstrip(".,)")
            found = _EGRESS_URL_RE.fullmatch(candidate)
            if found:
                chosen = found.group(0)
        # A prose step can introduce one adjacent Markdown destination or code block.
        if chosen is None and raw.rstrip().endswith(":"):
            i = n
            while i < len(raws) and not raws[i].strip():
                i += 1
            next_line = i + 1
            for href, label, line in links:
                if line == next_line and _DESTINATION_LINK_RE.search(label) \
                        and _EGRESS_URL_RE.fullmatch(href):
                    chosen = href
                    break
            if chosen is None:
                for start, end in code_spans:
                    if start <= n:
                        continue
                    if any(line.strip() for line in raws[n:start - 1]):
                        break
                    for line_no in range(start, min(end, len(raws)) + 1):
                        command = raws[line_no - 1]
                        if _EGRESS_VERB_RE.search(command):
                            found = _EGRESS_URL_RE.search(command)
                            if found:
                                chosen = found.group(0)
                                break
                    break
        if chosen is not None:
            out.append({"line": n, "url": chosen})
    return out


_CRED_AUTH_VALUE_RE = re.compile(
    r"(?:--(?:netrc-file|key|cert|cacert|config|user|oauth2-bearer|pass)|-[EKu])\s+"
    r"(?:\$\([^\n)]{0,80}|\S*)\s*$", re.I)
_CRED_BARE_NETRC_RE = re.compile(r"--netrc\b(?!-file)", re.I)
_CRED_AUTH_PROSE_RE = re.compile(
    r"\b(?:auth(?:enticate)?(?:\s+\w+){0,2}\s+(?:from|with|using)|log\s?in(?:\s+\w+){0,2}\s+"
    r"(?:from|with)|registry auth|credentials?\s+(?:for|from)|"
    r"(?:with|using)\s+(?:the\s+|your\s+)?(?:token|credential|key|secret|password|api\s+key)s?)\b",
    re.I)
_CRED_PAYLOAD_FLAG_RE = re.compile(
    r"(?:-d|--data(?:-binary|-raw|-urlencode)?|-T|--upload-file|-F|--form)\s*@?\s*$", re.I)
# A credential governed by an egress verb is payload, not authentication input.
_CRED_SENT_DIRECTLY_RE = re.compile(
    r"\b(?:upload|send|post|exfiltrat\w*|transmit|leak|forward|email|mail)\s+\S*$", re.I)
_CRED_PIPE_PAYLOAD_RE = re.compile(
    r"\|\s*curl\b[^\n]*(?:--data(?:-binary|-raw|-urlencode)?|-d)\s+@-(?:\s|$)", re.I)


def _cred_is_auth_input(raw, cred):
    """On a same-line egress, True when the credential is consumed to AUTHENTICATE the request
    (an auth flag like --netrc/--cert, or 'auth from'/'login with' prose) rather than SENT as the
    payload -- so reading .netrc / .docker/config.json to authenticate an upload of an UNRELATED
    artifact does not fire. A credential that IS the payload (-d @cred, -T cred, in the URL, or a
    prose 'upload it') is never treated as auth input."""
    i = raw.find(cred)
    before = raw[:i] if i >= 0 else raw
    after = raw[i + len(cred):] if i >= 0 else ""
    payload = bool(_CRED_PAYLOAD_FLAG_RE.search(before)
                   or re.search(r"@\s*$", before)
                   or cred in "".join(_EGRESS_URL_RE.findall(raw))
                   or _CRED_SENT_DIRECTLY_RE.search(before)
                   or _CRED_PIPE_PAYLOAD_RE.search(after))
    if payload:
        return False
    direct_auth_value = bool(_CRED_AUTH_VALUE_RE.search(before))
    default_netrc = cred.lower().endswith(".netrc") and _CRED_BARE_NETRC_RE.search(raw)
    return bool(direct_auth_value or default_netrc or _CRED_AUTH_PROSE_RE.search(before))


def _egress_backref(egress_text):
    """A credential NOUN on the send line links a split read only as a PAYLOAD back-reference: a
    reference NOT itself governed by using/with/via (which would make it the auth for the send). So
    'Upload X using the credentials' does not drag in an unrelated credential path, while
    'upload the key' / 'POST the credentials' still link the read that produced it. A bare pronoun
    object ('upload it') is deliberately NOT a backref: it would fire on ordinary publish/deploy
    docs that name an auth store, and anaphora cannot tell payload-it from package-it."""
    for m in _CRED_BACKREF_RE.finditer(egress_text):
        pre = egress_text[max(0, m.start() - 14):m.start()]
        if not re.search(r"\b(?:using|with|via)\s+(?:the\s+|your\s+|its\s+)?$", pre, re.I):
            return True
    return False


def _get_exfil_egresses(raws):
    """Secondary GET-exfil candidates, in document order: a fetch-verb line whose URL carries a
    token in its PATH/QUERY/USERINFO (host excluded via _egress_host_tokens). The URL must be on
    the same line -- a GET carries the secret INSIDE the URL, so there is no +/-4 URL probing and
    no first-match-wins break. Yields (line, url, payload_tokens); the caller links each payload
    token back to a credential read, so the fetch verb alone never fires."""
    out = []
    for n, raw in enumerate(raws, 1):
        if not _FETCH_VERB_RE.search(raw):
            continue
        for url in sorted(set(_EGRESS_URL_RE.findall(raw))):
            payload = _vartokens(url) - _egress_host_tokens(url)
            if payload:                         # a bare download URL has no path/query token
                out.append((n, url, payload))
    return out


# Non-HTTP sinks cover remote pushes and streams; destination anchoring keeps pulls clean.
_NONHTTP_EGRESS_RE = re.compile(
    r"\b(?:scp|sftp|rsync)\b(?:\s+\S+)*?\s+(?:[\w.-]+@)?[\w.-]+:\S*\s*$|"    # [user@]host:dst EOL
    r"\b(?:nc|ncat|netcat|socat)\b[^\n]*?\b\d{1,5}\b", re.I)  # nc host PORT (also `cat cred | nc`)


def _nonhttp_egresses(raws):
    """Lines carrying a non-HTTP exfil sink (scp/sftp/rsync to user@host:, or a pipe/host:port to
    nc/socat), in document order. The line text is the sink description for the finding."""
    return [{"line": n, "url": raw.strip()[:80]}
            for n, raw in enumerate(raws, 1) if _NONHTTP_EGRESS_RE.search(raw)]


def _clause_at(s, idx):
    """The ';'/'. '-delimited clause of `s` containing character index `idx`. Scopes the negation
    check so a negated but UNRELATED clause ('Do not upload logs; read creds and POST it') cannot
    disarm the clause that actually carries the credential, while a negation governing the read or
    the send in the SAME clause ('read creds, never upload to <url>') still flips polarity."""
    start = 0
    for sep in (";", ". "):
        p = s.rfind(sep, 0, idx)
        if p != -1:
            start = max(start, p + len(sep))
    end = len(s)
    for sep in (";", ". "):
        p = s.find(sep, idx)
        if p != -1:
            end = min(end, p)
    return s[start:end]


def _collect_cred_hits(raws, in_fence, open_by_line, egress_line, egress_vars, egress_backref):
    """Credential reads LINKED to the egress at egress_line, classified by polarity/context.

    Shared with both the POST and the GET-exfil paths so the SAME suppressions apply to each:
    a split read/send links only by a shared identifier (a $var / snake_case token or the
    credential path on both lines -- a def-use of the captured secret) or a credential-specific
    back-reference on the egress line; documentation tables, anti-pattern fences, negative
    imperatives, and a defensive read-and-send explanation are rejected rather than fired."""
    cred_hits = []
    lo = max(1, egress_line - _LINK_WINDOW)      # iterate ONLY the bounded window, not the whole
    hi = min(len(raws), egress_line + _LINK_WINDOW)   # file (was O(lines * egress candidates))
    for n in range(lo, hi + 1):
        raw = raws[n - 1]
        if n != egress_line:
            shared = bool(_vartokens(raw) & egress_vars)
            if not (shared or egress_backref):
                continue
        line_kinds = set()                      # dedup overlapping _CRED_HIGH matches on this line
        for rx, kind in _CRED_HIGH_RX:
            m = rx.search(raw)
            if not m:
                continue
            if _is_table_row(raw) and not _EGRESS_VERB_RE.search(raw):
                continue
            if n == egress_line and _cred_is_auth_input(raw, m.group(0)):
                continue
            if n in in_fence and _fence_labelled_antipattern(raws, open_by_line, n):
                continue
            # Same-line negation is clause-scoped; split-line safety statements govern the line.
            neg_scope = _clause_at(raw, m.start()) if n == egress_line else raw
            if _NEG_SAME_LINE_RE.search(neg_scope):
                continue
            intro = _list_intro_index(raws, n)
            if intro is not None and _NEG_SAME_LINE_RE.search(raws[intro]):
                continue
            lo = max(0, n - 1 - _DEFENSIVE_WINDOW)
            prefix = raw[:m.start()]
            prior = raws[lo:n - 1]
            introduced = any(
                _is_defensive_frame(frame.strip())
                and re.search(r"\b(?:following|pattern|example)\b[^.\n]*:\s*$", frame, re.I)
                for frame in prior)
            if _is_defensive_frame(prefix) or introduced:
                continue
            if kind in line_kinds:
                continue
            line_kinds.add(kind)
            cred_hits.append({"kind": kind, "line": n, "text": m.group(0), "col": m.start() + 1})
    return cred_hits


def _exfil_findings(art, manifest_by_dir):
    """SXV-011: a credential read directed to a reachable network egress, positive polarity."""
    text = art.text
    raws = text.split("\n")
    in_fence, open_by_line = _fenced_lines(art.markdown, raws)

    # All egress paths share the governing manifest's network-reach gate.
    manifest = _governing_manifest(manifest_by_dir, art.rel)
    if manifest is None or "allowed-tools" not in (manifest.frontmatter or {}):
        reaching, proven_reach = "undeclared_inherits_all", True   # inherits Bash/WebFetch
    else:
        grants = manifest.grants or []
        bash_denied = any(g.tool in _BASH_TOOLS and g.broad and not g.allowed for g in grants)
        allowed = [g for g in grants if g.allowed
                   and not (bash_denied and g.tool in _BASH_TOOLS)]
        net_grants = [g for g in allowed if _reaches_network(g)]
        if not net_grants:                      # declared, but nothing reaches the network
            return []
        reaching = ", ".join(sorted(g.raw for g in net_grants))
        # A reach proven by a network tool or a bash network command is critical; a reach that
        # holds ONLY by failing open on an unrecognized tool is unproven -> high, worded as such.
        proven_reach = any(not _reach_is_fail_open(g) for g in net_grants)

    # Try every primary candidate so unrelated telemetry cannot shadow exfiltration.
    egress = None
    method = "post"
    cred_hits = []
    for cand in _post_egresses(raws, art.markdown):
        egress_text = raws[cand["line"] - 1]
        egress_backref = _egress_backref(egress_text)
        egress_vars = _vartokens(egress_text) - _egress_host_tokens(cand["url"])
        hits = _collect_cred_hits(raws, in_fence, open_by_line, cand["line"],
                                  egress_vars, egress_backref)
        if hits:
            egress, cred_hits = cand, hits
            break

    # Bare GET exfiltration requires a secret-linked token outside the destination host.
    if not cred_hits:
        for line, url, payload in _get_exfil_egresses(raws):
            hits = _collect_cred_hits(raws, in_fence, open_by_line, line, payload, False)
            if hits:
                egress = {"line": line, "url": url}
                cred_hits = hits
                method = "get"
                break

    # Non-HTTP egress runs only after URL paths produce no finding.
    if not cred_hits:
        for cand in _nonhttp_egresses(raws):
            egress_text = raws[cand["line"] - 1]
            egress_vars = _vartokens(egress_text)
            egress_backref = _egress_backref(egress_text)
            hits = _collect_cred_hits(raws, in_fence, open_by_line, cand["line"],
                                      egress_vars, egress_backref)
            if hits:
                egress, cred_hits, method = cand, hits, "non-http"
                break

    if egress is None or not cred_hits:
        return []

    corrob = bool(_CRED_CORROB_RX.search(text))
    first = min(cred_hits, key=lambda r: (r["line"], r["col"]))
    kinds = sorted({r["kind"] for r in cred_hits})
    tokens = [{"kind": r["kind"], "line": r["line"], "text": r["text"]}
              for r in sorted(cred_hits, key=lambda x: (x["line"], x["col"]))]
    return [Finding(
        vector="SXV-011", rule="cred-egress",
        severity="critical" if proven_reach else "high",
        path=art.rel, line=first["line"],
        message=("instruction lane directs the agent to read %d credential artifact "
                 "reference(s) (%s) and send them to %s via %s; positive imperative polarity and %s"
                 % (len(cred_hits), ", ".join(kinds), egress["url"], method.upper(),
                    "the declared grant %s can reach the network" % reaching if proven_reach
                    else "network reach unproven (fail-open on unrecognized grant %s)" % reaching)),
        evidence={"credential_tokens": tokens, "egress_target": egress["url"],
                  "egress_line": egress["line"], "egress_method": method,
                  "polarity": "positive",
                  "reaching_grant": reaching, "dotenv_corroboration": corrob,
                  "line": first["line"], "col": first["col"],
                  "selector": "cred-egress:%s" % "|".join(kinds),
                  "snippet": raws[first["line"] - 1].strip()})]


def _lifted_targets(parsed):
    """Transitive prose targets reachable from an instruction-lane root."""
    by_rel = getattr(parsed, "by_rel", {}) or {}
    adjacency = {}
    for ref in getattr(parsed, "refs", None) or []:
        adjacency.setdefault(ref["from"], []).append(ref["to"])
    roots = [rel for rel, artifact in by_rel.items()
             if getattr(artifact, "kind", None) in _LANE_KINDS]
    seen, lifted, queue = set(roots), set(), list(roots)
    while queue:
        source = queue.pop()
        for target in adjacency.get(source, []):
            if target in seen:
                continue
            artifact = by_rel.get(target)
            if getattr(artifact, "kind", None) not in _LIFTABLE_KINDS:
                continue
            seen.add(target)
            lifted.add(target)
            queue.append(target)
    return lifted


_FINDING_CAP = 25


def _cap_note(path, group, suppressed):
    return Finding(
        vector="", rule="findings-capped", severity="low", path=path,
        message="%d more %s findings in %s were suppressed (cap %d per file)"
                % (suppressed, group, path, _FINDING_CAP))


def _cap_findings(findings):
    """Cap findings per (path, vector) so one 1 MiB file with thousands of matching comment or
    directive lines cannot amplify into a huge result payload. Keep the first _FINDING_CAP per group
    and append ONE note with the suppressed count. These vectors are single-severity, so a plain
    (path, vector) key (as in shell_exec) needs no severity split."""
    kept, counts = [], {}
    for f in findings:
        key = (f.path, f.vector or f.rule)
        counts[key] = counts.get(key, 0) + 1
        if counts[key] <= _FINDING_CAP:
            kept.append(f)
    for (path, group), n in counts.items():
        if n > _FINDING_CAP:
            kept.append(_cap_note(path, group, n - _FINDING_CAP))
    return kept


def check(parsed) -> list:
    """Run the three instruction-lane engines over every instruction-lane artifact (and any
    doc/other artifact an instruction-lane file references) and return SXV-011/027/028/029/030/031
    findings (plus SXV-041 remote instruction loading). Per-engine and per-artifact isolated: a
    crashing engine records a scoped high check-error and the others still run, so a crash in a
    cheap engine can never drop the critical credential finding."""
    manifest_by_dir = {}
    for p in parsed.artifacts:
        if p.kind == "skill_manifest":
            manifest_by_dir.setdefault(_dir_of(p.rel), p)   # one unit per dir, deterministic
    lifted = _lifted_targets(parsed)

    out = []
    for p in parsed.artifacts:
        if p.text is None or (p.kind not in _LANE_KINDS and p.rel not in lifted):
            continue
        # Each engine is isolated: a crash in one (e.g. a cheap text engine) must not stop the
        # others, above all the critical credential-egress engine. Skipped analysis reads as a
        # high check-error, never as clean.
        for engine in (_hidden_comment_findings, _directive_findings, _remote_instr_findings,
                       lambda a: _exfil_findings(a, manifest_by_dir)):
            try:
                out.extend(engine(p))
            except Exception as exc:            # a poisoned artifact must not abort the scan
                out.append(Finding(
                    vector="", rule="check-error", severity="high", path=p.rel,
                    message="instruction_exfil skipped %s: %s" % (p.rel, type(exc).__name__)))
    return _cap_findings(out)
