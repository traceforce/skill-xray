# Correlation and operator decisions

Every scan correlates its findings before the report is written. In the SARIF run:

- `runs[].results` are the equivalent occurrences consolidated without losing distinct evidence;
- `runs[].properties.rawCandidates` are the emitted check results, with their original evidence and provenance;
- `runs[].properties.candidateLinks` give every candidate's result, disposition and reason.

Detector caps happen upstream. A cap/coverage record is not a claim that uncollected
candidates can be recovered. Existing LLM review annotations stay separate and never
authorize suppression. Additive LLM findings, when requested, are identified separately
in the correlation audit and cannot be suppressed by this deterministic policy.

## Identity

`rule_id` is a readable namespaced detector ID; SXV is its security classification,
not an individual finding ID. `id` and the versioned `fingerprint` identify an occurrence
using its relative path, rule and security evidence. Identical anchors at separate
locations have separate occurrence identities. Inserting ordinary blank lines preserves
fingerprints; adding/removing indistinguishable repeated occurrences can renumber them.

The separate `context_digest` hashes all captured package artifacts, including their
paths, raw-byte hashes, normalized contents and parse diagnostics. Any content edit invalidates
a prior operator decision, even if its fingerprint survives. This is deliberate:
blank lines and line endings can change shell continuation behavior. Unrelated edits also invalidate
decisions; there is no second dependency or reachability engine.

Code flows are emitted only for supported analyzer traces whose paths, UTF-8 positions
and quoted content validate against the captured IR. Unsupported traces remain in raw
evidence with a limitation, not a guessed connection between unrelated findings.

## Explicit scoped decisions

Without a policy, everything is reported. An operator may pass a policy file with `--policy`;
no policy is read from a scanned manifest or discovered automatically.
Start from the exact identity fields in a reviewed result:

```json
{
  "version": "skill-xray/scoped-policy/v1",
  "decisions": [{
    "rule_id": "skill-xray/command-injection",
    "path": "scripts/run.py",
    "fingerprint": "<the result's 64-character hash>",
    "context_digest": "<the result's 64-character context hash>",
    "action": "suppress",
    "reason": "Reviewed this exact operation under SEC-123"
  }]
}
```

All four scope fields must match. In the SARIF report a result's `rule_id` is its `ruleId`, its `path` is the first location's `artifactLocation.uri` with its percent-encoding decoded (the raw `/`-separated relative path), its `fingerprint` is the value under `partialFingerprints["skill-xray/evidence/v1"]` and its `context_digest` is `properties.contextDigest`; the console line `policy: N suppressed, N demoted, N of N decisions matched no result` says whether each decision found its result. No vector-wide ignore, wildcard identity, implicit
acceptance or previous LLM rejection is supported. For `action: "demote"`, supply a lower
`effective_severity`; this produces an audited `corrected` result without removing it.

Every result retains original/effective severity, decision reason, policy version,
decision provenance, candidate references, governing manifest, capability context and
coverage status. Suppressed results stay in the audit. Duplicate links point to the
retained result. No reporting threshold hides a demoted result.

Full capability evidence lives once per manifest under `runs[].properties.capabilityContexts`,
and each result references it through `governingManifest`. This replaces the repeated
per-result evidence array, not the evidence itself.

Operational/coverage records cannot be suppressed. Missing source/manifest context,
parse diagnostics, malformed positions, unsupported traces or reported coverage gaps
block suppression and demotion. Unknown capability axes are explanatory, not permission.
Invalid policies retain findings and produce a visible context error.

This policy is not a baseline database. It does not infer that missing findings are
fixed, carry forward model decisions, or change the detector's interpretation.

## SARIF output

```sh
skill-xray scan ./skill-package --output ../reports/skill.sarif
skill-xray scan ./skill-package --output ../reports/skill.sarif --policy ../reviewed-policy.json
```

The report and operator policy must be outside the scanned package. The report's parent
directory must already exist. A generated report therefore cannot become input on the
next identical scan. SARIF is the only output; the audit retains
suppressed results using native `suppressions` with a reason, rather than deleting them.

The order is checks, raw candidates, correlation, explicit dispositions, final results,
SARIF validation, atomic report replacement. The serializer cannot decide suppression.

Each SARIF result has a readable rule ID, stable finding ID, title/message, severity,
bounded analyzer evidence, source locations, fingerprint and audit references. SXV/CWE/tier,
original/effective severity, governing capability context and completeness remain separate
properties. Supported proven traces use native `codeFlows`; unrelated findings are never
stitched into a flow. No uncalibrated maliciousness score or inferred confidence is added.

`properties.category` distinguishes `security-finding` from `analysis-diagnostic`.
Diagnostics describe scanner errors or coverage gaps, not detected vulnerabilities;
they remain visible and cannot be suppressed. Empty SXV/CWE/tier fields are omitted,
not replaced with guessed classifications. A security finding may describe a capability
risk; the category does not establish malicious intent.

Native OpenGrep byte columns are converted to Unicode character columns; IR character
columns are preserved. Byte findings use byte regions. Unvalidated locations keep their
original values and a limitation rather than pointing at a guessed source span.
`reportedLocation` appears only when the source region is absent or unvalidated.
Original coordinates always remain in the linked raw candidate, including when native
byte columns were converted for SARIF. Unknown capability states remain explicit in
the shared context table; omission of an optional field never means analysis succeeded.

Run metadata identifies scanner, pinned engine, ruleset digest, policy version, coverage
and context errors. Coverage includes missing reporting/policy context, which is not the
same as a failed detector. A low coverage note does not become a new fatal exit condition.
Run-level `package` includes a display name and a versioned digest of captured content,
including when no finding exists. The digest is not a claim about uninspected content or
other installed skills, and contains no absolute installation root.

The official offline SARIF 2.1.0 schema and product reference/audit checks must pass before
writing. Output uses a same-directory temporary file, flush/fsync and atomic replacement.
Validation/write failures preserve the previous report. Reports over 64 MiB fail visibly;
there is no silent evidence truncation to fit the limit.
Report output cannot overwrite the explicitly selected operator policy. The writer fixes
the resolved destination before validation; output directory ancestry must remain trusted
against concurrent replacement by other processes. Source evidence can contain credentials,
so reports should be handled as sensitive data.

Exit 0 means scan/report completed, even with critical findings. Exit 2 means invalid input,
a failed check/context, existing material-incompleteness policy, or report validation/write
failure. There is no severity-based exit gate. With LLM disabled, identical inputs and
configuration produce byte-identical SARIF; scan-local IDs, engine fingerprints, timestamps
and absolute installation roots are not canonical report identities.
When report validation or writing fails, the console still prints the verdict line, no
`report:` line follows, any previous report is left untouched and the exit code is 2.

### Optional LLM audit

With `--llm --llm-review`, validated review annotations
also appear in `runs[].properties.llmReview`; every run with the lane on, review or not, carries
`runs[].properties.llmUsage` with the calls, failures, provider, model and enabled passes. `authoritative` is always false. Each
decision references the same stable `candidate_id` used by `rawCandidates`, result
`candidateIds` and `candidateLinks`; a reused review references its original candidate.
With `--llm --llm-shadow` the same properties carry the shadow decisions with `mode: "shadow"`.

Records preserve review status, reason, policy/provenance, validated proposal and, when
available, reviewer identity and request/response hashes. Confidence belongs to the model's
evidence assessment, not a calibrated maliciousness probability. Whole requests, manifests
and source windows are not duplicated into SARIF; hashes identify original
requests/responses, before candidate IDs are canonicalized.
Response hashes cover bounded text returned by the LLM session. A response rejected at
the session's size/type boundary has an explicit failure status but no response hash.

An `llm-disputed` annotation never changes result membership or native `suppressions`. By
default it does not change severity either. With the additional `--llm-apply` opt-in, a review
that passed every validation gate (consistent verdict fields, a verbatim evidence quote with any trailing
ellipsis of a length-capped copy dropped first, high confidence, full-file context) demotes the one text-pattern result it disputed (SXV-028/029/030/031
only) to `low` in the correlated results, recorded as `corrected` with `llm-review-policy`
provenance and `policy_version: skill-xray/llm-apply/v1` -- the same audited shape as an
operator demote. It never suppresses, never touches a mechanically anchored vector, a protected
or incomplete result, and never raises severity; `findings`, `final_findings` and raw candidates
keep the original evidence. `correlation.llm_applied` counts the demotions.
Failed, skipped, budget-limited and incomplete reviews remain explicit;
they are not clean verdicts. Review records cover deterministic candidates, not the separate
additive SXV-038 findings. No review field is added when review is disabled. Identical
recorded responses yield identical output; fresh model calls may return different opinions.

Fenced-code positions are mapped from generated code only when the original source span
can be verified. Tabs or transformed multiline spans may retain only the known line and
an explicit mapping limitation. Original generated positions/traces remain in evidence;
they are not emitted as if they were verified original-source flows.

Downstream consumers must preserve `effectiveSeverity` (SARIF `error` covers both high
and critical), native `suppressions`, fingerprints, flows and coverage.
