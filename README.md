> **License:** Source-visible, not open source. Original material is proprietary. Commercial use, redistribution, hosted-service use, and commercial derivative products require written permission. See [LICENSE](LICENSE) and [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md). Separately identified third-party components retain their own licenses.

# FreeRowCochkar

A defensive adversarial loophole finder inspired by the literalist, boundary-testing
reasoning associated with Nick Freeman, Clarence Darrow, Johnnie Cochran, and
B. R. Ambedkar.

The name is a mashup; the actual project is broader than law.

FreeRowCochkar asks a specific question:

> Where can someone obey the written rules literally while defeating what the system
> was clearly built to accomplish?

That question applies to legal and policy text, AI or human instructions, software
specifications, code, configuration, authorization systems, operating procedures, and
compliance controls.

## What V1 does

The first implementation is deterministic and dependency-free. It reports candidate
loopholes with exact evidence, an adversarial literal-reading path, and a hardening
suggestion.

Current detectors cover:

- vague qualifiers inside mandatory or prohibitive rules;
- exceptions that can swallow a base rule;
- overlapping instructions with conflicting permission or prohibition;
- required external dependencies with no defined failure path;
- prohibitions that cover direct action but omit delegated or indirect equivalents;
- swallowed exceptions in code;
- broad exception boundaries;
- fail-open and allow-by-default code signals.

This is intentionally an auditor, not an oracle. A finding means "inspect this boundary,"
not "this is definitely exploitable" and not "this behavior is lawful."

## Install

~~~bash
python -m pip install -e .
~~~

## Use

Audit an instruction or policy file:

~~~bash
freerowcochkar policy.md
~~~

Audit code:

~~~bash
freerowcochkar auth.py --profile code
~~~

Pipe text directly:

~~~bash
printf 'Operators must take reasonable steps before release.' | freerowcochkar -
~~~

Add the invariant the author actually intended:

~~~bash
freerowcochkar rules.md --intent "No protected effect occurs without explicit authorization"
~~~

Machine-readable finding output:

~~~bash
freerowcochkar rules.md --json
~~~

Inspect the extracted rule/constraint graph and adversarial paths:

~~~bash
freerowcochkar rules.md --graph-json
~~~

Both JSON outputs include a `coverage` summary: how many rules were extracted,
which normative-looking clauses were not parsed, and a limitation notice. Coverage
has an explicit status such as `heuristic_partial` or
`heuristic_extracted_unverified`, never a claim of complete parsing. An
exit status of zero means no *detected* high-severity findings (or graph paths);
it does **not** mean the input is safe, fully parsed, or compliant. The numeric
risk score is a triage heuristic, not exploit likelihood.

The typed graph recognizes a bounded subset of English. It handles common
permission/prohibition forms, certain direct/delegated effects, and textual
conditions. A ban qualified by `unless X` and a permission guarded by the
*identical* `if X`/`when X` predicate are not reported as an unconditional
conflict. Other pairs of distinct guards are surfaced as unresolved by the
regular analyzer; this is **not** proof of temporal or logical disjointness.
Role aliases, complex nested clauses, implied exceptions, and external
authorization still require independent review.

### Source attribution and known blind spots

Markdown blockquotes and fenced code are **excluded from default operative-rule
inference**, with line-preserving offsets. Their excluded spans appear in JSON
as `coverage.nonoperative_clauses`, each marked `attribution_status: unverified`.
This is **not** a claim that a quoted passage is legally or operationally
nonbinding: a document can explicitly incorporate quoted text. Headings are
**not** excluded; they may contain binding rules. To explicitly treat quotes
and fences as active input, use `--include-nonoperative`. An empty finding set
does not establish safety, particularly when excluded or unparsed spans exist.

To bind a report to the exact UTF-8 text submitted for analysis, pass
`--provenance` with `--json` or `--graph-json`. `--source-url URL` optionally
labels that content; the URL is **not fetched or verified**. The reported
`content_sha256` digests the original analyzed string, including line endings,
not its filtered view or any purported remote file.

Normative grammar is deliberately incomplete. The parser recognizes some
`without [prior|explicit|written] approval/authorization/permission/consent`
guards without mistaking the approval requirement for an executable effect.
Passive voice, causative `have` delegation, richer condition logic, and implicit
actor/role equivalence remain unparsed. Code scanning masks comments and
ordinary string literals **only for parseable Python**; f-string interpolations
are retained. Other or malformed languages use generic regex fallback, and
executable code dynamically assembled in `exec()`/`eval()` strings is **not
analyzed**. These are explicit coverage limitations, not clearance findings.

## Example

Input:

~~~text
Operators must not export customer records.
Operators may export customer records for support.
~~~

FreeRowCochkar flags a precedence collision because a motivated literalist can point to
the permissive rule and claim that "for support" controls the prohibition. The hardening
question is then concrete: who can invoke that exception, under what conditions, with
what scope, and which invariant remains non-waivable?

## Direction

V1 uses reproducible heuristics. The next major layer is a typed constraint graph:

~~~text
rule text
  -> obligations / permissions / prohibitions / exceptions / delegation
  -> state-and-action graph
  -> adversarial path search
  -> evidence-bound loophole candidate
  -> hardening patch
  -> regression case proving the patch closes the path
~~~

That is the core of the project: not merely linting words, but searching the reachable
space between literal rules and intended outcomes.

Architecture is committed in the repository:

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — system layers, graph model, evidence classes, failure model, and package boundaries.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — the motivated-literalist adversary and protected properties.
- [docs/ROADMAP.md](docs/ROADMAP.md) — staged path from deterministic linting to multi-step compositional search and policy/code comparison.
- [docs/DESIGN.md](docs/DESIGN.md) — concise design rationale and detector inventory.
