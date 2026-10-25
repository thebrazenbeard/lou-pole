# FreeRowCochkar Architecture

## Mission

FreeRowCochkar is a defensive adversarial analysis engine for rule-governed systems.

Its core invariant is:

> A candidate loophole exists when literal reachable behavior is broader than the intended invariant.

The system is deliberately domain-general. A "rule" may come from a legal or policy text,
an AI instruction hierarchy, an operating procedure, a software specification, source
code, configuration, an authorization boundary, or another machine- or human-enforced
constraint system.

The architecture separates four questions that are often collapsed:

1. What does the source literally say?
2. What behavior does that source permit, prohibit, or require?
3. What composed behavior is reachable when multiple rules interact?
4. Does that reachable behavior violate the author's intended invariant?

FreeRowCochkar should never silently turn question 4 into question 1.

## Architectural principles

### 1. Literal text and interpreted structure remain separate

Source text is immutable evidence for a finding. Extracted rules are interpretations with
their own confidence. Graph edges are derived representations. A graph edge never replaces
the source span that justified it.

### 2. Deterministic before probabilistic

The base engine uses deterministic parsing and graph search. Model-assisted semantic
equivalence may be added later, but it must be labeled as model-derived evidence and may
not silently alter deterministic facts.

### 3. Candidate loophole, not verdict

A path means the written system appears to admit a route worth inspection. It does not
establish that the route is lawful, safe, enforceable, ethical, exploitable, or intended.

### 4. Outcome scope matters

Rules often constrain an actor or verb but fail to constrain the resulting effect. The
graph therefore normalizes effects separately from routes. This is what permits detection
of patterns such as:

- "You must not delete X."
- "You may instruct service Y to delete X."

The route differs; the effect does not.

### 5. Provenance is first-class

Every extracted rule, graph edge, adversarial path, and finding must be traceable back to
one or more source spans.

## Runtime pipeline

```text
input material
    |
    v
line-preserving source-role masking
    |
    v
deterministic clause extraction
    |
    +----------------------+
    |                      |
    v                      v
local heuristics      typed rule extraction
    |                      |
    |                      v
    |               constraint graph
    |                      |
    |                      v
    |              adversarial path search
    |                      |
    +-----------+----------+
                |
                v
       evidence-bound findings
                |
                v
       hardening recommendations
                |
                v
       regression corpus / tests
```

## Layer 0: Input

V1 accepts UTF-8 text from a file or stdin.

Current supported source classes:

- instructions;
- policies and procedures;
- specifications;
- contracts or legal-like text;
- source code;
- mixed text/code documents.

The Markdown lexical boundary masks explicitly quoted and fenced regions from
default operative-policy inference, preserving byte-independent character
offsets and source line numbers. Excluded spans retain their raw text and carry
`attribution_status: unverified` in coverage: formatting is **not** authority
evidence. Callers may explicitly opt in to analyzing these regions. Headings
are retained because operative prohibitions can appear in headings. The lexer
does not infer document-level incorporation, authority, or semantic role.

Future adapters may preserve richer structure from Markdown, YAML, JSON, source ASTs,
policy languages, repository metadata, or document formats. Adapters must preserve
source-location provenance.

## Layer 1: Local deterministic heuristics

The original V1 analyzer operates directly on clauses and code text.

Current detector families:

- ambiguous normative qualifier;
- exception surface;
- precedence collision;
- missing dependency failure behavior;
- indirect-effect scope gap;
- swallowed exception;
- fail-open/default-allow signal;
- overbroad exception boundary.

These detectors are intentionally cheap and explainable. They remain useful even after
the graph engine becomes more capable.

## Layer 2: Typed rule extraction

`rules.py` transforms normative language into `Rule` records.

A rule currently contains:

```text
Rule {
    rule_id
    modality        # permit | prohibit | require | unknown
    subject
    action
    object
    effect_key
    condition?
    exception?
    indirect
    delegated_actor?
    source
    confidence
}
```

The parser is conservative. If the system cannot extract a defensible subject/action
structure, it should omit the rule rather than invent one.
Its bounded approval qualifier recognizes `without prior/explicit/written
approval|authorization|permission|consent` as a guard, not an action. Passive
voice, causative `have` delegation and semantic role mapping need a later
representation; their absence from the graph is not evidence of compliance.

## Layer 3: Constraint graph

`constraints.py` represents a rule system as typed nodes and edges.

Current node families:

- `actor:<subject>`
- `effect:<normalized effect>`
- `route:delegate:<rule>`

Current edge relations:

- `PERMITS`
- `PROHIBITS`
- `REQUIRES`
- `DELEGATES`
- `EXCEPTS`
- `PRECEDES`
- `FALLBACK`

Not every relation is emitted by the V1 parser yet. The enum is the architectural
contract for the next implementation stages.

### Effect normalization

The graph distinguishes route from effect.

Normalization is deliberately conservative. Articles and possessive determiners may be
removed, but scope-bearing qualifiers such as `protected`, `customer`, `audit`,
`temporary`, `all`, or `any` must survive unless an explicit semantic-equivalence
layer supplies separately labeled evidence. Aggressive normalization can manufacture
false loopholes.

For example:

```text
Operators must not delete protected records.
Operators may instruct the cleanup service to delete protected records.
```

Both normalize toward the effect:

```text
effect:delete:protected records
```

The second rule additionally introduces a delegation route. This lets graph search reason
about an equivalent outcome obtained through a different path.

## Layer 4: Adversarial path search

The graph searches for compositions where local literal compliance can reach a globally
restricted result.

V1 implements two graph path classes:

### FRC-PATH-DELEGATE — delegation laundering

A direct prohibition exists for an effect, while another rule permits a delegated or
indirect route to the same effect and the prohibition does not itself cover indirect
production.

### FRC-PATH-CONFLICT — literal permission conflict

The same actor is both permitted and prohibited to produce the same normalized effect,
with no represented precedence rule.

The current parser does not have a theorem prover for conditions. It suppresses
an unconditional conflict when a prohibition's `unless` exception literally
matches a permission's `if`/`when` condition, and does not claim graph
reachability when two explicit guards differ. The ordinary analyzer emits a
medium-severity `guard_overlap_unknown` review candidate for unresolved
guard pairs. `until`, `after`, and related qualifiers are preserved as source
conditions, not evaluated against a clock or event model. The absence of a
graph path is not proof that no violating behavior is reachable.

Future path classes should include:

- exception chaining;
- fallback laundering;
- authority laundering;
- temporal gaps;
- scope hopping;
- identity/role switching;
- retry/idempotency gaps;
- cross-layer policy/code mismatch;
- deny-at-entry / allow-downstream compositions;
- individually legal multi-step sequences with prohibited aggregate effect;
- resource or quota splitting;
- state-reset loopholes;
- stale-policy or version-skew paths.

## Layer 5: Finding synthesis

A graph path is translated into a user-facing `Finding` with:

- stable detector/path ID;
- category;
- severity;
- exact evidence spans;
- explanation;
- literalist path;
- hardening recommendation;
- confidence.

Severity is not legal severity or exploit severity. It is triage severity for the
structural rule-system weakness.

## Intended invariant channel

The CLI accepts `--intent` as a plain-language declaration of what the author meant to
protect.

V1 preserves this in the report but does not yet use it as a semantic constraint.

The CLI additionally exposes heuristic extraction coverage in JSON and text:
extracted rule count and normative-looking source clauses not represented as
rules. Coverage statuses include `empty_input`, `no_rules_extracted`,
`heuristic_partial`, and `heuristic_extracted_unverified`. Markdown excluded
spans are separately enumerated, with attribution explicitly unverified. This
can reveal dropped obligations but is **not** a completeness
certificate; a clause can also be parsed incorrectly without appearing in the
unparsed list. Exit status zero and risk score zero have no clearance meaning.

The opt-in `source` payload binds `content_sha256` to the caller-supplied UTF-8
string, preserving line endings. Its URL, if provided, is caller-declared and
`verification: not_checked`; neither fetching nor external authenticity is
asserted. Graph and report CLI formats use the same digest basis. Code regexes
scan Python executable token regions when the complete input parses as Python,
retaining f-string interpolation. Other/malformed source falls back to generic
regex matching; dynamically executed string content is not proven covered.

Future versions should parse declared invariants into a distinct invariant graph, then
compare reachable literal behavior against that graph. The invariant graph must remain
separate from source-derived rules so the tool never rewrites literal meaning to fit
declared intent.

## Evidence classes

FreeRowCochkar should preserve these evidence classes:

1. `SOURCE_LITERAL` — exact source text and location.
2. `DETERMINISTIC_PARSE` — rule structure produced by reproducible parsing.
3. `DETERMINISTIC_GRAPH` — graph edge/path derived from deterministic rules.
4. `MODEL_SEMANTIC_CANDIDATE` — future model-derived equivalence or interpretation.
5. `EXTERNAL_AUTHORITY` — future cited statute, precedent, standard, docs, or other external source.
6. `HUMAN_ACCEPTED` — a reviewer has accepted the interpretation for a particular use.

Higher classes do not erase lower classes.

## Trust boundaries

FreeRowCochkar must distinguish:

- finding a structural weakness;
- asserting a real-world exploit works;
- asserting a legal interpretation is valid;
- executing an exploit;
- changing the audited target.

The analyzer should perform the first. The remaining effects require separate tooling,
evidence, and authority.

## Failure model

Important failure classes include:

- parser false positives;
- parser false negatives;
- effect-normalization collisions;
- failure to distinguish direct and indirect scope;
- unrelated text suppressing a local detector;
- source-span drift;
- duplicate findings from local and graph detectors;
- hidden precedence not represented in the graph;
- semantic equivalence guessed too aggressively;
- model-generated structure presented as deterministic;
- version skew between analyzed source and reported findings.

The engine should prefer "candidate not established" over invented structure.

## Testing strategy

Every detector or path class should have:

1. a positive fixture that must trigger;
2. a minimally changed negative fixture that must not trigger;
3. an adversarial regression case based on a previously observed false positive/negative;
4. stable source spans;
5. deterministic JSON shape.

Cross-version Python CI is required for the package baseline.

Future semantic/model layers need frozen evaluation corpora and must report deterministic
and model-derived results separately.

## Package boundaries

```text
src/freerowcochkar/
    analyzer.py       orchestration and finding synthesis
    source_roles.py   Markdown lexical masks and excluded-span evidence
    models.py         public report/finding data model
    rules.py          deterministic normative-rule extraction
    constraints.py    typed graph and adversarial path search
    cli.py            command-line interface
```

As the project grows, likely boundaries are:

```text
parsers/             source-specific adapters
graph/               richer graph representation and searches
semantics/           optional semantic-equivalence engines
corpus/              adversarial fixtures and benchmark cases
hardening/           patch generation and closure checks
provenance/          source digests, spans, exact-version bindings
integrations/        repository/CI/pre-commit adapters
```

## Non-goals for the base engine

The deterministic core should not:

- invent law or precedent;
- assert that a loophole is legally valid;
- silently execute discovered paths;
- mutate audited repositories by default;
- treat model confidence as proof;
- hide contradictory evidence;
- optimize merely for number of findings.

The desired behavior is fewer, stronger, reproducible candidates.

## Architectural frontier

The next major implementation target is a multi-step state-transition graph.

Instead of only matching two rules that share an effect, the engine should model:

```text
state --action/rule--> state --action/rule--> ... --> effect
```

Then it can search for a path where every edge is locally permitted but the terminal
state violates a prohibition or declared invariant.

That is the transition from a sophisticated linter to a genuine compositional loophole
finder.
