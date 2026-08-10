# @actor / @entitles — Design

Status: **implemented in guardlink** (§8 records where). Consumer side (bugb) still to do.
Primary repo: **guardlink**. Consumer: **bugb / siete**
(`report/triage.py`, rubric item 3 of `docs/prd/triage-adjudicator-design.md`).

Depends on: nothing new in guardlink. bugb's side is a hook that already exists and is starved of
data (`measure_privilege`, `RubricItem.ENTITLED_PRINCIPAL`).

This doc proposes two annotations. It also records, in §7, four gaps found during the same
investigation that are **not** fixed here and that I rank as more consequential — because they cause
silence rather than noise. The scope of this doc is deliberately the smaller of the two.

## 1. Problem

Three findings against `temporalio/temporal` were filed as advisories and all three rejected, with
every technical claim conceded. One shared shape:

> **the privilege required to trigger the effect is a privilege that already legitimately grants that
> effect.**

- *path traversal*: "Setting it requires namespace Admin, the role that configures a namespace's
  archival destination **by design**."
- *Nexus SSRF*: "All Nexus endpoint management APIs require cluster-level admin privileges."
- *JWT audience*: "Reaching those paths already requires a JWT the cluster accepts."

That question — *is the caller already entitled to this effect?* — has no field to read. guardlink's
17 verbs are:

```
Relations     exposes · mitigates · accepts · transfers · flows · boundary
Evidence      confirmed
Lifecycle     validates · audit · owns · handles · assumes
Metadata      feature
Special       comment · shield (+ begin/end)
Declarations  asset · threat · control
```

None names a **principal**. `@owns` is *team* ownership (`@owns security-team for App.API` —
"responsible team"), not authority. `@boundary between #namespace-api and #archival-fs` names two
assets, so it cannot say whether crossing is a privilege change. Severity lives on the threat class
globally, so `#path-traversal [critical]` holds regardless of who can reach it.

The measured cost, from bugb's first validation run against that repo: **all 13 triage assessments
landed on `needs-decision`**, 11 of them failing on `entitled-principal` alone. Nothing could be
rated, reported or dismissed on privilege grounds. The rubric item exists, the disposition mapping
exists (`→ BY_DESIGN`), and the answer has no source.

## 2. The insight

Entitlement is a statement about **purpose**. It cannot be probed, measured or derived from the code
by inspection alone — which is exactly why it needs to be *written down* rather than computed.

But that makes it the most dangerous kind of annotation in the language, because it is the only one
whose error mode is a **silent false negative**. So the design is driven by the asymmetry rather
than by the feature:

| Error | Effect | Verdict |
|---|---|---|
| **Under-grant** — fewer entitlements than reality | finding stays `eligible`; extra noise | tolerable |
| **Over-grant** — more entitlements than reality | real escalation closed as `by-design` | **unacceptable** |

Two things narrow the exposure more than they first appear.

**Triage asks about the measured floor, not the annotation's subject.** An entitlement naming
`admin` cannot conceal a writer-level bug, because if a writer succeeded the question becomes *"is
writer entitled?"*. To cause a false negative, an annotation must over-grant **precisely the role
the defect admits**.

**bugb already requires a failed lower-privileged attempt** before it will call minimum privilege
measured (`triage-adjudicator-design.md` §3.3). An entitlement can only ever act on top of a
measurement that already exists.

## 3. The decisions

### 3.1 Grammar

Two annotations, following §2.1's general form. `@actor` is a **definition** annotation (§3.1),
declared once per project along`@asset`/`@threat`/`@control`. `@entitles` is a **relation**.

> **Amended by §9.** The `against <threat>` clause below, and the demotion of `<capability>` from
> join key to justification, are §9's decisions. §9 supersedes the final paragraph of this section.

```
@actor <Name> (#<id>) [-- "<description>"]

@entitles <actor> to <capability> [on <asset>] [against <threat>] [-- "<description>"]
```

```
# @actor Namespace_Admin (#ns-admin) -- "Administers one namespace's configuration"
# @actor Namespace_Writer (#ns-writer) -- "Starts and signals workflows in its namespace"

# @entitles #ns-admin to configure-archival-destination on #archival-fs against #path-traversal
#     -- "By design: the archival URI is namespace configuration. Authz: ScopeCluster/AccessAdmin
#         at common/api/metadata.go:189"
```

`<capability>` is a normalised identifier (§2.10), not free prose — enforced by the grammar, so
writing prose there is a parse error rather than a silently unusable value.

### 3.2 An entitlement never gates testing — only reporting

The strongest constraint in this design.

guardlink already has two annotations that remove an exposure from the SARIF export entirely —
`@mitigates` and `@accepts`. In the reference repository **three pairs are hidden that way right
now**, and bugb's intake reports them as *"hidden from the pentest export … and cannot be tested
until that is audited."* A suppression that also prevents verification is how a threat model becomes
confidently wrong.

`@entitles` must not become the third such mechanism. It carries **no export semantics**. The
exposure is probed exactly as before; only the *recommendation* changes, downstream, in bugb's
triage. A reader of the SARIF cannot tell an entitlement exists.

### 3.3 `by-design` stays visible, with its citation

An entitlement that demotes a finding must surface the demotion and the reason. In bugb that is the
hardening bucket, reading *"closed because #ns-admin is entitled to configure-archival-destination,
per common/api/metadata.go:189"*.

The point is not tidiness. An over-grant is the failure mode that matters, and the only way it gets
caught is if a human sees the sentence and disagrees with it. A finding that silently disappears
cannot be argued with.

### 3.4 No citation, no effect

An `@entitles` whose description does not point at the authorization code that grants it is **inert**
— parsed, exported, and ignored by triage. Same rule bugb's recon already enforces: no uncited claim
may demote a finding.

This is also what makes the annotation reviewable. `ScopeCluster/AccessAdmin at
common/api/metadata.go:189` is checkable by a reviewer in the pull request that adds it, and
`guardlink diff` can flag the entitlement as stale when that file changes.

### 3.5 Ownership-class threats are out of scope, structurally

**Entitlement models capability. It cannot answer an ownership question, and must be prevented from
trying.**

For two peers at the same privilege — tenant A's admin against tenant B's namespace — *both* are
entitled to the capability. The question is whether either is entitled to **this object**:

```
@entitles #ns-admin to delete-namespace        <- says nothing about WHOSE namespace
probe: tenant-A admin deleted tenant-B's namespace
"is the measured role entitled?" -> yes -> by-design            WRONG
```

That is the over-grant false negative arriving *structurally* rather than from a bad annotation. An
IDOR is **right capability, wrong object**.

So: for ownership-class threats — `#namespace-isolation`, IDOR, and CWE-639/862/863-shaped classes —
the entitled-principal check is **not applicable**, and an entitlement may never demote them. Those
are answered by the two-arm differential (did A reach B's object?), which bugb measures and cxg's
`mutator._looks_cross_identity` already requires two-arm evidence for.

Ownership is deliberately **not** added to the grammar here. `@owns` means responsible team, and
overloading it — or adding a tenancy verb — would invite exactly the conflation this section
forbids. Ownership stays measured.

### 3.6 Drafted by an agent, accepted by a human

The volume is small: the reference repository's entire role model is roughly a dozen actor/capability
pairs (`System:Admin`, namespace `Admin/Write/Read/Worker`, crossed with a handful of capabilities).

Given the error mode is a silent false negative, the annotating agent should **propose** entitlements
with citations into a review artifact, and only accepted ones land in source. Two reasons beyond
caution: the annotating agent runs under *attack* lenses, so its incentive is to find exposures
rather than to grant authority; and an entitlement is precisely the kind of claim a maintainer will
contest, so it should carry a human's name.

### 3.7 Validation

`guardlink validate` gains two mechanical checks — both are typo-class, neither can verify intent:

- an `@entitles` naming an actor with no `@actor` declaration is an error;
- an `@actor` id declared twice is an error, matching the existing rule for `@asset`/`@threat`.

`guardlink diff` reports an entitlement whose cited file changed, as stale rather than as removed.

## 4. Non-goals

- **Not a suppression mechanism** (§3.2). No export semantics, no effect on what gets probed.
- **Not an answer to IDOR or any ownership question** (§3.5).
- **Not automatically verifiable.** An entitlement is a claim about purpose; nothing can probe it.
  The citation, the visibility and the human acceptance are the only checks that exist, and this doc
  does not pretend otherwise.
- **Not a severity model.** Severity remains on the threat class; deriving it per exposure from
  (principal, effect, boundary) is a larger change and is listed in §7.
- **Not a deployment/config dimension.** "This exposure only exists under configuration X" is still
  inexpressible — see §7.

## 5. Compatibility

Purely additive. A model with no `@actor`/`@entitles` parses and exports exactly as today, and
bugb's `entitled-principal` continues to resolve unanswered, which escalates to `needs-decision`
rather than demoting. No existing annotation changes meaning.

## 6. Testing

- Grammar: both forms parse, including the optional `on <asset>` and the description; a missing
  citation parses but is marked inert.
- `validate`: undeclared actor is an error; duplicate actor id is an error.
- Export: SARIF for a model with entitlements is **byte-identical** to one without, except for the
  entitlement payload itself — proving §3.2.
- `diff`: an entitlement whose cited file changed reports stale.
- Consumer contract (in bugb): an entitlement demotes only when minimum privilege is *measured*, only
  for the measured role, never for an ownership-class threat, and never without a citation.
- Regression from the reference repo: `archival-fs::path-traversal` with
  `@entitles #ns-admin to configure-archival-destination` moves `needs-decision → by-design`, while
  `frontend-api::namespace-isolation` stays unaffected (§3.5).

## 7. Found in the same investigation, not fixed here

Ranked by consequence. **The first two I consider more important than this document's subject**,
because they cause silence rather than noise — and a threat-model tool that goes quiet is worse than
one that is merely noisy.

1. **`guardlink diff` keys exposures on `asset::threat` alone**, so it cannot see a newly discovered
   weakness in a pair it already knows. bugb had to write its own delta and says so in
   `phases/p40_export.py`; the reference repo has **17 pairs holding more than one distinct
   exposure**, so anyone relying on guardlink's diff alone gets a false "no change".
2. **`@accepts` / `@mitigates` remove an exposure from the export**, with no owner, no expiry and no
   review date. Three pairs in the reference repo are in that state, and the only reason anyone knows
   is that bugb's intake reports it. An acceptance should be time-boxed and attributable.
3. **Reachability is sparse and coarse.** 16 of 64 exposures in the reference SARIF carry a route,
   and the fallback (`routeByFile ?? routeByAsset`) attaches whichever route was seen first — on
   another repo, 6 of 17 entries claimed the same path for unrelated handlers. bugb already
   distrusts the fallback and only feeds `BY_FILE` routes into goal synthesis.
4. **No deployment/configuration dimension.** The reference repo models "authorization is off by
   default" as a *threat* (`#auth-open`), which is a workaround for the absence of a way to say "this
   exposure exists only under configuration X". bugb compensates by emitting severity per reference
   configuration; guardlink cannot express the condition at all.
5. **Severity is a property of the threat class, not of the exposure.** `@threat … [critical]` holds
   globally, so `#path-traversal` is critical regardless of who can reach it or what boundary is
   crossed. Deriving it per exposure from (principal, effect, boundary) is the natural completion of
   §3.1 — and is precisely what would have made the three rejected advisories rate themselves
   correctly. `@exposes` accepts a severity override, but that restates a number rather than deriving
   one. bugb compensates with severity-per-reference-configuration; guardlink has no model for it.
6. **`@boundary` names two assets, not two trust levels.** `@boundary between #namespace-api and
   #archival-fs` records that a crossing happens, not whether it is a *privilege* change — so the
   rubric question "does this cross a boundary the vendor asserts?" is answered by inference rather
   than by the model. With `@actor` in the language, a boundary could name the principals on each
   side, which is the smaller and more useful version of §7.5.
7. **No vendor support-status.** "The filestore archiver is documented for local installations and
   testing, not production" is the single external fact that decided the strongest of the three
   rejections, and it is inexpressible — not in `@audit`, not in `@assumes`, nowhere. It is also not
   derivable from the code: the source says only *"archive workflow histories to local disk"*, which
   is a description of behaviour, not a statement of supported scope. bugb reaches it with a network
   lookup at intake; guardlink cannot record it even once it is known.

8. **`@confirmed` has no supersession or staleness model, so verdicts accrete.** In the reference
   repo `components/callbacks/config.go` carries **two** `@confirmed #ssrf on #callbacks` — lines 75
   and 77 — and the only thing marking the second as a re-assertion rather than new evidence is its
   prose: *"Re-listed as CONFIRMED by pentest run 20260809-162437 … Treat this entry as a
   re-assertion of the earlier verdict, not as new callback evidence."* There is no run id, no date
   and no `supersedes` relation, so nothing mechanical can tell a fresh proof from a restatement of
   an old one. Three consequences compound: an automated writer adds one per confirming run, so the
   file grows without bound; §7.1's diff cannot distinguish a re-assertion from a discovery; and a
   consumer that counts annotations per site — which bugb's write-back verification now does, by
   necessity — has a duplicate credit a pending record it did not prove. The honesty is currently
   carried entirely by the annotating agent choosing to write that sentence, which is the right
   instinct in the wrong place.

Also noted, smaller: the workspace convention that **all `@asset`/`@threat`/`@control` declarations
live in one shared file** ("Never redeclare an ID that exists in this file") serialises annotation —
any parallel writer must either merge into that file or hold a lock, which is the binding constraint
on fanning annotation out across a large tree. And `@assumes` and `@transfers` exist and are unused in the reference repo, and
`@assumes` looks like the natural home for "internode RPC is expected to run on a trusted network" —
which is currently argued in prose. And parse errors are tolerated: bugb's intake reported *"the
existing annotations contain parse errors"* on two separate derives, with no gate.

## 8. What was built

The guardlink half of this document is implemented. Nothing in §1–§6 was renegotiated
during implementation; the notes below are where a decision needed a concrete shape.

**Grammar** — `src/parser/parse-line.ts`. `@actor` reuses the `@control` shape
(`<Name> (#id) -- "desc"`); `@entitles` takes an actor ref, the capability, an optional
`on <asset>`, and a description. Capability is a single token (`[A-Za-z][A-Za-z0-9_.\-]*`),
so writing prose there is a **parse error** rather than a silently unjoinable key — the
grammar enforces §3.1 instead of trusting it. Both `capability` (as written) and
`canonical_capability` (§2.10-normalised, the join key) are carried, following the
`name`/`canonical_name` precedent on `@threat`.

**Citation** — `src/parser/citation.ts`. §3.4 needed a decision the doc left open: what
counts as "pointing at the authorization code". A citation is a `path/to/file.ext` token,
optionally `:line`, extracted from the description. `Authz: ScopeCluster/AccessAdmin` does
not match (no file extension), nor does `cwe:CWE-89` or a URL. The file is never opened —
whether the path exists is a reviewer's question, not the parser's. Every entitlement
carries `inert: boolean`, so a consumer cannot read an uncited claim as an effective one
by forgetting to check.

**No export semantics (§3.2)** — enforced by a test, not by a comment:
`tests/actor-entitlement.test.ts` asserts `JSON.stringify` equality between the SARIF for a
model with entitlements and the same model without. `src/analyzer/sarif.ts` carries a note
saying not to "complete" the exporter by adding them.

**Validation (§3.7)** — `findUndeclaredActors` (error) and `findInertEntitlements`
(warning) in `src/parser/validate.ts`, wired into `guardlink validate`, `/validate`, and
`guardlink_validate`. Duplicate actor ids fall out of the existing generic id check for
free. Actor ids join `definedIds` in `findDanglingRefs`, so an actor ref is not
double-reported as both dangling and undeclared.

**Staleness (§3.7)** — `diffModels` cannot derive "the cited file changed" from two models,
so it takes an optional `changedFiles` list; `getChangedFiles(root, ref)` supplies it from
`git diff --name-only`. A stale entitlement is reported even when the delta is otherwise
empty, since by definition the annotation itself did not change. An uncited entitlement has
no basis and cannot go stale. Diff keys an entitlement on (actor, capability) per §3.1, so
a changed `on <asset>` is a modification rather than an add plus a remove.

**Visibility (§3.3)** — the demotion sentence belongs to bugb, but everything it needs to
write one is surfaced here: `guardlink report` prints an Entitlements section with each
citation and lists declared principals under Roles & Access; the dashboard has an
Entitlements table that marks uncited rows inert; `guardlink lookup actors` /
`lookup entitlements [for #actor]` and `guardlink_status` expose the same via MCP;
`guardlink sync` carries entitlements into agent instruction files so an annotating agent
stops re-filing capabilities that are already granted by design.

**Compatibility (§5)** — `actors` and `entitlements` are optional on `ThreatModel`, so a
report JSON written before this change still satisfies the schema and older readers are
unaffected. Every reader uses `model.entitlements || []`.

**Propose then accept (§3.6)** — `src/review/entitlements.ts`, next to the existing
exposure review rather than beside it: both writers share `insertAnnotationsAt`,
`detectCommentStyle` and `escapeDesc` from `src/review/index.ts`, so an accepted
entitlement lands by the same rules as an accepted risk.

The artifact is `.guardlink/entitlement-proposals.json` — versioned JSON, like
`config.json`. A proposal carries the actor, the capability, the optional asset, the
threat it is meant to answer for, the rationale, the citation extracted from it,
the target `file:line` an accepted annotation would be written to, who proposed it,
and the decision history. It is a ledger, not a queue: a decision is appended and
no record is deleted, so a rejection stays readable next to the claim it refused.
Identity is `(actor, capability)` — the same key `diff` uses per §3.1 — so re-filing
the same claim updates it instead of accumulating near-duplicates, and an agent
cannot resurrect a claim a human has already accepted or rejected by filing it again.

Four things are enforced in code rather than asked for in a prompt:

- **§3.4 has teeth at the accept step.** Accepting an uncited proposal raises
  `InertProposalError` unless the human passes `acknowledgeInert` (`--acknowledge-inert`,
  or typing `inert` at the interactive prompt). When they do, the annotation that lands
  carries a `@comment` saying it is inert and who accepted it that way — an inert claim
  in source should read as inert.
- **§3.5 is surfaced at proposal time and gates the accept.** Ownership-class shapes are
  matched on the threat (`#namespace-isolation`, IDOR, tenancy, BOLA, CWE-639/862/863),
  on ownership language in the rationale, and against ownership-class exposures already
  recorded on the proposal's asset. The warning is stored on the proposal and re-shown
  before the decision; accepting over it raises `OwnershipClassProposalError` unless the
  human acknowledges it (`--acknowledge-ownership`, or `y` at the prompt), and the
  annotation that lands then repeats the warning with their name on the override. The
  match is a heuristic, so it warns rather than forbids — but it cannot be walked past
  without being read. Rejecting is never gated.
- **An `@entitles` no human accepted is a validation error.** `findUnacceptedEntitlements`
  compares source against the ledger and is wired into `guardlink validate` and
  `guardlink_validate`. It is skipped entirely when the project has no ledger, so a repo
  that has not opted into the flow is not retro-actively in violation. This is what
  stops an agent writing the annotation directly: the claim still parses, but it arrives
  in a diff with a red mark on it.
- **The line is proved before it is written.** `buildEntitlesBody` runs the real
  `parseLine` over the annotation it is about to insert, so a claim that would not be
  read back as an entitlement is a proposal-time error rather than a line in source that
  the model silently lacks. Free-text fields are collapsed to one line first, so a
  newline in an agent-supplied rationale cannot forge a second annotation.

**Surface** — `guardlink entitle` mirrors `guardlink review`: interactive by default
(accept / reject / defer / skip / quit), `--list`, `--status` to filter, and
non-interactive `--propose`, `--accept <id>`, `--reject <id>`, `--defer <id>`, plus the two
acknowledgement flags. A decision needs a name (`--by`, else `git config user.name`, else
`$USER`, else it asks), and a rejection needs a reason. Proposals are walked bottom-up
within a file, since an acceptance inserts lines above every anchor below it. Over MCP an agent gets `guardlink_entitlement_propose` and
`guardlink_entitlement_list` and nothing else: there is **no accept tool**, for the same
reason agents do not write `@accepts`. The annotate prompt now points agents at the
propose path instead of at the annotation.

`tests/entitlement-proposal.test.ts` holds the cases: a proposal round-trips through the
artifact; an acceptance writes a line the real parser reads back as an entitlement with
the accepting human named; an uncited proposal cannot become effective without the
acknowledgement, and is still reported inert afterwards; a rejection leaves source
byte-identical; an ownership-class claim is refused until acknowledged; and an `@entitles`
with no accepted proposal is an error while a repo with no ledger is left alone.

**Not built here** — the §7 items remain open.

## 9. Amendment: the capability join

Status: **proposed**. Amends §3.1. Written before the bugb consumer, because getting this wrong
produces silent wrong answers of exactly the kind §2 exists to prevent.

### 9.1 What the join has to answer

Triage holds a finding — an `(asset, threat)` pair — and a **measured role** (§3.3 of
`triage-adjudicator-design.md`). It must decide whether that role is entitled to the effect the
finding achieves.

§3.1 as written says `<capability>` is the join key. That cannot work, because **nothing on the
finding side carries a capability**. An exposure names an asset and a threat; there is no operation
recorded anywhere for the join to match against.

The deeper reason is that an entitlement is inherently a link between two *different* things:

- a **benign capability** — Namespace Admin may configure the archival destination;
- a **dangerous effect** — that configuration reaches an unconfined path write.

Admin is entitled to the first. Admin is emphatically **not** entitled to the second — that the one
enables the other *is the defect*. This is the maintainer's own position on the reference finding:
*"You're correct that the archival directory is not confined to a root, and we'll look at confining
it"*, alongside a refusal to treat it as a vulnerability. The entitlement is the judgment that the
benign capability legitimately carries the dangerous exposure. It is not an assertion that the role
may cause the effect, and a design that reduces it to one is stating something untrue.

### 9.2 The three candidate joins

| | Grammar | Join key | Over-grant risk |
|---|---|---|---|
| **A** — as shipped | `to <cap> on <asset>` | `(actor, asset)` | **Unacceptable.** Demotes *every* threat on that asset for that role, including one discovered later. An entitlement written for a path-traversal would silently demote a future deserialization bug in the same archiver. |
| **B** — add a threat slot | `to <cap> on <asset> against <threat>` | `(actor, asset, threat)` | **Narrowest available.** Over-granting requires naming the exact pair that carries the defect. |
| **C** — exposures declare what they abuse | `@exposes … abuses:<cap>` plus `to <cap>` | `capability` | Narrow, and the two halves are authored by different parties at different times. |

A is what the parser does today: `asset` is optional and there is no threat slot, so an entitlement
either joins too broadly or does not join at all. Since §2 fixes the design's whole direction against
over-granting, A cannot stand.

### 9.3 Decision: B

```
@entitles #ns-admin to configure-archival-destination on #archival-fs against #path-traversal
    -- "By design: the archival URI is namespace configuration.
        Authz: ScopeCluster/AccessAdmin at common/api/metadata.go:189"
```

The join is **`(actor, asset, threat)`**. Three consequences, all deliberate:

1. **`<capability>` is no longer the join key.** It is the justification — the operation a reviewer
   reads to judge whether the claim is honest. `canonical_capability` remains in the model as a
   normalised label and for grouping, and the "the join key" comments on
   `ThreatModelEntitlement.canonical_capability` and `EntitlesAnnotation.canonical_capability` are
   now wrong and must be corrected. This reverses §3.1's final paragraph.
2. **An entitlement lacking either `on <asset>` or `against <threat>` cannot demote.** It joins
   nothing, so it is treated exactly as `inert` is under §3.4: carried in the model, visible to a
   reviewer, ineffective. The precise form is opt-in and the loose form is harmless, which is the
   right default for the one annotation whose error mode is silent.
3. **Grammar cost is one optional clause**, consistent with `@accepts <threat> on <asset>`.

Granularity is right in practice. In the reference repository `archival-fs::path-traversal` spans
four exposures across three files but is a single pair, so one entitlement covers all four; while
`namespace-api::path-traversal` requires its own, correctly, because it is a different handler behind
different authorization. That repository would need roughly a dozen entitlements in total.

### 9.4 The objection, stated rather than discovered

**B is shaped like `@accepts` scoped to an actor.** `@accepts #path-traversal on #archival-fs` says
"we accept this risk"; B says "this is fine when Namespace Admin does it". Anyone reviewing the
grammar will notice, so it is better named here than found later.

Two differences make them genuinely distinct, and both are load-bearing:

- **`@accepts` removes the exposure from the SARIF export; `@entitles` never does** (§3.2). The
  threat is still probed on every run.
- **`@accepts` is unconditional; an entitlement acts only when the *measured* role matches** (§3.3 of
  the triage design). A finding proved by a lower-privileged identity is unaffected by an entitlement
  naming admin.

So `@accepts` says *stop looking*, and `@entitles` says *keep looking, and here is who may legitimately
succeed*. If that distinction ever erodes — if an entitlement gains export semantics — the annotation
has become a suppression and should be deleted rather than fixed.

### 9.5 Why not C

C is the better design on one axis that matters: the exposure's author names the operation
(`abuses:configure-archival-destination`) independently of anyone claiming entitlement, so the two
halves of the judgment are written by different people at different times. For a claim whose failure
is silent, two-party authorship is a real review property, and it keeps `capability` as an honest
join key.

It is rejected on cost and on where that cost falls. C annotates **every exposure** — the hot path,
written under attack lenses, where the annotating agent's attention should be on the weakness rather
than on the operation that reaches it. B puts the burden on the dozen entitlements, which are
human-accepted anyway under §3.6. C also has a failure mode B does not: an exposure whose `abuses:`
is wrong or missing silently stops joining, and nothing distinguishes that from "no entitlement
exists".

C stays on the table for a future revision. If entitlements ever need to span assets — the same
capability reached through several handlers — C is the shape that does it without repetition.

### 9.6 §3.5 is unchanged and independent

Ownership-class threats (`#namespace-isolation`, IDOR, CWE-639/862/863-shaped) can never be demoted
by an entitlement **regardless of how precise the join is**, because both peers hold the capability
and the question is about the object. §3.5's rule sits above the join and is unaffected by this
amendment. A perfect `(actor, asset, threat)` match on a namespace-isolation finding must still be
refused.

### 9.7 What this changes in the shipped code

- `parse-line.ts` — add the optional `against <threat>` clause to `PATTERNS.entitles`; resolve it
  with `resolveRef` as the other threat refs are.
- `types/index.ts` — `threat?: string` on `EntitlesAnnotation` and `ThreatModelEntitlement`; correct
  both "the join key" comments on `canonical_capability`.
- `parse-project.ts` — carry `threat` through into the model entry.
- A model-level predicate for "can this entitlement demote": cited **and** has both `asset` and
  `threat`. Better computed once in guardlink than re-derived by every consumer, since forgetting it
  is the silent failure.
- `diff/engine.ts` — an entitlement's identity for change detection becomes
  `(actor, asset, threat)`; capability is compared *within* that identity, so a capability edit on
  the same triple reads as a modification rather than an add plus a remove (§9.8). An earlier draft
  of this line put capability in the key, which contradicted §9.8 and §9.3 — anything in the key
  makes an edit read as remove+add.

### 9.8 Testing

- `against #threat` parses, resolves, and round-trips into the model.
- An entitlement with `on` but no `against` is carried and reported as unable to demote; likewise
  `against` with no `on`.
- Uncited **and** imprecise are reported independently — a reviewer needs to know which is missing.
- SARIF remains byte-identical to a model without entitlements (§3.2 regression, now including the
  threat slot).
- `diff` reports a capability change on the same `(actor, asset, threat)` as a modification rather
  than an add plus a remove.
- Consumer contract: a `(actor, asset, threat)` match demotes only when minimum privilege is
  *measured* and the measured role is the named actor; an ownership-class threat is refused even on
  an exact match (§9.6).
