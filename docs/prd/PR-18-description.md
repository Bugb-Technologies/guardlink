## What does this PR do?

**Stacks on #17** — `fix/first-run-experience` branches off
`fix/defect-sweep-post-epic`, so this diff contains #17 in full. Review #17
first; this PR is six commits on top of it.

Two write-path defects that corrupt the model, and four that land in a user's
first five minutes.

**The write path validates what it writes (D39, D51).**
`guardlink_annotate_apply` promised "malformed input is rejected with the reason"
and then accepted both an invented reference and a source file that does not
exist, each with `ok: true, errors: []`.

- D39: `@mitigates #api against #xss-by-render using #octet-stream`, neither id
  declared anywhere, was written. `validate` warned later, exit 0 — so an
  invented reference survived the write path, the validate path and CI.
- D51: a sidecar for a mistyped filename was written and its annotations entered
  the model — a phantom critical exposure attributed to a file not in the repo —
  and `validate` then reported "Validation passed". The path check already
  existed and was wired to `guardlink_context`, the tool that cannot cause harm.

Both now reject with a reason. Forward references are legitimate, so they are an
explicit opt-in rather than a prohibition: `allow_undeclared_refs: true` writes
and returns a `warnings[]` naming each undeclared id. The default rejects,
because an undeclared reference is overwhelmingly a typo and the workflow we ship
to every agent is definition-first.

These two were fixed and D40/D41 deliberately were not: D40 and D41 produce
output a caller can see is wrong, while these produce a threat model that is
confidently wrong and stays wrong.

**The first five minutes (D38, D43, D44, D45).** Four places where the tool
disagreed with itself inside one command's output, or pointed somewhere that did
not exist.

- **D38** — `init`'s "Next steps" said "Add annotations to your source files"
  regardless of mode, while the `.guardlink/README.md` written by the same
  command says, under the default, that annotations do *not* go in source files.
  Step 2 now comes from the resolved mode.
- **D44** — `init` appended to an existing `.gitignore` but never created one, so
  every fresh project left `threat-dashboard.html` untracked *and* unignored
  despite `init` having just decided which four names it expects ignored.
- **D45** — `.guardlink/README.md` said "The complete reference is
  `.guardlink/GUARDLINK_REFERENCE.md`" while `init` wrote
  `docs/GUARDLINK_REFERENCE.md`. The next sentence is "Read it before inventing
  syntax". The path varies by `rootFiles`, not by annotation mode, and the two
  writers were keyed off different things; one helper now decides.
- **D43** — `guardlink status` printed "GuardLink Status: unknown" in every repo
  while `config.json` held the name. Nothing read it.

Verified by walking the whole first run in a fresh repo in default mode — `init`
→ read its output → read the README → follow it → annotate → `validate` →
`status` → `dashboard` → `artifacts` → `sync` — running every command the output
told us to run. Nothing contradicts itself and nothing points at a missing file.

**Merged `main` (PR #16) via #17.** One conflict here: the
`guardlink_annotate_apply` description, which both sides had rewritten. Composed
— ours lists the four rejection classes and the opt-in, main's adds that
`@entitles` is refused too and points at `guardlink_entitlement_propose`. Both
are true of the merged code (`HUMAN_ONLY` is `{accepts, entitles}`), checked
before the sentence was written.

## Type

- [x] Bug fix
- [ ] New feature
- [ ] Annotation spec change
- [ ] Documentation
- [x] CI / tooling — `tests/apply-annotations-validation.test.ts`. The D50
      command-string probe needed no change to cover main's new
      `guardlink entitle` / `entitle --propose` lines: it extracts commands from
      the generated docs rather than from a list, so it picked them up and
      checked them against the real CLI on its own

## Checklist

- [x] `npm run build` — tsc clean
- [x] `npm test` — 920 passing, 52 files (includes #17's and PR #16's suites)
- [x] `guardlink validate .` — passes; `--artifacts` gate exits 0
- [ ] `CHANGELOG.md` updated — **not done.** Deferred to #17, which owns the
      1.5.0 entry; these six defects should be folded into it rather than given
      their own section.

Also run: `npm run lint` (0 problems), `node scripts/query-set.mjs` (no drift on
both corpora), and the full first-run walk described above.

## Spec changes

**None.** Annotation syntax is unchanged by this PR, and no merge resolution here
touched the grammar. The `@actor` / `@entitles` spec change belongs to PR #16.

One MCP tool input schema gained an optional field —
`guardlink_annotate_apply.allow_undeclared_refs` (boolean, default `false`) — and
the result may now carry `warnings[]` alongside the existing `errors[]`. Neither
is part of the report `schema_version`, which is unchanged at `1.0.0`.

The `ThreatModel` and report-schema additions listed in #17's description
(`annotation_hash`, `coverage_percent` semantics, `annotated_files` /
`source_files` excluding `.gal`) arrive in this diff too, because it contains
#17 — they are described there.
