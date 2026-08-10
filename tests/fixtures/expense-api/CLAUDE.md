# ExpenseApi — Project Instructions

<!-- guardlink:begin -->
## GuardLink — Security Model

This project carries a [GuardLink](https://guardlink.bugb.io) threat model: security facts
recorded next to the code they describe — what each component is exposed to, what mitigates
it, how data flows between components — parsed into something you can query.

**Ask it instead of inferring security context from the source.** It already answers most of
what you would otherwise guess at, and it records decisions that are invisible in the code,
such as which risks a human has explicitly accepted.

| You are about to… | Ask |
|---|---|
| edit a file | `guardlink_context(file)` — annotations there, the assets they name, open exposures, controls the file must uphold |
| change a shared component | `guardlink_graph(from, depth, direction)` — blast radius across data flows and trust boundaries |
| act on a scanner finding | `guardlink_lookup("cwe:CWE-89")` — is this weakness class declared, and is it mitigated, accepted, open or confirmed |
| finish a change | `guardlink validate .` then `guardlink diff HEAD~1` — did I make this worse |

Without MCP, the same answers come from `guardlink status .`, `guardlink parse . --format json`
and `guardlink diff HEAD~1`.

**Full reference: `docs/GUARDLINK_REFERENCE.md`**

### Where annotations go

**Annotation mode: `external`. Annotations live in `.gal` sidecars under
`.guardlink/annotations/` — NOT in source files.**

The sidecar path mirrors the source path, with `.gal` appended:

| Source file | Its annotations |
|---|---|
| `src/auth/login.ts` | `.guardlink/annotations/src/auth/login.ts.gal` |
| `internal/db/query.go` | `.guardlink/annotations/internal/db/query.go.gal` |

Inside a `.gal`, group annotations under a `@source` block naming the real code location:

```
@source file:src/auth/login.ts line:42 symbol:login
@exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into SQL"
@mitigates #api against #sqli using #prepared-stmts -- "parameterized via pg"
```

`.gal` files hold **raw GAL lines** — no `#` prefix, no doc-block. Do
not edit source files to add annotations in this mode.

> Sidecars are found wherever the convention puts them, including for source files under
> `test/`, `vendor/` or `dist/` — directories the parser skips for *source* but not for
> annotations. `guardlink validate` warns if a `.gal` is off-convention, and still parses it.

### What you owe it back

**When you write or change code that touches security-relevant behavior, add the annotations in
the same change.** This includes: new endpoints, authentication/authorization logic, data validation, database queries, file I/O, external API calls, crypto operations, process spawning, user input handling, and configuration parsing. Do NOT annotate pure business logic, formatting utilities, UI components, or helper functions that never touch security boundaries.

### Key Rules

1. **Annotate new code.** When you add a function, endpoint, or module that handles user input, accesses data, crosses a trust boundary, or could fail in a security-relevant way — add `@exposes`, `@mitigates`, `@flows`, `@handles`, or at minimum `@comment` annotations. This is not optional.
2. **NEVER write `@accepts`.** That is a human-only governance decision. When you find a risk with no mitigation in code, write `@exposes` to document the risk + `@audit` to flag it for human review + `@comment` to suggest potential controls.
3. **Use `@confirmed` for verified exploits.** When a pentest, CXG scan, or manual reproduction proves a threat is exploitable, mark it with `@confirmed #threat on Asset [severity] -- "evidence"`. This is distinct from `@exposes` (theoretical) — `@confirmed` means real, verified, not a false positive. Include severity based on actual observed impact.
4. Do not delete or mangle existing annotations. Treat them as part of the code. Edit only when intentionally changing the threat model.
5. Definitions (`@asset`, `@threat`, `@control` with `(#id)`) live in `.guardlink/definitions.py`. Reuse existing `#id`s — never redefine. If you need a new asset or threat, add the definition there first, then reference it in source files.
6. Source files use relationship verbs only: `@mitigates`, `@exposes`, `@confirmed`, `@flows`, `@handles`, `@boundary`, `@comment`, `@validates`, `@audit`, `@owns`, `@assumes`, `@transfers`, `@feature`.
7. Write coupled annotation blocks that tell a complete story: risk + control (or audit) + data flow + context note. Never write a lone `@exposes` without follow-up.
8. Avoid `@shield` unless a human explicitly asks to hide code from AI — it creates blind spots.

### Workflow (while coding)

- **Opening a file:** `guardlink_context(file)` before you read far into it. Note which kind of empty an empty answer is — `scanned_without_annotations` means clean, `not_scanned` means the parser never read it. They are not the same.
- **Before writing:** skim `.guardlink/definitions.py` for the existing assets, threats and controls. Reuse those ids.
- **While writing:** annotate as you go, not as a pass afterward — in the file's `.gal` sidecar (see "Where annotations go").
- **After changing:** `guardlink diff HEAD~1` — the one command that answers "did I add exposure". Then `guardlink validate .` for syntax and dangling refs, and `guardlink status .` for coverage.
- **After annotating:** `guardlink sync` refreshes this block and `.guardlink/README.md` from the current model.

### Tools

- **MCP** (Claude Code, Cursor): `guardlink_context`, `guardlink_graph`, `guardlink_lookup`, `guardlink_diff`, `guardlink_validate`, `guardlink_status`, `guardlink_suggest`.
- **CLI** (always): `guardlink status .`, `guardlink parse .`, `guardlink validate .`, `guardlink diff HEAD~1`, `guardlink report .`.
- `guardlink_lookup` answers a fixed set of named forms and **refuses anything else rather than
  guessing** — send it a bad query to get the list. Beyond `asset`/`threat`/`control`, it reaches
  every relation the model holds: `owner of X`, `handles pii`, `assumptions for X`, `audits for X`,
  `validations for X`, `acceptances`, `transfers`, `comments for X`, `shields`, `cross-repo refs`,
  and `cwe:CWE-89` / `owasp:A03` for scanner findings.
- Reference matches report `matched_via: exact | alias | substring`. A substring match is a
  suggestion, not an identification; `ambiguous` with `candidates` means several records tied.

### Quick Syntax (common verbs)

```
@exposes App.API to #sqli [P0] cwe:CWE-89 -- "req.body.email concatenated into SQL"
@mitigates App.API against #sqli using #prepared-stmts -- "Parameterized queries via pg"
@audit App.API -- "Timing attack risk — needs human review to assess bcrypt constant-time comparison"
@flows User -> App.API via HTTPS -- "Login request path"
@boundary between #api and #db (#data-boundary) -- "App → DB trust change"
@handles pii on App.API -- "Processes email and session token"
@validates #prepared-stmts for App.API -- "sqlInjectionTest.ts ensures placeholders used"
@audit App.API -- "Token rotation logic needs crypto review"
@confirmed #sqli on App.API [critical] cwe:CWE-89 -- "Pentest verified: raw SQL injection via email param"
@feature "SSO Login" -- "Single sign-on authentication flow"
@owns security-team for App.API -- "Team responsible for reviews"
@comment -- "Rate limit: 100 req/15min via express-rate-limit"
```

<!-- guardlink:end -->
