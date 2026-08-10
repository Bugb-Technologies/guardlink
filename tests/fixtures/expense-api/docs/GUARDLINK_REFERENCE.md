# GuardLink — Annotation Reference

> Canonical reference for **expense-api**. All agent instruction files point here.
> Full specification: [docs/SPEC.md](https://github.com/Bugb-Technologies/guardlink/blob/main/docs/SPEC.md)

## Quick Reference

```
DEFINE   @asset <Component.Path> (#id) -- "description"
         @threat <Name> (#id) [severity] cwe:CWE-NNN -- "description"
         @control <Name> (#id) -- "description"

RELATE   @mitigates <Asset> against <#threat> using <#control> -- "how"
         @exposes <Asset> to <#threat> [severity] cwe:CWE-NNN -- "what's wrong"
         @accepts <#threat> on <Asset> -- "HUMAN-ONLY — AI agents must use @audit instead"
         @transfers <#threat> from <Source> to <Target> -- "who handles it"

FLOW     @flows <Source> -> <Target> via <mechanism> -- "details"
         @boundary <AssetA> | <AssetB> (#id) -- "trust boundary"
         @boundary between <AssetA> and <AssetB> (#id) -- "trust boundary"

LIFECYCLE
         @validates <#control> for <Asset> -- "test evidence"
         @audit <Asset> -- "what needs review"
         @owns <team-id> for <Asset> -- "responsible team"
         @handles <pii|phi|financial|secrets|internal|public> on <Asset>
         @assumes <Asset> -- "unverified assumption"

METADATA @feature "Feature Name" -- "tag code with a feature for filtering"

COMMENT  @comment -- "security-relevant developer note"

PROTECT  @shield -- "reason"
         @shield:begin -- "reason"   ... code ...   @shield:end
```

## Severity

`[P0]` = critical, `[P1]` = high, `[P2]` = medium, `[P3]` = low

## External References

Append after severity: `cwe:CWE-89`, `owasp:A03:2021`, `capec:CAPEC-66`, `attack:T1190`

## Rules

1. **Annotate as you code.** When you write or modify security-relevant code (endpoints, auth, data access, validation, I/O, crypto, process spawning), add annotations in the same change. This is required, not optional.
2. **Define once, reference everywhere.** `@asset`, `@threat`, `@control` with `(#id)` go in `.guardlink/definitions.py`. Source files use relationship verbs only (`@mitigates`, `@exposes`, etc.).
3. **Read definitions before adding.** Check for existing IDs first — avoid duplicates.
4. **Every `@exposes` needs a response.** Match with `@mitigates` (fix exists) or `@audit` (flag for human review). AI agents must NEVER write `@accepts` — that is a human-only governance decision. Use `@audit` instead.
5. **Use the full verb set.** `@flows` for data movement, `@handles` for data classification, `@boundary` for trust boundaries.

## When Writing Code

| Situation | Annotation |
|-----------|------------|
| Writing new endpoint/handler | `@exposes` + `@mitigates` (or `@audit`) + `@flows` + `@comment` — tell the complete story |
| New service/component | `@asset` in definitions, then reference in source |
| Security gap exists | `@exposes Asset to #threat` + `@audit Asset` |
| Risk with no fix yet | `@audit Asset` + `@comment` explaining potential controls. NEVER `@accepts`. |
| Implementing a fix | `@mitigates Asset against #threat using #control` |
| Processing sensitive data | `@handles pii on Asset` |
| Proprietary algorithm | `@shield:begin` ... `@shield:end` |
| Tagging code to a feature | `@feature "SSO Login" -- "Single sign-on flow"` |
| Unsure which annotation | `@comment -- "describe what you see"` |

## Commands

```bash
guardlink validate .          # Check for errors
guardlink report .            # Generate threat-model.md
guardlink status .            # Coverage summary
guardlink suggest <file>      # Get annotation suggestions
guardlink feature list        # List all @feature tags
guardlink feature show <name> # Show model for a specific feature
```

## MCP Tools

When connected via `.mcp.json`, use:
- `guardlink_parse` — parse annotations, return threat model
- `guardlink_lookup` — query threats, controls, exposures by ID
- `guardlink_suggest` — get annotation suggestions for a file
- `guardlink_validate` — check for syntax errors
- `guardlink_status` — coverage stats
