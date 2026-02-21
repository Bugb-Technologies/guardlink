# Guardlink — Project Instructions

<!-- guardlink:begin -->
## GuardLink — Security Annotations (Required)

This project uses [GuardLink](https://guardlink.bugb.io) annotations in source code comments.
**Full reference: `docs/GUARDLINK_REFERENCE.md`**

### Key Rules

1. Definitions (`@asset`, `@threat`, `@control` with `#id`) go in `.guardlink/definitions.ts` — read it before adding new ones.
2. Source files use relationship verbs only: `@mitigates`, `@exposes`, `@accepts`, `@flows`, `@handles`, `@boundary`, `@comment`.
3. Every `@exposes` needs a matching `@mitigates` or `@accepts`.
4. Always add at least `@comment` on security-relevant code.
5. Run `guardlink validate .` after making changes.

### MCP Tools Available

Use `guardlink_lookup` to check existing definitions. Use `guardlink_validate` after annotating. Use `guardlink_suggest <file>` for recommendations.

### Quick Syntax

```
@exposes Asset to #threat [P0] cwe:CWE-89 -- "description"
@mitigates Asset against #threat using #control -- "how"
@comment -- "security-relevant note"
```

<!-- guardlink:end -->
