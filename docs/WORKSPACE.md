# Multi-Repo Workspaces

GuardLink workspaces link multiple service repos into a unified threat model.
Each repo maintains its own annotations, and `guardlink merge` combines them
into a single dashboard with cross-repo tag resolution, risk tracking, and
weekly diff summaries.

## Quick Start

```bash
# Link three sibling repos into a workspace
guardlink link-project ./payment-svc ./auth-lib ./api-gateway \
  --workspace acme-platform \
  --registry github.com/acme

# Each repo now has .guardlink/workspace.yaml
# Agent instruction files updated with cross-repo context

# Generate per-repo reports
cd payment-svc && guardlink report --format json -o payment-svc.json
cd ../auth-lib && guardlink report --format json -o auth-lib.json
cd ../api-gateway && guardlink report --format json -o api-gateway.json

# Merge into unified dashboard
guardlink merge payment-svc.json auth-lib.json api-gateway.json \
  --workspace acme-platform \
  --json merged.json \
  -o dashboard.html
```

## Concepts

**Workspace**: A named collection of repos that share a threat model boundary.
Each repo has its own annotations, but tags can reference definitions in sibling
repos using dot-prefix notation.

**Tag prefixes**: In a workspace, tag IDs use the repo name as a prefix:
`#payment-svc.refund-handler`, `#auth-lib.token-verify`. This prevents
collisions and makes ownership clear.

**External refs**: When an annotation in repo A references a tag defined in
repo B (e.g. `@mitigates #auth-lib.token-verify against ...`), that's an
external ref. These are detected during parsing and show as "external refs"
in `guardlink validate`. They resolve during `guardlink merge`.

**Merge**: Combines N per-repo report JSONs into a single `MergedReport` with
deduplicated definitions, a unified tag registry, cross-repo reference
resolution, and aggregated stats.

## workspace.yaml

Each linked repo gets `.guardlink/workspace.yaml`:

```yaml
workspace: acme-platform
this_repo: payment-svc
repos:
  - name: payment-svc
    registry: github.com/acme/payment-svc
  - name: auth-lib
    registry: github.com/acme/auth-lib
  - name: api-gateway
    registry: github.com/acme/api-gateway
```

| Field | Required | Description |
|-------|----------|-------------|
| `workspace` | yes | Workspace name, shared across all repos |
| `this_repo` | yes | This repo's name (differs per repo) |
| `repos` | yes | All repos in the workspace |
| `repos[].name` | yes | Short name, used as tag prefix |
| `repos[].registry` | no | Remote URL for linking/discovery |

## Commands

### link-project — Fresh setup

Links multiple repos into a new workspace. Auto-initializes repos that haven't
run `guardlink init` yet.

```bash
guardlink link-project ./svc-a ./svc-b ./svc-c \
  --workspace my-platform \
  --registry github.com/my-org
```

### link-project --add — Add a repo

Adds a new repo to an existing workspace. Reads workspace config from an
existing member, adds the new repo, and updates all sibling repos it can
find on disk.

```bash
guardlink link-project --add ./new-service --from ./svc-a
```

### link-project --remove — Remove a repo

Removes a repo from the workspace. Updates all sibling repos found on disk.

```bash
guardlink link-project --remove old-service --from ./svc-a
```

### report --format json — Per-repo report

Generates a report JSON with metadata (repo name, workspace, commit SHA,
schema version). This is the input for `guardlink merge`.

```bash
guardlink report --format json -o guardlink-report.json
```

### merge — Combine reports

Merges N report JSONs into a unified threat model.

```bash
guardlink merge repo-a.json repo-b.json repo-c.json \
  --workspace acme-platform \
  --json merged.json \
  -o dashboard.html \
  --diff-against last-week.json
```

| Flag | Description |
|------|-------------|
| `--json <file>` | Write merged report JSON |
| `-o <file>` | Write dashboard HTML (default: `workspace-dashboard.html`) |
| `--diff-against <file>` | Compare against previous merge, write weekly diff |
| `-w, --workspace <name>` | Workspace name (auto-detected from reports if unset) |
| `--summary-only` | Print text summary only, skip dashboard |

### TUI commands

```
/workspace             Show workspace config, sibling repos, registries
/link <repos...>       Link repos (same as CLI link-project)
/link --add <repo>     Add repo to workspace (uses current dir as --from)
/link --remove <name>  Remove repo from workspace
/merge <files...>      Merge reports (supports --json, --diff-against, -o)
```

### MCP tool

`guardlink_workspace_info` returns workspace context for AI agents: workspace
name, this repo's identity, sibling repos with tag prefixes, and cross-repo
annotation rules. Returns null fields if not in a workspace.

## Writing Cross-Repo Annotations

In a workspace, annotations can reference sibling repos by tag prefix:

```typescript
// In payment-svc:
// @asset PaymentService.RefundHandler (#payment-svc.refund) -- "Processes refund requests"
// @flows #request from #api-gateway.router to #payment-svc.refund via gRPC
// @mitigates #payment-svc.refund against #auth-lib.token-replay using #request-signing
```

Rules:
- Use `#<repo-name>.<component>` for all tag IDs
- Reference sibling assets/threats/controls by their full prefixed tag
- Don't redefine assets that belong to another repo — reference by tag
- External refs show as warnings in local `guardlink validate` but resolve
  during `guardlink merge`
- `@flows` across repos are encouraged — they document service boundaries

## Merge Behavior

**Tag registry**: When the same tag is defined in multiple repos, ownership is
determined by prefix match (`#payment-svc.refund` → owned by `payment-svc`).
If no prefix match, first definition wins. Duplicates produce warnings.

**Reference resolution**: All tag references in relationship annotations
(mitigates, exposes, flows, etc.) are checked against the unified registry.
Unresolved refs are listed in the merge output with inferred target repo.

**Deduplication**: Definition annotations (asset, threat, control) are deduped
by tag ID — first definition wins. Relationship annotations are kept from all
repos (the same relationship stated in two repos is meaningful).

**Stale detection**: Reports older than 7 days (configurable) get a warning.
Missing repos (in workspace but no report file) are flagged.

**Severity**: The merged report computes unmitigated exposures across the full
workspace, catching cases where repo A exposes a threat that repo B was
supposed to mitigate.

## CI Integration

See `examples/ci/` for GitHub Actions workflows:

- **`per-repo-report.yml`** — runs in each service repo. Validates on PRs,
  generates + uploads report JSON on push to main.
- **`workspace-merge.yml`** — runs weekly in a central repo. Downloads all
  report artifacts, merges, generates dashboard, computes weekly diff.

See `examples/ci/README.md` for full setup instructions.

## Weekly Workflow

A typical weekly cycle:

1. Engineers push code with annotations → per-repo CI validates + generates reports
2. Monday: workspace merge workflow runs → unified dashboard + weekly diff
3. Security lead reviews dashboard: new unmitigated exposures, removed mitigations,
   unresolved cross-repo refs
4. Team addresses gaps: add missing mitigations, fix dangling refs, update annotations
