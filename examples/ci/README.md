# GuardLink CI Templates

Two GitHub Actions workflows for multi-repo workspace threat modeling.

## Quick Start

### 1. Per-repo: `per-repo-report.yml`

Copy to **each service repo** as `.github/workflows/guardlink.yml`.

**On PRs:** validates annotations, posts threat model diff as comment, uploads SARIF.
**On push to main:** generates `guardlink-report.json` and uploads as artifact.

No configuration needed — works out of the box.

### 2. Workspace merge: `workspace-merge.yml`

Copy to a **central repo** (e.g. `infra`, `security`, or `threat-model`) as
`.github/workflows/guardlink-merge.yml`.

**Runs weekly** (Monday 9am UTC) or on manual dispatch.
Downloads report artifacts from all workspace repos, merges them, generates a
unified dashboard, and computes a week-over-week diff.

**Setup:**

1. Create a GitHub PAT (classic) with `actions:read` scope on all workspace repos.
   Store it as the `GUARDLINK_PAT` secret in the central repo.

2. Edit the `env` block at the top of the workflow:

```yaml
env:
  REPOS: "your-org/payment-service your-org/auth-service your-org/api-gateway"
  WORKSPACE_NAME: "your-workspace"
```

3. (Optional) Enable GitHub Pages deployment by uncommenting the Pages block.

4. (Optional) Add a `SLACK_WEBHOOK_URL` secret for weekly Slack summaries.

## How It Works

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│ payment-svc │  │ auth-svc    │  │ api-gateway │
│             │  │             │  │             │
│ push → main │  │ push → main │  │ push → main │
│   ↓         │  │   ↓         │  │   ↓         │
│ guardlink   │  │ guardlink   │  │ guardlink   │
│ report JSON │  │ report JSON │  │ report JSON │
│   ↓         │  │   ↓         │  │   ↓         │
│ artifact 📦 │  │ artifact 📦 │  │ artifact 📦 │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │                │                │
       └────────┬───────┘────────────────┘
                │
        ┌───────▼────────┐
        │ Central repo   │
        │ (weekly cron)  │
        │                │
        │ download all   │
        │ artifacts      │
        │   ↓            │
        │ guardlink      │
        │ merge          │
        │   ↓            │
        │ dashboard.html │
        │ merged.json    │
        │ weekly-diff.md │
        └────────────────┘
```

## Artifact Retention

Per-repo reports are retained for **30 days** (configurable via `retention-days`).
Merged results are retained for **90 days**. The merge workflow commits
`previous/workspace-report.json` to enable week-over-week diffs.

