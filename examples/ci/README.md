# Multi-Repo CI Setup

Automate threat model reports across your workspace with two GitHub Actions workflows.

**What you get:** Every push to main generates a per-repo report. Every Monday (or on demand), a central workflow merges all reports into a unified dashboard with a week-over-week diff.

## How It Works

```
  service repos (each runs per-repo workflow)         central repo (runs weekly merge)
 ┌──────────────────────────────────────────┐       ┌────────────────────────────────┐
 │                                          │       │                                │
 │  push → main                             │       │  Monday 9am (cron)             │
 │    ↓                                     │       │    ↓                            │
 │  guardlink validate                      │       │  download all report artifacts  │
 │  guardlink report --format json          │       │    ↓                            │
 │    ↓                                     │       │  guardlink merge *.json         │
 │  upload artifact: guardlink-report.json  │ ────► │    ↓                            │
 │                                          │       │  dashboard.html + weekly diff   │
 │  (PRs also get: diff comment + SARIF)    │       │  + merged.json (for next week)  │
 └──────────────────────────────────────────┘       └────────────────────────────────┘
```

## Prerequisites

Before starting, make sure you've linked your repos locally:

```bash
guardlink link-project ./svc-a ./svc-b ./svc-c --workspace my-platform
```

This creates `.guardlink/workspace.yaml` in each repo. See [docs/WORKSPACE.md](../../docs/WORKSPACE.md) for details.

---

## Step 1: Add the Per-Repo Workflow to Each Service Repo

Copy [`per-repo-report.yml`](per-repo-report.yml) into each service repo:

```
your-service-repo/
└── .github/
    └── workflows/
        └── guardlink.yml    ← copy per-repo-report.yml here
```

That's it — no configuration needed. On every push to main, it will:
- Validate annotations
- Generate `guardlink-report.json`
- Upload it as a GitHub artifact (retained 30 days)

On PRs, it will:
- Run validation
- Post a threat model diff as a PR comment
- Upload SARIF to GitHub's Security tab

Commit and push to each service repo.

## Step 2: Create the Central Merge Repo

Pick or create a repo that will host the merged dashboard. This can be an existing `infra`, `security`, or `platform` repo — or a dedicated `threat-model` repo.

Copy [`workspace-merge.yml`](workspace-merge.yml) into it:

```
central-repo/
└── .github/
    └── workflows/
        └── guardlink-merge.yml    ← copy workspace-merge.yml here
```

## Step 3: Configure the Merge Workflow

Open `guardlink-merge.yml` and edit the `env` block at the top:

```yaml
env:
  REPOS: "your-org/payment-service your-org/auth-service your-org/api-gateway"
  WORKSPACE_NAME: "your-workspace"
  ARTIFACT_NAME: "guardlink-report"
```

- **`REPOS`** — space-separated list of `org/repo` names. These must match the repos where you added the per-repo workflow in Step 1.
- **`WORKSPACE_NAME`** — your workspace name (same as in `guardlink link-project --workspace`).
- **`ARTIFACT_NAME`** — leave as `guardlink-report` unless you changed it in the per-repo workflow.

## Step 4: Create a GitHub PAT

The merge workflow needs to download artifacts from your service repos.

1. Go to **GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)**
2. Create a new token with the **`actions:read`** scope
3. Make sure it has access to all repos listed in `REPOS`
4. In the central repo, go to **Settings → Secrets → Actions** and add it as **`GUARDLINK_PAT`**

> **Tip:** For GitHub Enterprise or fine-grained tokens, you need "Actions: Read" permission on each service repo.

## Step 5: Push and Verify

1. Push the per-repo workflow to each service repo. Wait for the first push-to-main run to complete — check that a `guardlink-report` artifact appears under Actions → your workflow run → Artifacts.

2. Push the merge workflow to the central repo. Trigger it manually: **Actions → GuardLink Workspace Merge → Run workflow**.

3. Check the output: the workflow should download all repo artifacts, run the merge, and upload `workspace-dashboard.html`, `workspace-report.json`, and a weekly diff as artifacts.

---

## Optional: GitHub Pages

To auto-publish the dashboard to GitHub Pages, uncomment the Pages deployment section in `workspace-merge.yml`. The dashboard will be available at `https://your-org.github.io/central-repo/`.

Make sure GitHub Pages is enabled in the central repo's settings (Settings → Pages → Source: GitHub Actions).

## Optional: Slack Notifications

To get a weekly summary in Slack:

1. Create a [Slack Incoming Webhook](https://api.slack.com/messaging/webhooks)
2. Add it as `SLACK_WEBHOOK_URL` secret in the central repo
3. The workflow's Slack step is already configured — it sends the weekly diff summary

## Optional: Adjust the Schedule

The default schedule is Monday at 9am UTC. Change the cron expression in the merge workflow:

```yaml
on:
  schedule:
    - cron: '0 9 * * 1'   # Monday 9am UTC
    # - cron: '0 14 * * 5' # Friday 2pm UTC (example)
```

---

## What the Merge Output Looks Like

Each Monday, the merge produces three files:

**`workspace-dashboard.html`** — Interactive HTML dashboard showing all assets, threats, mitigations, and exposures across the entire workspace. Cross-repo data flows visible. Open in any browser.

**`workspace-report.json`** — Machine-readable merged report. This becomes `--diff-against` input for next week's run. Contains the tag registry, unresolved cross-repo refs, per-repo statuses, and aggregated totals.

**`workspace-merge-weekly-diff.md`** — Human-readable summary of what changed:

```
# acme-platform — Weekly Threat Model Changes

**Period:** 2026-02-17 → 2026-02-24
**Risk trend:** 🟢 decreased

## Changes
- +5 new mitigation(s)
- +3 new exposure(s)
- -1 removed mitigation(s) ⚠️

## Risk
- 🟢 2 exposure(s) now mitigated

## Repos
- 📝 payment-service (updated)
- 📝 api-gateway (updated)
```

---

## Artifact Retention

- Per-repo reports: **30 days** (configurable via `retention-days` in per-repo workflow)
- Merged results: **90 days**
- The merge workflow commits `previous/workspace-report.json` to enable week-over-week diffs

## Troubleshooting

**"No artifacts found for repo X"** — The per-repo workflow hasn't run on that repo yet, or the artifact expired (>30 days). Push a commit to main on that repo to trigger a fresh report.

**"guardlink-report artifact not found"** — Check that the artifact name in the per-repo workflow matches `ARTIFACT_NAME` in the merge workflow. Default is `guardlink-report`.

**PAT permission errors** — Make sure the token has `actions:read` scope and access to all listed repos. For fine-grained tokens, each repo needs explicit "Actions: Read" permission.

**Empty dashboard** — Check the merge workflow logs. Look for "repos loaded" count — if 0, none of the artifact downloads succeeded. Verify repo names in `REPOS` match exactly (case-sensitive, include org prefix).
