# Multi-repo workspaces

This guide now lives at
**<https://docs.bugb.io/guardlink/guides/link-repositories-into-a-workspace/>**.

Linking repositories, what `workspace.yaml` holds, writing cross-repo `#repo.tag`
references, merging per-repo reports, reading the resolved and unresolved
counters, and the CI shape the whole thing is built for.

It moved because the documentation site is generated against a released package
and its commands are verified by running them, which a hand-written file in this
repository cannot promise. Keeping both meant one of them was always wrong.

| Page | |
| --- | --- |
| Link repositories into a workspace | <https://docs.bugb.io/guardlink/guides/link-repositories-into-a-workspace/> |
| `guardlink link-project` and `guardlink merge` | <https://docs.bugb.io/guardlink/reference/cli/reports/> |
| The threat model as an artifact | <https://docs.bugb.io/guardlink/concepts/the-threat-model-artifact/> |

The multi-repo CI workflows stay in this repository, because they ship as files
you copy. See [`examples/ci/`](../examples/ci/).
