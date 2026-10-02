What the code lets each agent and principal do — `@agents` and `@reaches` (can invoke), `@effects` (what the
code does) and `@gates` (who decides first) — set against what a human approved with `@entitles`. An effect is
tied to an actor only when both are written in one doc-block, bound to the same code; reaching an effect
through calls across handlers takes a call graph and is not inferred here.

| Measure | Count |
|---------|-------|
| Agents (`@agents`) | 1 |
| Other principals (`@reaches`) | 1 |
| Reaches | 7 |
| **Unentitled reaches** | **5** |
| Effects | 9 (7 mutating) |
| **Ungated mutations** | **5** |
| Gates | 2 |
| Egress from a reach | 0 |
| Injection-to-tool routes | 0 |

### #support-agent — AI agent

LLM agent; acts for the signed-in customer

6 capabilities, 4 unentitled, 3 ungated mutations.

| Capability | On | As | Entitled | What it leads to | Location |
|------------|----|----|----------|------------------|----------|
| `lookup-order` | #tool-surface | #agent-session | yes | read #orders-db | src/tools.ts:5 |
| `run-sql` | #tool-surface | — | **no** | **delete (ungated)** #orders-db, **write (ungated)** #users-db | src/tools.ts:14 |
| `issue-refund` | #tool-surface | — | yes | spend (gated by #support-human) #payments | src/tools.ts:25 |
| `search-kb` | #tool-surface | — | **no** | read #kb | src/tools.ts:34 |
| `fetch-url` | #tool-surface | — | **no** | — | src/tools.ts:43 |
| `mcp-files` | #tool-surface | — | **no** | **write (ungated)** #host-fs | src/tools.ts:51 |

### #ci-runner — principal

Release pipeline

1 capability, 1 unentitled, 1 ungated mutation.

| Capability | On | As | Entitled | What it leads to | Location |
|------------|----|----|----------|------------------|----------|
| `publish-package` | #registry | — | **no** | **write (ungated)** #registry | src/billing.ts:12 |

### Reach Map

Rows are actors, columns the assets they reach. A capability is marked ✗ when no cited `@entitles` covers it;
an effect is marked ungated when it mutates and no `@gates` stands in front of it.

| Actor | #tool-surface | #orders-db | #users-db | #payments | #kb | #host-fs | #registry | #outbox |
|-------|---|---|---|---|---|---|---|---|
| #support-agent (agent) | `lookup-order` ✓<br>`run-sql` ✗<br>`issue-refund` ✓<br>`search-kb` ✗<br>`fetch-url` ✗<br>`mcp-files` ✗ | read<br>**delete (ungated)** | **write (ungated)** | spend (gated by #support-human) | read | **write (ungated)** | · | · |
| #ci-runner | · | · | · | · | · | · | `publish-package` ✗<br>**write (ungated)** | · |
| _not tied to a reach_ | · | · | · | **spend (ungated)** | · | · | · | notify (gated by #support-human) |

### Unentitled Reaches

Capabilities the code hands out that no cited `@entitles` covers: can minus may. For an agent this is the
Excessive Agency list. Only a human closes one, by accepting an entitlement proposal (`guardlink entitle --propose`).

| Actor | Capability | On | Why nothing covers it | Location |
|-------|------------|----|-----------------------|----------|
| #ci-runner | `publish-package` | #registry | no `@entitles` for this actor and capability | src/billing.ts:12 |
| #support-agent (agent) | `run-sql` | #tool-surface | no `@entitles` for this actor and capability | src/tools.ts:14 |
| #support-agent (agent) | `search-kb` | #tool-surface | the entitlement is for another asset (src/tools.ts:36) | src/tools.ts:34 |
| #support-agent (agent) | `fetch-url` | #tool-surface | the entitlement cites no authorization code, so it covers nothing (src/tools.ts:44) | src/tools.ts:43 |
| #support-agent (agent) | `mcp-files` | #tool-surface | no `@entitles` for this actor and capability | src/tools.ts:51 |

### Ungated Mutations

Effects other than `read` with no `@gates` in front of them. A gate suppresses nothing; its absence means
nothing in the model says a person or a check decides before the effect lands.

| Effect | Asset | As | Reached through | Location |
|--------|-------|----|-----------------|----------|
| spend | #payments | #billing-sa | _no reach on this code_; #support-human for `issue-refund` does not cover it: the gate is for one capability, and no reach on this code says which capability gets here | src/billing.ts:5 |
| write | #registry | — | #ci-runner `publish-package` | src/billing.ts:13 |
| delete | #orders-db | — | #support-agent `run-sql` | src/tools.ts:15 |
| write | #users-db | — | #support-agent `run-sql` | src/tools.ts:16 |
| write | #host-fs | — | #support-agent `mcp-files` | src/tools.ts:52 |

### Gates

| Asset | Approver | For | Stands in front of | Location |
|-------|----------|-----|--------------------|----------|
| #payments | #support-human | `issue-refund` | spend on #payments (src/tools.ts:26) | src/approval.ts:5 |
| #outbox | #support-human | every capability | notify on #outbox (src/approval.ts:13) | src/approval.ts:12 |

### Effects Not Tied to a Reach

No `@agents` or `@reaches` is bound to the same code, so which principal reaches these
is a call-graph question. They still count as ungated mutations when nothing gates them.

- notify (gated by #support-human) on #outbox (src/approval.ts:13)
- **spend (ungated)** on #payments (src/billing.ts:5)

### OWASP Top 10 for LLM Applications

Each row is a target for review or test, not a finding the model has proved.

| Item | What GuardLink looks for | Found |
|------|--------------------------|-------|
| LLM06 Excessive Agency | Unentitled @agents (functionality), an effect running as a broader identity than the agent presents (permissions), and mutations with no @gates (autonomy). | 7 |
| LLM01 Prompt Injection | Input from outside the model that @flows into an agent which can reach an ungated mutation. | 0 |
| LLM05 Improper Output Handling | A write, delete, execute or notify bound to the same code as the agent's tool, so model output reaches it directly. | 3 |

**LLM06 Excessive Agency**

- _functionality_ — #support-agent: can run-sql on #tool-surface and no cited @entitles covers it (src/tools.ts:14)
- _functionality_ — #support-agent: can search-kb on #tool-surface and no cited @entitles covers it (src/tools.ts:34)
- _functionality_ — #support-agent: can fetch-url on #tool-surface and no cited @entitles covers it (src/tools.ts:43)
- _functionality_ — #support-agent: can mcp-files on #tool-surface and no cited @entitles covers it (src/tools.ts:51)
- _autonomy_ — #support-agent: delete on #orders-db through run-sql, with no @gates in front of it (src/tools.ts:15)
- _autonomy_ — #support-agent: write on #users-db through run-sql, with no @gates in front of it (src/tools.ts:16)
- _autonomy_ — #support-agent: write on #host-fs through mcp-files, with no @gates in front of it (src/tools.ts:52)

**LLM05 Improper Output Handling**

- _model output into an effect_ — #support-agent: run-sql hands model-written arguments to a delete on #orders-db in the same code (src/tools.ts:15)
- _model output into an effect_ — #support-agent: run-sql hands model-written arguments to a write on #users-db in the same code (src/tools.ts:16)
- _model output into an effect_ — #support-agent: mcp-files hands model-written arguments to a write on #host-fs in the same code (src/tools.ts:52)

### Open Exposures on Reached Assets

| Severity | Asset | Threat | Description | Location |
|----------|-------|--------|-------------|----------|
| high | #users-db | #excessive-agency | Reachable from the agent's tool surface, nothing approves the write | src/tools.ts:17 |

