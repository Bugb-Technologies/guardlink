# GuardLink — Security Annotations for Code

**Version:** 1.0.0  
**Status:** Release  
**License:** CC-BY-4.0 (specification text), MIT (reference implementations and conformance tests)  
**Authors:** BugB Technologies  
**Heritage:** Builds on the original [ThreatSpec project](https://github.com/threatspec/threatspec) (2015–2020)

---

## Abstract

GuardLink is a language-agnostic specification for embedding security intent directly in source code through structured annotations in comments. Annotations describe what a developer knows about the security properties of their code: what threats exist, what controls are in place, what risks have been accepted, and how data flows between components.

GuardLink extends the original ThreatSpec specification (dormant since 2020) with richer annotation types covering data classification, trust boundaries, ownership, assumptions, validation, and AI interaction controls. It is designed to be parsed by automated tools, consumed by CI/CD pipelines, and maintained by both humans and AI coding assistants.

---

## 1. Design Principles

**1.1. Annotations are English verbs.** Every annotation reads as a natural-language statement. A developer encountering `@mitigates AuthService against SQL_Injection` understands it without documentation. Branded prefixes, product names, and abbreviations are avoided in the core syntax.

**1.2. Annotations live in comments.** GuardLink annotations are embedded in source code comments using the host language's comment syntax. They travel with the code through version control, appear in pull request diffs, and are reviewed alongside the code they describe.

**1.3. Annotations are structured data.** While readable as English, every annotation has a deterministic grammar that can be parsed by regex into typed data structures. Ambiguous or free-form syntax is avoided.

**1.4. Annotations capture intent, not implementation.** An `@exposes` annotation says "this code is vulnerable to X" — it does not describe how the vulnerability works. A `@mitigates` annotation says "this code defends against X" — it does not duplicate the implementation. The annotation is a pointer from code to the threat model.

**1.5. Annotations are incremental.** A codebase does not need 100% annotation coverage to be useful. A single `@exposes` annotation on a critical endpoint is valuable. Tools should work with partial annotation and measure coverage over time.

**1.6. Annotations are tool-agnostic.** GuardLink defines the syntax and semantics of annotations. It does not mandate specific tools, CI/CD platforms, or security scanners. Any conforming parser can extract annotations; any conforming tool can consume the resulting threat model.

---

## 2. Syntax Overview

### 2.1. General Form

All GuardLink annotations follow this pattern:

```
<comment-prefix> @<verb> <arguments> [<qualifiers>] [<external-refs>] [-- "<description>"]
```

Where:
- `<comment-prefix>` is the host language's comment syntax (`//`, `#`, `--`, `/*`, etc.)
- `@<verb>` is one of the defined annotation verbs (§3)
- `<arguments>` are verb-specific, positional (§3)
- `<qualifiers>` are optional metadata in brackets: severity (§2.5) or classification (§2.6)
- `<external-refs>` are optional references to external taxonomies (§2.8)
- `-- "<description>"` is an optional human-readable explanation (§2.7)

### 2.2. Component Paths

Components are referenced using dot-separated paths that mirror the system's logical architecture:

```
App.Auth.Login
Backend.API.Users
Infrastructure.Database.Primary
```

Paths are case-sensitive. Each segment should be a meaningful name (PascalCase recommended). Depth is unlimited but 2-4 segments is typical.

A component path does NOT need to correspond to a file path or module structure. It represents the logical architecture as the team understands it.

### 2.3. Identifiers

Annotations can define or reference short identifiers using `#id` syntax:

```
// Define an identifier:
// @threat SQL_Injection (#sqli) -- "Unsanitized input reaches query builder"

// Reference it elsewhere:
// @mitigates App.Auth against #sqli using #prepared-stmts
```

Identifiers:
- Are prefixed with `#` when referenced
- Are wrapped in `(#id)` when defined
- Contain only `[a-zA-Z0-9_-]`
- Are case-sensitive
- Must be unique within a project

**Scope:** Identifiers are project-wide. A project is defined as the scope of a single parse operation, typically corresponding to a single git repository. An identifier defined in any file within the project can be referenced from any other file within the same project. Duplicate definitions of the same identifier within a project are a parse error.

### 2.4. Inline References

When an annotation references a threat or control by name rather than identifier, the full name is used:

```
// @mitigates App.Auth against SQL_Injection using Parameterized_Queries
```

Underscores in names serve as word separators for readability. Tools must normalize names for matching using the algorithm defined in §2.10.

### 2.5. Severity Qualifiers

Severity is expressed in square brackets after the target:

```
// @exposes App.API to #idor [critical]
// @threat Broken_Access_Control (#bac) [P0]
```

Accepted values (case-insensitive):

| Qualifier | Meaning |
|-----------|---------|
| `[P0]` or `[critical]` | Exploitable, severe impact, fix immediately |
| `[P1]` or `[high]` | Exploitable, significant impact |
| `[P2]` or `[medium]` | Exploitable with conditions, moderate impact |
| `[P3]` or `[low]` | Minor impact or difficult to exploit |

P-level and word-level qualifiers are interchangeable. Tools must accept both forms and may normalize to either.

### 2.6. Classification Qualifiers

The `@handles` annotation uses data classification qualifiers:

```
// @handles pii on App.Users.Profile
// @handles secrets on App.Config.Vault
```

Standard classifications:

| Qualifier | Meaning |
|-----------|---------|
| `pii` | Personally identifiable information |
| `phi` | Protected health information |
| `financial` | Financial data, payment info, account numbers |
| `secrets` | API keys, tokens, credentials, passwords |
| `internal` | Non-public business data |
| `public` | Data intended for public access |

Implementations may define additional classifications.

### 2.7. Descriptions

An optional description follows `--` and is enclosed in double quotes:

```
// @mitigates App.Auth against #sqli using #prepared-stmts -- "All DB access uses parameterized queries via sqlx"
```

Descriptions:
- Are always enclosed in `"double quotes"`
- May contain any UTF-8 text, subject to the escaping rules in §2.11
- Should be concise (one sentence recommended, two maximum)
- Are metadata for humans and reports; tools should not parse their content semantically

Multi-line descriptions use continuation lines starting with `--`:

```
// @threat Session_Hijacking (#session-hijack) [P1]
// -- "Attacker steals session token via XSS or network interception"
// -- "Particularly dangerous on shared networks"
```

### 2.8. External Reference Qualifiers

Annotations may reference entries in external security taxonomies using `prefix:ID` syntax. External references appear after severity qualifiers (if present) and before the description:

```
// @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 owasp:A03:2021 -- "Unsanitized input"
// @exposes App.API to #idor [P1] cwe:CWE-639 -- "No ownership check"
// @threat Exploitation_of_Public_App (#exploit-public) attack:T1190 -- "Internet-facing service"
```

Recognized prefixes:

| Prefix | Taxonomy | Example |
|--------|----------|---------|
| `cwe:` | MITRE Common Weakness Enumeration | `cwe:CWE-89`, `cwe:CWE-639` |
| `owasp:` | OWASP Top 10 (year-qualified) | `owasp:A03:2021`, `owasp:A01:2021` |
| `attack:` | MITRE ATT&CK Technique | `attack:T1190`, `attack:T1059.001` |
| `capec:` | MITRE CAPEC Attack Pattern | `capec:CAPEC-66` |

External references are optional metadata. They do not change the semantics of the annotation. Tools should preserve and propagate them into output formats (SARIF, JSON, reports) but must not require them for correct parsing.

Multiple external references may appear on a single annotation, separated by whitespace:

```
// @threat Injection (#inj) [P0] cwe:CWE-89 cwe:CWE-78 owasp:A03:2021 -- "Multiple injection vectors"
```

Implementations may support additional prefixes beyond those listed here. Unrecognized prefixes should be preserved as opaque strings rather than rejected.

### 2.9. Comment Prefix Handling

Parsers must strip the host language's comment prefix before matching annotations. Supported comment styles:

| Style | Languages |
|-------|-----------|
| `//` | C, C++, C#, Java, JavaScript, TypeScript, Go, Rust, Swift, Kotlin, Scala, Dart |
| `#` | Python, Ruby, Bash, Perl, YAML, Terraform, R, Elixir, Nim |
| `--` | Haskell, Lua, SQL, Ada, VHDL |
| `/* */` | C, C++, Java, CSS (block comments) |
| `(* *)` | OCaml, Pascal |
| `""" """` | Python (docstrings) |
| `%` | LaTeX, Erlang, MATLAB |
| `;` | Lisp, Clojure, Assembly, INI files |
| `<!-- -->` | HTML, XML, SVG |
| `{- -}` | Haskell (block comments) |
| `REM` | Batch files |
| `'` | VBA, VB.NET |

Within block comments (`/* */`, `<!-- -->`, etc.), parsers should check each line independently after stripping the comment delimiters and any leading `*` characters (common in Javadoc-style blocks).

### 2.10. Name Normalization

When annotations reference threats or controls by name (rather than by `#id`), tools must normalize names for matching. The canonical normalization algorithm is:

1. Apply Unicode NFKC normalization
2. Convert to lowercase
3. Replace all whitespace characters (space, tab, non-breaking space) with underscore (`_`)
4. Replace all hyphens (`-`) with underscore (`_`)
5. Collapse consecutive underscores into a single underscore
6. Strip leading and trailing underscores

Under this algorithm, the following names all resolve to the same canonical form `sql_injection`:

```
SQL_Injection
sql-injection
SQL INJECTION
Sql_Injection
sql__injection
SQL-Injection
```

Tools must use canonical forms for matching and deduplication. Tools may display original (non-normalized) names in reports and UI for readability, but all comparisons, lookups, and graph construction must use the canonical form.

### 2.11. Description Escaping

Description strings are enclosed in double quotes. The following escape sequences are recognized within descriptions:

| Sequence | Meaning |
|----------|---------|
| `\"` | Literal double quote character |
| `\\` | Literal backslash character |

No other escape sequences are defined. All other characters (including newlines within multi-line continuations, unicode characters, and single quotes) are literal.

Examples:

```
// @threat XSS (#xss) -- "Attacker injects \"<script>\" tags via user input"
// @control Escaping (#escape) -- "Uses OWASP encoder \\ context-aware output encoding"
```

Parsers must unescape `\"` and `\\` when extracting description text. Writers must escape `"` and `\` when generating annotations programmatically.

---

## 3. Annotation Reference

### 3.1. Definition Annotations

These annotations declare the building blocks of a threat model.

#### `@asset` — Declare a Component

```
@asset <path> [(#id)] [-- "<description>"]
```

Declares a component, service, module, or resource in the system architecture. Assets are the nodes of the threat model graph.

```python
# @asset App.Auth.Login (#login) -- "User-facing authentication endpoint"
# @asset Infrastructure.Database.Primary (#primary-db) -- "PostgreSQL 15, stores all user data"
# @asset External.PaymentGateway (#stripe) -- "Stripe API integration"
```

#### `@threat` — Declare a Threat

```
@threat <n> [(#id)] [<severity>] [<external-refs>] [-- "<description>"]
```

Names a threat, attack vector, or vulnerability class. Threats are what the system must defend against.

```java
// @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Unsanitized input reaches query builder"
// @threat Broken_Access_Control (#bac) [P0] owasp:A01:2021 -- "Missing authorization checks on resource access"
// @threat Credential_Stuffing (#cred-stuff) [high] capec:CAPEC-600 -- "Automated login attempts with leaked credentials"
```

#### `@control` — Declare a Security Control

```
@control <n> [(#id)] [-- "<description>"]
```

Names a security control, defense mechanism, or mitigation strategy that is implemented in the codebase.

```go
// @control Parameterized_Queries (#prepared-stmts) -- "All DB access uses database/sql with placeholders"
// @control Rate_Limiting (#rate-limit) -- "Token bucket at 100 req/min per IP via middleware"
// @control RBAC (#rbac) -- "Role-based access control with principle of least privilege"
```

### 3.2. Relationship Annotations

These annotations connect assets, threats, and controls into a graph.

#### `@mitigates` — Code Defends Against a Threat

```
@mitigates <asset> against <threat> [using <control>] [-- "<description>"]
```

Declares that code at this location defends an asset against a named threat, optionally using a named control. This is the core "security positive" annotation — it says "we have a defense here."

```typescript
// @mitigates App.Auth against #sqli using #prepared-stmts -- "Login query uses parameterized statement"
function authenticate(username: string, password: string) {
    return db.query('SELECT * FROM users WHERE username = $1 AND password_hash = $2', [username, hash(password)]);
}
```

#### `@exposes` — Code is Vulnerable to a Threat

```
@exposes <asset> to <threat> [<severity>] [<external-refs>] [-- "<description>"]
```

Declares that code at this location leaves an asset vulnerable to a named threat. This is the core "security negative" annotation — it says "we know this is a weakness."

```python
# @exposes App.API.Users to #idor [P1] cwe:CWE-639 -- "No ownership check on GET /users/:id"
@app.get("/users/{user_id}")
def get_user(user_id: int):
    return db.get_user(user_id)  # Anyone can access any user
```

#### `@accepts` — Acknowledge a Risk

```
@accepts <threat> on <asset> [-- "<description>"]
```

Declares a conscious decision to accept a known risk without mitigation. This is not negligence — it's a documented business decision with reasoning.

```ruby
# @accepts #info-disclosure on App.API.HealthCheck -- "Health endpoint returns version info; this is public and non-sensitive"
get '/health' do
  { status: 'ok', version: APP_VERSION }.to_json
end
```

#### `@transfers` — Delegate Risk Responsibility

```
@transfers <threat> from <source-asset> to <target-asset> [-- "<description>"]
```

Declares that responsibility for handling a threat is transferred from one component to another.

```go
// @transfers #auth-bypass from App.API to External.Auth0 -- "Authentication delegated to Auth0; we trust their implementation"
func authMiddleware(next http.Handler) http.Handler {
    return auth0.Verify(next)
}
```

#### `@flows` — Data Flow Between Components

```
@flows <source> -> <target> [via <mechanism>] [-- "<description>"]
```

Declares a data or control flow between two components. The `->` operator is required and indicates direction.

```java
// @flows App.Frontend -> App.API via HTTPS/443 -- "All API calls over TLS 1.3"
// @flows App.API -> Infrastructure.Database via TLS/5432 -- "PostgreSQL wire protocol over TLS"
// @flows App.API -> External.S3 via HTTPS -- "File uploads sent to S3 bucket"
```

#### `@boundary` — Trust Boundary

```
@boundary between <asset-a> and <asset-b> [(#id)] [-- "<description>"]
@boundary <asset-a> | <asset-b> [(#id)] [-- "<description>"]
```

Marks a trust boundary between two security zones. All data crossing a boundary should be validated. The pipe (`|`) form is syntactic sugar for the `between ... and` form.

```yaml
# @boundary between External.Internet and Internal.DMZ (#perimeter) -- "WAF + firewall boundary"
# @boundary External.Internet | Internal.DMZ (#perimeter) -- "WAF + firewall boundary"
# @boundary between Internal.DMZ and Internal.Backend (#app-boundary) -- "Service mesh with mTLS"
```

### 3.3. Lifecycle Annotations

These annotations support security process and governance.

#### `@validates` — Test Verifies a Control

```
@validates <control> for <asset> [-- "<description>"]
```

Declares that a test at this location verifies that a security control functions correctly.

```python
# @validates #prepared-stmts for App.Auth -- "Integration test confirms SQLi payloads are blocked"
def test_sql_injection_blocked():
    response = client.post('/login', json={'username': "admin' OR '1'='1", 'password': 'x'})
    assert response.status_code == 401
```

#### `@audit` — Flag for Security Review

```
@audit <asset> [-- "<description>"]
```

Flags code for future security review. Functions as a structured TODO for the security team.

```rust
// @audit App.Crypto -- "Is AES-128-GCM still sufficient? Consider migration to AES-256"
fn encrypt(plaintext: &[u8], key: &Key) -> Vec<u8> {
    aes_gcm_128::encrypt(plaintext, key)
}
```

#### `@owns` — Assign Security Ownership

```
@owns <owner> for <asset> [-- "<description>"]
```

Assigns security ownership of a component to a team, role, or individual. Ownership determines who reviews changes and who is responsible for security posture.

```typescript
// @owns platform-security for App.Auth -- "All auth changes require security team review"
// @owns payments-team for App.Billing -- "PCI-DSS compliance responsibility"
```

#### `@handles` — Sensitive Data Classification

```
@handles <classification> on <asset> [-- "<description>"]
```

Marks code that processes sensitive data, with a classification tag indicating the data type.

```python
# @handles pii on App.Users.Profile -- "Stores name, email, phone, address"
# @handles secrets on App.Config.Vault -- "Holds API keys and database credentials"
# @handles phi on App.Medical.Records -- "HIPAA-regulated patient health data"
```

#### `@assumes` — Document a Security Assumption

```
@assumes <asset> [-- "<description>"]
```

Documents an assumption the code relies on that, if violated, could create a security vulnerability. Assumptions are latent risks.

```go
// @assumes App.API -- "All requests are pre-authenticated by the API gateway"
// @assumes Infrastructure.Network -- "Internal network traffic is not interceptable"
func handleRequest(r *http.Request) {
    // No auth check here — assumed handled upstream
    userID := r.Header.Get("X-User-ID")
}
```

### 3.4. Comment Annotations

#### `@comment` — Security-Relevant Developer Note

```
@comment [-- "<description>"]
```

Attaches a security-relevant developer note to the surrounding code. Comments appear in the threat model report but do not define threats, controls, or relationships. They serve as the minimum annotation — developers who are unsure which annotation type applies can always add `@comment` to ensure their note is captured in the security model.

```typescript
// @comment -- "Legacy OAuth1 flow, scheduled for removal in Q3"
async function legacyAuth(req: Request) { ... }

// @comment -- "Rate limit configured in API gateway, not in application code"
app.post('/api/transfer', handleTransfer);
```

### 3.5. Special Annotations

#### `@shield` — AI Exclusion Marker

```
@shield [-- "<reason>"]
@shield:begin [-- "<reason>"]
@shield:end
```

Excludes code from AI coding assistant context. The `@shield` annotation is a marker intended for cooperating tools: it declares the developer's intent that the annotated code should not be processed by external AI systems.

Single-line form excludes the annotated function or class:

```python
# @shield -- "Proprietary trading algorithm, do not expose to external LLMs"
def calculate_position_size(signals, portfolio):
    ...
```

Block form excludes a range of code:

```java
// @shield:begin -- "HSM integration contains key material handling"
private byte[] deriveKey(byte[] masterKey, byte[] context) {
    // ... sensitive cryptographic operations ...
}
private byte[] wrapKey(byte[] key, byte[] wrappingKey) {
    // ... more sensitive operations ...
}
// @shield:end
```

**Compliance requirements for GuardLink-aware AI integrations (Conformance Level 4):**

Implementations claiming Level 4 conformance (§9) must:
1. Detect `@shield` annotations during context gathering
2. Exclude the annotated scope (function, class, or begin/end block) from all prompts
3. Not summarize, paraphrase, or reference the excluded code
4. Continue to process non-shielded code normally

Non-conforming tools are not bound by this requirement, but the annotation serves as a clear signal of developer intent regardless of tooling.

---

## 4. ThreatSpec Compatibility

GuardLink is a superset of the original ThreatSpec syntax. The original annotations map to current syntax as follows:

| Original ThreatSpec | Current GuardLink | Notes |
|---------------------|-------------------|-------|
| `@mitigates Component against Threat with Control` | `@mitigates Component against Threat using Control` | `with` → `using` (both accepted) |
| `@exposes Component to Threat` | `@exposes Component to Threat` | Identical |
| `@accepts Threat to Component` | `@accepts Threat on Component` | `to` → `on` (both accepted) |
| `@transfers Threat from Source to Target` | `@transfers Threat from Source to Target` | Identical |
| `@connects Component to Component` | `@flows Component -> Component` | Arrow syntax preferred |
| `@review Component` | `@audit Component` | Renamed for clarity |

Conforming parsers must accept both original and current syntax for backward compatibility. When both forms are present in the same codebase, the current form takes precedence.

---

## 5. Threat Model Data Structure

Parsing all annotations in a codebase produces a **ThreatModel** — a typed data structure that represents the complete security posture as declared by the development team.

### 5.1. Canonical Schema

```json
{
  "version": "1.0.0",
  "project": "my-project",
  "generated_at": "2026-02-13T12:00:00Z",
  "source_files": 142,
  "annotations_parsed": 87,

  "assets": [
    {
      "path": ["App", "Auth", "Login"],
      "id": "login",
      "description": "User-facing authentication endpoint",
      "location": { "file": "src/auth/login.ts", "line": 12, "parent_symbol": "LoginController" }
    }
  ],

  "threats": [
    {
      "name": "SQL_Injection",
      "canonical_name": "sql_injection",
      "id": "sqli",
      "severity": "critical",
      "external_refs": ["cwe:CWE-89", "owasp:A03:2021"],
      "description": "Unsanitized input reaches query builder",
      "location": { "file": "docs/threats.md", "line": 5, "parent_symbol": null }
    }
  ],

  "controls": [
    {
      "name": "Parameterized_Queries",
      "canonical_name": "parameterized_queries",
      "id": "prepared-stmts",
      "description": "All DB access uses parameterized queries",
      "location": { "file": "src/db/query.ts", "line": 1, "parent_symbol": null }
    }
  ],

  "mitigations": [
    {
      "asset": "App.Auth",
      "threat": "sqli",
      "control": "prepared-stmts",
      "description": "Login query uses parameterized statement",
      "location": { "file": "src/auth/login.ts", "line": 15, "parent_symbol": "authenticate" }
    }
  ],

  "exposures": [
    {
      "asset": "App.API.Users",
      "threat": "idor",
      "severity": "P1",
      "external_refs": ["cwe:CWE-639"],
      "description": "No ownership check on GET /users/:id",
      "location": { "file": "src/api/users.ts", "line": 42, "parent_symbol": "getUser" }
    }
  ],

  "acceptances": [],
  "transfers": [],
  "flows": [],
  "boundaries": [],
  "validations": [],
  "audits": [],
  "ownership": [],
  "data_handling": [],
  "assumptions": [],
  "shields": [],
  "comments": [],

  "coverage": {
    "total_symbols": 340,
    "annotated_symbols": 87,
    "coverage_percent": 25.6,
    "unannotated_critical": [
      { "file": "src/api/admin.ts", "line": 10, "kind": "function", "name": "deleteUser" }
    ]
  }
}
```

### 5.2. Location Object

Every annotation carries a source location:

```json
{
  "file": "src/auth/login.ts",
  "line": 15,
  "end_line": null,
  "parent_symbol": "authenticate"
}
```

- `file`: Relative path from project root
- `line`: 1-indexed line number of the annotation comment
- `end_line`: For block annotations (`@shield:begin/end`), the closing line
- `parent_symbol`: Best-effort detection of the enclosing function, method, or class name. `null` when detection fails. Tools must not rely on this field for correctness — it is metadata for human readability.

### 5.3. Graph Interpretation

The threat model forms a directed graph:

- **Nodes:** Assets, Threats, Controls
- **Edges:** `@mitigates` (Control → Asset, defending against Threat), `@exposes` (Threat → Asset), `@flows` (Asset → Asset), `@boundary` (bidirectional between Assets), `@transfers` (Asset → Asset, for a Threat), `@validates` (Test → Control)

An asset with `@exposes` edges and no corresponding `@mitigates` edges is **unmitigated** — a candidate for remediation or explicit `@accepts`.

An `@assumes` annotation on an asset is a **latent risk** — if the assumption is violated, the asset may be exposed.

A `@validates` annotation with no corresponding test execution data is **unverified** — the control exists in code but has no proof it works.

---

## 6. SARIF Output Mapping

GuardLink annotations map naturally to SARIF 2.1.0 (Static Analysis Results Interchange Format) for integration with GitHub Code Scanning, GitLab SAST, Azure DevOps, and other platforms.

### 6.1. Mapping Rules

| Annotation | SARIF Representation |
|------------|---------------------|
| `@exposes` | `result` with `level: "warning"` or `"error"` (based on severity) |
| `@accepts` | `result` with `level: "note"`, `kind: "informational"` |
| `@assumes` | `result` with `level: "note"`, `kind: "review"` |
| `@audit` | `result` with `level: "note"`, `kind: "review"` |
| `@mitigates` | `result` with `level: "none"`, `kind: "pass"` (suppresses matching `@exposes`) |
| `@handles` (secrets/pii) | `result` with `level: "note"` for data flow tracking |

### 6.2. Severity Mapping

| GuardLink Severity | SARIF Level |
|--------------------|-------------|
| `critical` / `P0` | `error` |
| `high` / `P1` | `error` |
| `medium` / `P2` | `warning` |
| `low` / `P3` | `note` |
| (no severity) | `warning` |

### 6.3. External Reference Mapping

When annotations include external references (§2.8), they map to SARIF `taxa` references:

```json
{
  "taxa": [
    {
      "toolComponent": { "name": "CWE", "guid": "..." },
      "id": "CWE-89",
      "index": 0
    }
  ]
}
```

CWE references additionally populate the `cwe` property on SARIF results, which GitHub Code Scanning uses for CWE badge display.

### 6.4. Example SARIF Output

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "guardlink",
        "version": "1.0.0",
        "informationUri": "https://github.com/Bugb-Technologies/guardlink",
        "rules": [{
          "id": "TS2001",
          "name": "ExposedThreat",
          "shortDescription": { "text": "Code exposes an asset to a known threat" },
          "defaultConfiguration": { "level": "warning" }
        }, {
          "id": "TS2002",
          "name": "UnmitigatedExposure",
          "shortDescription": { "text": "Exposure has no corresponding mitigation" },
          "defaultConfiguration": { "level": "error" }
        }, {
          "id": "TS2003",
          "name": "AcceptedRisk",
          "shortDescription": { "text": "Risk has been consciously accepted" },
          "defaultConfiguration": { "level": "note" }
        }, {
          "id": "TS2004",
          "name": "SecurityAssumption",
          "shortDescription": { "text": "Code relies on a security assumption" },
          "defaultConfiguration": { "level": "note" }
        }, {
          "id": "TS2005",
          "name": "AuditRequired",
          "shortDescription": { "text": "Code flagged for security review" },
          "defaultConfiguration": { "level": "note" }
        }]
      }
    },
    "results": [{
      "ruleId": "TS2001",
      "level": "error",
      "message": { "text": "App.API.Users is exposed to IDOR [P1]: No ownership check on GET /users/:id" },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "src/api/users.ts" },
          "region": { "startLine": 42 }
        },
        "logicalLocations": [{
          "name": "getUser",
          "kind": "function"
        }]
      }],
      "taxa": [{
        "toolComponent": { "name": "CWE" },
        "id": "CWE-639"
      }]
    }]
  }]
}
```

When uploaded to GitHub via the Code Scanning API, `@exposes` annotations appear as inline security alerts on the relevant lines in pull requests.

---

## 7. Diff and Change Detection

When comparing threat models between two git refs (e.g., a feature branch vs. `main`), the diff engine classifies changes:

### 7.1. Change Classifications

| Classification | Meaning | Default CI Behavior |
|---------------|---------|---------------------|
| `REMOVED_DEFENSE` | Deleted `@mitigates` while corresponding `@exposes` still present | **Fail** |
| `SEVERITY_ESCALATION` | Existing `@exposes` severity increased (e.g., `[P2]` → `[P0]`) | **Fail** |
| `REMOVED_ACCEPTANCE` | Deleted `@accepts` without adding `@mitigates` for the same threat | **Fail** |
| `NEW_EXPOSURE` | New `@exposes` added (with or without mitigation) | **Warn** |
| `NEW_RISK` | New `@exposes` that is mitigated or accepted | **Warn** |
| `IMPROVED` | New `@mitigates` or `@control` reducing exposure | **Pass** |
| `ACCEPTED` | New `@accepts` acknowledging a known risk | **Pass** (with note) |
| `INFO` | Changes to `@flows`, `@boundary`, `@owns`, `@handles`, `@assumes` | **Pass** |

**Design rationale:** Adding `@exposes` is classified as `NEW_EXPOSURE`, not as a regression. Documenting a vulnerability is a positive act of transparency — the vulnerability existed before the annotation did. CI should surface new exposures for review but should not punish developers for declaring them. True regressions are defensive actions — removing a mitigation, escalating a severity, or revoking an acceptance — where the security posture demonstrably worsened.

### 7.2. CI Gate Rules

Default CI behavior (configurable):

```yaml
# Example CI configuration
guardlink:
  fail_on:
    - removed_defense          # Mitigation deleted while exposure remains
    - severity_escalation      # Exposure severity increased
    - removed_acceptance       # Accepted risk revoked without replacement
  warn_on:
    - new_exposure             # New @exposes added (reward honesty, flag for review)
    - new_risk                 # New exposure even if mitigated (awareness)
    - unmitigated_high         # Any P0/P1 exposure without mitigation
  allow:
    - accepted                 # Explicitly accepted risks pass
    - improved                 # New defenses always pass
    - info                     # Metadata changes pass
```

Tools should provide clear exit codes: `0` for pass, `1` for fail-level findings, `2` for warn-level findings (configurable to fail or pass).

---

## 8. AI Coding Assistant Integration

GuardLink is designed for a world where AI coding assistants (Claude Code, GitHub Copilot, OpenAI Codex, Google Gemini CLI, Cursor, Windsurf, etc.) are part of the development workflow.

### 8.1. Instruction Files

Projects can include instruction files that teach coding agents to write GuardLink annotations. Instruction files use the agent's native format:

| Agent | File |
|-------|------|
| Claude Code | `CLAUDE.md` |
| Gemini CLI | `GEMINI.md` |
| OpenAI Codex | `AGENTS.md` |
| Cursor | `.cursorrules` |
| Windsurf | `.windsurfrules` |

A conforming instruction file should contain:
1. The annotation syntax reference
2. Rules for when to add annotations (security-relevant code changes)
3. The constraint that agents only add annotations and do not modify functional code, execute commands, change CI configuration, or modify secrets
4. Examples in the project's primary language

### 8.2. MCP Server Integration

A conforming GuardLink tool may expose a Model Context Protocol (MCP) server with the following tool interface:

| Tool | Purpose |
|------|---------|
| `guardlink_parse` | Parse annotations from specified files, return threat model |
| `guardlink_status` | Return coverage statistics and unmitigated exposures |
| `guardlink_validate` | Check annotations for syntax errors and dangling references |
| `guardlink_suggest` | Given a code diff, suggest appropriate annotations |
| `guardlink_lookup` | Query the threat model for a specific asset, threat, or control |

MCP integration enables real-time threat model awareness during coding sessions. Tools should support project-scoped MCP configuration (e.g., `.mcp.json` for Claude Code) so that the MCP server can be committed to the repository and automatically available to all developers.

### 8.3. AI-Powered Threat Analysis

A conforming Level 4 implementation may provide AI-driven threat analysis that takes the parsed ThreatModel as input and produces structured reports using established threat modeling frameworks:

| Framework | Description |
|-----------|-------------|
| STRIDE | Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege |
| DREAD | Risk scoring: Damage, Reproducibility, Exploitability, Affected Users, Discoverability |
| PASTA | Process for Attack Simulation and Threat Analysis — seven-stage methodology |
| Attacker-centric | Persona-based analysis with kill chains, attack trees, and adversary motivation |
| RAPID | Risk Assessment Process for Informed Decision-making |
| General | Comprehensive analysis combining multiple frameworks as appropriate for the codebase |

The analysis workflow:
1. The tool serializes the ThreatModel (assets, threats, controls, flows, boundaries, exposures) into a prompt
2. Project context (README, package manifest, directory structure) is included for architecture understanding
3. Code snippets from annotated locations are extracted to provide real implementation context
4. The prompt is sent to an LLM (via direct API or CLI agent) with framework-specific system instructions
5. The AI reads the actual source files, cross-references annotations with code, and produces a structured report
6. Reports are saved as timestamped markdown files in `.guardlink/threat-reports/`

Analysis can be performed through multiple execution paths:
- **Direct API**: Streaming LLM calls via Anthropic, OpenAI, OpenRouter, DeepSeek, or Ollama
- **CLI Agents**: Inline execution via Claude Code, Codex CLI, or Gemini CLI (the agent reads the codebase directly)
- **IDE Agents**: Prompt copied to clipboard for Cursor, Windsurf, or other IDE-integrated assistants

Additional analysis capabilities:
- **Extended thinking / reasoning mode**: Enables chain-of-thought reasoning for deeper analysis
- **Web search grounding**: Augments analysis with real-time CVE, advisory, and vulnerability data
- **Custom prompts**: Free-text analysis instructions for domain-specific or mixed-framework analysis

### 8.4. Interactive Dashboard

A conforming implementation may generate an interactive HTML dashboard that visualizes the threat model. The dashboard should include:
- Risk grade and severity breakdown
- Asset graph with threat/control relationships
- Mermaid-based data flow diagrams generated from `@flows` and `@boundary` annotations
- Exposure triage view with severity filtering
- Annotation coverage statistics
- Integrated AI threat report summaries (loaded from `.guardlink/threat-reports/`)

### 8.5. Interactive TUI

A conforming implementation may provide an interactive terminal interface (TUI) that combines:
- Slash commands for all CLI operations (`/parse`, `/status`, `/validate`, `/exposures`, etc.)
- Freeform AI chat for conversational threat model exploration
- Exposure triage workflow (`/exposures` → `/show <n>` for detail + code context)
- Coverage scanning (`/scan`) to identify unannotated security-relevant symbols
- Integrated AI provider configuration (`/model`) supporting both direct API and CLI agent modes

### 8.6. `@shield` Compliance

AI tools claiming GuardLink Level 4 conformance (§9) must implement `@shield` exclusion as defined in §3.4. This is a compliance requirement for GuardLink-aware AI integrations. Code marked with `@shield` contains content the developer has explicitly decided should not be processed by external AI systems.

---

## 9. Conformance Levels

### Level 1: Parser

A Level 1 conforming implementation:
- Parses all annotation types defined in §3
- Accepts GuardLink v1 syntax (§4)
- Produces a ThreatModel data structure conforming to the schema in §5
- Handles all comment prefix styles listed in §2.9
- Implements name normalization per §2.10
- Implements description escaping per §2.11
- Preserves external references per §2.8
- Reports syntax errors with file and line number

### Level 2: Analyzer

A Level 2 conforming implementation (includes Level 1) additionally:
- Produces SARIF output conforming to §6
- Computes annotation coverage statistics
- Detects unmitigated exposures (has `@exposes` without corresponding `@mitigates`)
- Detects dangling references (references `#id` that is never defined)

### Level 3: CI/CD

A Level 3 conforming implementation (includes Level 2) additionally:
- Computes threat model diffs between git refs (§7)
- Classifies changes per §7.1
- Supports configurable CI gate rules per §7.2
- Provides exit codes suitable for CI pipeline integration

### Level 4: AI-Integrated

A Level 4 conforming implementation (includes Level 3) additionally:
- Respects `@shield` exclusion markers (§3.4, §8.6)
- Provides MCP server integration (§8.2) or equivalent
- Supports AI-assisted annotation generation
- May provide AI-powered threat analysis with framework-specific reports (§8.3)
- May provide interactive dashboard visualization (§8.4)
- May provide interactive TUI with exposure triage and AI chat (§8.5)

### Conformance Testing

The GuardLink project maintains a conformance test suite consisting of:

- **Fixture files:** Annotated source files in 10+ languages with known annotations
- **Expected parse output:** JSON files containing the expected ThreatModel for each fixture
- **Expected SARIF output:** SARIF files for Level 2 validation
- **Diff scenarios:** Pairs of threat models with expected change classifications for Level 3

An implementation may claim conformance at a given level by passing all test cases for that level and all levels below it. The conformance test suite is published under the MIT license at the GuardLink project repository and is maintained alongside the specification.

---

## 10. Examples

### 10.1. TypeScript / Express API

```typescript
// @asset App.API (#api) -- "Express REST API serving the main application"
// @boundary between External.Internet and App.API (#api-boundary) -- "Nginx reverse proxy with rate limiting"

import express from 'express';
import { db } from './database';

// @control Input_Validation (#input-val) -- "Zod schema validation on all request bodies"
// @control JWT_Authentication (#jwt-auth) -- "RS256 JWT tokens verified on every protected route"

const app = express();

// @mitigates App.API against #sqli using #prepared-stmts -- "Parameterized queries via Prisma ORM"
// @mitigates App.API against #xss using #input-val -- "Zod strips unexpected fields and validates types"
// @handles pii on App.API -- "Processes user profiles containing name, email, phone"
app.get('/users/:id', authenticate, async (req, res) => {
    // @exposes App.API to #idor [P1] cwe:CWE-639 -- "No ownership check — any authenticated user can access any profile"
    const user = await db.user.findUnique({ where: { id: req.params.id } });
    res.json(user);
});

// @mitigates App.API against #brute-force using #rate-limit -- "10 attempts per 15 minutes per IP"
app.post('/login', rateLimit({ max: 10, windowMs: 15 * 60 * 1000 }), async (req, res) => {
    // @mitigates App.API against #sqli using #prepared-stmts
    const user = await db.user.findUnique({ where: { email: req.body.email } });
    // ...
});
```

### 10.2. Python / FastAPI

```python
# @asset App.ML.Pipeline (#ml-pipeline) -- "Machine learning inference pipeline"
# @asset App.ML.Models (#ml-models) -- "Trained model artifacts stored in S3"

# @threat Model_Poisoning (#model-poison) [high] attack:T1565 -- "Adversarial training data corrupts model behavior"
# @threat Prompt_Injection (#prompt-inj) [critical] cwe:CWE-77 -- "User input manipulates LLM behavior"

# @control Input_Sanitization (#sanitize) -- "Strip control characters and limit input length"
# @control Output_Filtering (#output-filter) -- "Post-process LLM output to remove PII and harmful content"

# @mitigates App.ML.Pipeline against #prompt-inj using #sanitize -- "Input cleaned before reaching model"
# @mitigates App.ML.Pipeline against #prompt-inj using #output-filter -- "Output filtered before returning to user"
@app.post("/predict")
async def predict(request: PredictRequest):
    sanitized = sanitize_input(request.prompt)
    result = await model.predict(sanitized)
    return filter_output(result)

# @shield -- "Proprietary model architecture and training hyperparameters"
class CustomTransformer:
    def __init__(self):
        self.hidden_dim = 4096
        self.num_layers = 32
        # ...
```

### 10.3. Go / HTTP Service

```go
// @asset App.PaymentService (#payments) -- "Handles all payment processing and refunds"
// @handles financial on App.PaymentService -- "Credit card numbers, transaction amounts, merchant IDs"
// @boundary between App.PaymentService and External.Stripe (#payment-boundary) -- "TLS 1.3, API key auth"

// @threat Payment_Tampering (#payment-tamper) [P0] cwe:CWE-345 -- "Attacker modifies amount or recipient in transit"
// @control HMAC_Verification (#hmac) -- "HMAC-SHA256 signature on all payment requests"
// @control Idempotency_Keys (#idempotency) -- "UUID idempotency key prevents duplicate charges"

// @mitigates App.PaymentService against #payment-tamper using #hmac -- "Request signature verified before processing"
// @mitigates App.PaymentService against #double-charge using #idempotency -- "Duplicate requests return cached response"
func processPayment(w http.ResponseWriter, r *http.Request) {
    // @assumes App.PaymentService -- "API gateway has already verified the user's authentication token"
    if !verifyHMAC(r) {
        http.Error(w, "invalid signature", http.StatusForbidden)
        return
    }
    // ...
}
```

### 10.4. Rust / Cryptographic Code

```rust
// @asset App.Crypto (#crypto) -- "Cryptographic operations for data-at-rest encryption"
// @handles secrets on App.Crypto -- "Encryption keys, nonces, key derivation parameters"

// @threat Key_Leakage (#key-leak) [P0] cwe:CWE-316 -- "Encryption key exposed in memory, logs, or error messages"
// @control Zeroize (#zeroize) -- "All key material zeroed on drop via zeroize crate"
// @control Constant_Time (#ct) -- "All comparisons use constant-time operations to prevent timing attacks"

// @shield:begin -- "Key derivation implementation — security-critical, exclude from AI context"

// @mitigates App.Crypto against #key-leak using #zeroize -- "Key struct implements ZeroizeOnDrop"
#[derive(Zeroize, ZeroizeOnDrop)]
struct EncryptionKey {
    bytes: [u8; 32],
}

// @mitigates App.Crypto against #timing-attack using #ct -- "HMAC comparison uses constant_time_eq"
fn verify_mac(expected: &[u8], actual: &[u8]) -> bool {
    constant_time_eq(expected, actual)
}

// @shield:end
```

### 10.5. Terraform / Infrastructure

```hcl
# @asset Infrastructure.VPC (#vpc) -- "Production VPC in us-east-1"
# @boundary between External.Internet and Infrastructure.VPC (#vpc-boundary) -- "Security groups + NACLs"

# @threat Unrestricted_Ingress (#open-ingress) [P0] cwe:CWE-284 -- "Security group allows 0.0.0.0/0 access"
# @control Restricted_CIDR (#restricted-cidr) -- "Ingress limited to office IP ranges and VPN"

# @mitigates Infrastructure.VPC against #open-ingress using #restricted-cidr
resource "aws_security_group" "api" {
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs  # Office + VPN only
  }

  # @exposes Infrastructure.VPC to #open-ingress [P2] -- "SSH open to VPN range, not fully restricted"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.vpn_cidr]
  }
}
```

---

## 11. Acknowledgments

GuardLink builds on the original [ThreatSpec](https://github.com/threatspec/threatspec) project by Fraser Scott and its contributors (2015–2020), published under the MIT License. The original project established the foundational concept of embedding threat model annotations in source code comments and defined the core verbs (`@mitigates`, `@exposes`, `@transfers`, `@accepts`) that GuardLink inherits.

The extended annotation set (data classification, ownership, assumptions, validation, trust boundaries, AI shielding) was developed through practical application across production codebases, with design contributions from the BugB Technologies team and community feedback.

---

## 12. Governance

### 12.1. Specification Ownership

GuardLink is maintained as an open specification at [`github.com/Bugb-Technologies/guardlink`](https://github.com/Bugb-Technologies/guardlink). The specification text is licensed under CC-BY-4.0. Reference implementations, conformance test suites, and tooling are licensed under MIT.

BugB Technologies is the initial maintainer and primary contributor. The specification is designed for community governance and welcomes contributions from any organization or individual.

### 12.2. GuardLink Enhancement Proposals (GLEPs)

Changes to the specification follow a lightweight RFC process:

1. **GLEP submission.** Any contributor may submit a GuardLink Enhancement Proposal as a pull request to the spec repository. A GLEP must include: motivation (what problem it solves), specification changes (exact text diffs), backward compatibility analysis, and at least one example.

2. **Review period.** GLEPs are open for public comment for a minimum of 14 days. The Steering Committee may extend this period for significant changes.

3. **Acceptance criteria.** A GLEP is accepted when it receives approval from at least two Steering Committee members and has no unresolved objections from any Steering Committee member. Accepted GLEPs are merged into the specification and assigned a version number.

4. **Versioning.** The specification follows Semantic Versioning:
   - **Patch** (1.0.x): Clarifications, typo fixes, additional examples. No parser changes required.
   - **Minor** (1.x.0): New annotation types, new optional qualifiers, new conformance requirements. Existing parsers continue to work; new features are additive.
   - **Major** (x.0.0): Breaking changes to existing annotation syntax or semantics. Existing parsers may require updates.

### 12.3. Steering Committee

The Steering Committee is responsible for reviewing GLEPs, resolving disputes, and maintaining the specification and conformance suite. The initial committee consists of the founding contributors from BugB Technologies. The committee will expand to include representatives from other organizations as the ecosystem grows.

Membership criteria:
- Active contribution to the specification, conformance suite, or a conforming implementation
- Commitment to the specification's design principles (§1)
- No single organization may hold more than 50% of committee seats once the committee exceeds 4 members

### 12.4. Multi-Implementation Requirement

To prevent the specification from becoming a single-vendor format, the following principle applies: any annotation type or feature added via GLEP should be implementable by any conforming tool. Features that inherently require a specific vendor's infrastructure are out of scope for the core specification and should be documented as vendor extensions.

The GuardLink project maintains at least two independent implementations (a reference implementation and a minimal conformance-testing implementation) to validate that the specification is implementable without vendor-specific knowledge.

---

## Appendix A: Quick Reference Card

```
DEFINE
  @asset    <path> (#id) -- "description"
  @threat   <n> (#id) [severity] [cwe:ID] [owasp:ID] [attack:ID] -- "description"
  @control  <n> (#id) -- "description"

CONNECT
  @mitigates  <asset> against <threat> [using <control>] -- "description"
  @exposes    <asset> to <threat> [severity] [cwe:ID] -- "description"
  @accepts    <threat> on <asset> -- "description"
  @transfers  <threat> from <source> to <target> -- "description"
  @flows      <source> -> <target> [via <mechanism>] -- "description"
  @boundary   between <asset-a> and <asset-b> (#id) -- "description"
  @boundary   <asset-a> | <asset-b> (#id) -- "description"

LIFECYCLE
  @validates  <control> for <asset> -- "description"
  @audit      <asset> -- "description"
  @owns       <owner> for <asset> -- "description"
  @handles    <classification> on <asset> -- "description"
  @assumes    <asset> -- "description"

COMMENT
  @comment    [-- "description"]

SPECIAL
  @shield     [-- "reason"]
  @shield:begin / @shield:end

SEVERITY:     [P0] [P1] [P2] [P3]  or  [critical] [high] [medium] [low]
DATA:         pii | phi | financial | secrets | internal | public
IDS:          Define with (#id), reference with #id
EXTERNAL:     cwe:CWE-89 | owasp:A03:2021 | attack:T1190 | capec:CAPEC-66
NAMES:        Normalized: lowercase, separators → underscore, NFKC
DESCRIPTIONS: Escaped: \" for quote, \\ for backslash
```

---

## Appendix B: Formal Grammar (EBNF)

The following EBNF grammar defines the annotation syntax. Parsers may use regex for practical implementation but must produce results consistent with this grammar.

```ebnf
annotation       = "@" verb SP arguments { SP qualifier } { SP external_ref } [ SP "--" SP description ] ;

(* Verbs *)
verb             = "asset" | "threat" | "control"
                 | "mitigates" | "exposes" | "accepts" | "transfers"
                 | "flows" | "boundary"
                 | "validates" | "audit" | "owns" | "handles" | "assumes"
                 | "comment"
                 | "shield" | "shield:begin" | "shield:end" ;

(* Arguments — verb-specific *)
arguments        = asset_args | threat_args | control_args
                 | mitigates_args | exposes_args | accepts_args | transfers_args
                 | flows_args | boundary_args
                 | validates_args | audit_args | owns_args | handles_args | assumes_args
                 | comment_args
                 | shield_args ;

asset_args       = component_path [ SP id_def ] ;
threat_args      = name [ SP id_def ] ;
control_args     = name [ SP id_def ] ;
mitigates_args   = component_path SP "against" SP threat_ref [ SP "using" SP control_ref ] ;
exposes_args     = component_path SP "to" SP threat_ref ;
accepts_args     = threat_ref SP "on" SP component_path ;
transfers_args   = threat_ref SP "from" SP component_path SP "to" SP component_path ;
flows_args       = component_path SP "->" SP component_path [ SP "via" SP mechanism ] ;
boundary_args    = [ "between" SP ] component_path SP "and" SP component_path [ SP id_def ]
                 | component_path SP "|" SP component_path [ SP id_def ] ;
validates_args   = control_ref SP "for" SP component_path ;
audit_args       = component_path ;
owns_args        = owner_name SP "for" SP component_path ;
handles_args     = classification SP "on" SP component_path ;
assumes_args     = component_path ;
comment_args     = (* empty *) ;
shield_args      = (* empty *) ;

(* Building blocks *)
component_path   = segment { "." segment } ;
segment          = letter { letter | digit | "_" } ;
name             = word { ("_" | "-" | SP) word } ;
word             = letter { letter | digit } ;
id_def           = "(#" identifier ")" ;
id_ref           = "#" identifier ;
identifier       = ( letter | digit | "_" | "-" ) { letter | digit | "_" | "-" } ;
threat_ref       = id_ref | name ;
control_ref      = id_ref | name ;
owner_name       = identifier ;
mechanism        = { any_char - "--" } ;
classification   = "pii" | "phi" | "financial" | "secrets" | "internal" | "public" ;

(* Qualifiers *)
qualifier        = severity ;
severity         = "[" severity_value "]" ;
severity_value   = "P0" | "P1" | "P2" | "P3"
                 | "critical" | "high" | "medium" | "low" ;  (* case-insensitive *)

(* External references *)
external_ref     = ext_prefix ":" ext_id ;
ext_prefix       = "cwe" | "owasp" | "attack" | "capec" | identifier ;
ext_id           = { letter | digit | "-" | ":" | "." } ;

(* Description *)
description      = '"' { escaped_char } '"' ;
escaped_char     = '\\"' | '\\\\' | any_char - '"' ;

(* Primitives *)
SP               = " " { " " } ;
letter           = "A"-"Z" | "a"-"z" ;
digit            = "0"-"9" ;
any_char         = ? any UTF-8 character ? ;
```

This grammar is informative. In cases of ambiguity between this grammar and the prose specification in §2–§3, the prose specification takes precedence.

---

*This specification is published under CC-BY-4.0. You are free to share and adapt this material for any purpose, including commercial, provided you give appropriate credit. Reference implementations and conformance tests are published under the MIT license.*
