// @asset App.Auth.Login (#login) -- "User-facing authentication endpoint"
// @asset Infrastructure.Database.Primary (#primary-db) -- "PostgreSQL 15"
// @asset External.PaymentGateway (#stripe) -- "Stripe API integration"

// @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 owasp:A03:2021 -- "Unsanitized input reaches query builder"
// @threat Broken_Access_Control (#bac) [P0] -- "Missing authorization checks"
// @threat Credential_Stuffing (#cred-stuff) [high] capec:CAPEC-600 -- "Automated login attempts"

// @control Parameterized_Queries (#prepared-stmts) -- "All DB access uses placeholders"
// @control Rate_Limiting (#rate-limit) -- "Token bucket at 100 req/min"
// @control RBAC (#rbac) -- "Role-based access control"

// @mitigates App.Auth.Login against #sqli using #prepared-stmts -- "Login uses parameterized query"
// @exposes App.Auth.Login to #bac [P1] cwe:CWE-639 -- "No ownership check on profile access"
// @accepts #cred-stuff on App.Auth.Login -- "Rate limiting is sufficient"

// @transfers #sqli from App.Auth.Login to External.PaymentGateway -- "Payment provider handles their own SQL"
// @flows App.Auth.Login -> Infrastructure.Database.Primary via TLS/5432 -- "PostgreSQL over TLS"
// @boundary between App.Auth.Login and External.PaymentGateway (#pay-boundary) -- "TLS 1.3 API key auth"

// @validates #prepared-stmts for App.Auth.Login -- "Integration test confirms SQLi payloads blocked"
// @audit App.Auth.Login -- "Review session handling for timing attacks"
// @owns platform-security for App.Auth.Login -- "Security team reviews all auth changes"
// @handles pii on App.Auth.Login -- "Processes name, email, phone"
// @handles secrets on Infrastructure.Database.Primary -- "Connection strings and credentials"
// @assumes App.Auth.Login -- "API gateway has already verified TLS termination"

// @shield -- "Proprietary algorithm below"
// @shield:begin -- "Key derivation, exclude from AI context"
function deriveKey() { return 42; }
// @shield:end

// v1 compat tests
// @mitigates App.Auth.Login against #sqli with #prepared-stmts -- "v1 with keyword"
// @accepts #cred-stuff to App.Auth.Login -- "v1 to keyword"
// @review Infrastructure.Database.Primary -- "v1 review keyword"
// @connects App.Auth.Login to External.PaymentGateway -- "v1 connects keyword"

// Multi-line description
// @threat Session_Hijacking (#session-hijack) [P1]
// -- "Attacker steals session token via XSS"
// -- "Particularly dangerous on shared networks"

// Escaped description
// @threat XSS (#xss) -- "Attacker injects \"<script>\" tags via user input"
