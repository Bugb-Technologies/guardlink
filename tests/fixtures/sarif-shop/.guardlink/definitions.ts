// Definitions for the sarif-shop fixture. See ../FIXTURE.md.

// @asset Shop.Web (#web) -- "Public HTTP API"
// @asset Shop.Orders (#orders) -- "Order service behind the API"
// @asset Shop.Store (#store) -- "Order database"
// @asset Shop.Mailer (#mailer) -- "Outbound webhook client"

// @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 owasp:A03:2021 -- "Request text reaches a query unescaped"
// @threat Insecure_Direct_Object_Reference (#idor) [high] cwe:CWE-639 owasp:A01:2021 -- "Objects fetched by id with no owner check"
// @threat Server_Side_Request_Forgery (#ssrf) [medium] cwe:CWE-918 -- "Caller chooses where the server connects"
// @threat Log_Flooding (#log-flood) [low] -- "Unbounded caller text written to logs"
// @threat Denial_Of_Service (#dos) [medium] cwe:CWE-400 -- "Unbounded work per request"

// @control Parameterized_Queries (#param-queries) -- "Bound query parameters"
// @control Owner_Check (#owner-check) -- "Ownership verified before access"
