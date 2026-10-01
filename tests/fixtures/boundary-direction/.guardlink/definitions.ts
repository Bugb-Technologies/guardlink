// Definitions for the boundary-direction fixture. See ../FIXTURE.md.

// @asset Shop.Web (#web) -- "Public HTTP API"
// @asset Shop.Orders (#orders) -- "Order service behind the API"
// @asset Shop.Store (#store) -- "Order database"

// @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 owasp:A03:2021 -- "Request text reaches a query unescaped"
