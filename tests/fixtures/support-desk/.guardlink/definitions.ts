// Definitions for the support-desk fixture. See ../FIXTURE.md.

// @asset Agent.ToolSurface (#tool-surface) -- "Tools registered with the support agent"
// @asset Shop.OrdersDb (#orders-db) -- "Orders table"
// @asset Shop.UsersDb (#users-db) -- "Users table"
// @asset Shop.Payments (#payments) -- "Refunds through the payment processor"
// @asset Shop.Kb (#kb) -- "Help-centre articles"
// @asset Shop.Outbox (#outbox) -- "Emails to customers"
// @asset Host.Fs (#host-fs) -- "The host filesystem"
// @asset Release.Registry (#registry) -- "The package registry releases are published to"
// @asset Identity.AgentSession (#agent-session) -- "Customer-scoped token the agent presents"
// @asset Identity.BillingSa (#billing-sa) -- "Service account that can move money"

// @threat Excessive_Agency (#excessive-agency) [high] cwe:CWE-862 -- "Agent holds a capability nobody approved"

// @actor Support_Agent (#support-agent) -- "LLM agent; acts for the signed-in customer"
// @actor Support_Human (#support-human) -- "Approves refunds and outbound email in the review queue"
// @actor CI_Runner (#ci-runner) -- "Release pipeline"

export {};
