/**
 * Outbound webhooks for the sarif-shop fixture. Every annotation here is
 * file-level: it sits on the module, not on a function.
 *
 * @flows #orders -> #mailer via notify -- "Order events queued for delivery"
 * @flows #mailer -> ExternalHost via fetch -- "Webhook POSTed to a caller-supplied URL"
 * @exposes #mailer to #ssrf [medium] cwe:CWE-918 -- "Webhook URL is not validated before the request"
 * @transfers #ssrf from #mailer to #web -- "URL validation is the API layer's job"
 * @assumes #mailer -- "Callers pass only registered webhook URLs"
 * @audit #mailer -- "Confirm the API layer really rejects private address ranges"
 * @exposes #mailer to #log-flood [low] -- "Delivery failures log the full response body"
 * @exposes #mailer to
 */
export async function notify(url: string, body: string): Promise<void> {
  await fetch(url, { method: 'POST', body });
}
