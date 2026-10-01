/**
 * HTTP entry points for the boundary-direction fixture.
 *
 * @boundary from Client to #web (#edge) -- "Internet to API: nothing before this point is trusted"
 * @boundary between #web and #orders (#svc) -- "API to order service over the internal network"
 */
export const service = 'web';

/**
 * @flows Client -> #web via POST./orders/search -- "Free-text search term in the body"
 * @flows #web -> #orders via searchOrders -- "Term passed to the order service"
 * @flows #orders -> #store via query -- "Term reaches SQL"
 * @boundary from #orders to #store (#data) -- "Service to database: the store trusts every query it is sent"
 * @exposes #store to #sqli [critical] cwe:CWE-89 owasp:A03:2021 -- "Search term concatenated into SQL"
 */
export function searchOrders(term: string): string {
  return lookup(`SELECT * FROM orders WHERE note LIKE '%${term}%'`);
}

/**
 * @flows #store -> Backup via pg_dump -- "Nightly dump to off-site storage"
 * @boundary between #store and Backup (#backup) -- "Database to off-site storage"
 */
export function nightlyBackup(): string {
  return lookup('backup');
}

function lookup(text: string): string {
  return text;
}
