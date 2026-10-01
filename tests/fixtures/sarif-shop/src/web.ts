/**
 * HTTP entry points for the sarif-shop fixture.
 *
 * @boundary between Client and #web (#edge) -- "Internet to API: nothing before this point is trusted"
 * @flows Client -> #web via HTTPS -- "Every request arrives over TLS"
 */
export const service = 'web';

/**
 * @flows Client -> #web via GET./orders/:id -- "Order id from the path"
 * @flows #web -> #orders via getOrder -- "Id handed to the order service unchanged"
 * @exposes #orders to #idor [high] cwe:CWE-639 owasp:A01:2021 -- "No owner check before the order is returned"
 * @confirmed #idor on #orders [high] cwe:CWE-639 -- "Reproduced: user B read user A's order by id"
 */
export function getOrder(id: string): string {
  return lookup(id);
}

/**
 * @flows Client -> #web via POST./orders/search -- "Free-text search term in the body"
 * @flows #web -> #orders via searchOrders -- "Term passed to the order service"
 * @flows #orders -> #store via query -- "Term reaches SQL"
 * @boundary between #orders and #store (#data) -- "Service to database"
 * @exposes #store to #sqli [critical] cwe:CWE-89 owasp:A03:2021 -- "Search term concatenated into SQL"
 * @handles pii on #store -- "Customer names and addresses"
 */
export function searchOrders(term: string): string {
  return lookup(`SELECT * FROM orders WHERE note LIKE '%${term}%'`);
}

/**
 * @flows Client -> #web via DELETE./orders/:id -- "Order id from the path"
 * @exposes #orders to #dos [medium] cwe:CWE-400 -- "Cascade delete is unbounded"
 * @mitigates #orders against #dos using #param-queries -- "Delete is a single bound statement"
 * @exposes #orders to #csrf [medium] -- "Refers to a threat this model never defines"
 */
export function deleteOrder(id: string): string {
  return lookup(id);
}

function lookup(text: string): string {
  return text;
}
