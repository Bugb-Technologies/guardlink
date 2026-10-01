/**
 * GuardLink — route channels on @flows, and which route a claim is reached through.
 *
 * A `@flows` whose `via` mechanism begins `METHOD./path` declares an HTTP route
 * (SPEC §3.2, `@flows`, route channels). `parseRouteChannel` is the one reader
 * of that form: the parser stores its result on every flow record as `route`,
 * and the SARIF exporter attributes routes to findings through
 * `buildRouteIndex`, so the model and the export cannot read one mechanism two
 * ways.
 *
 * Attribution (SPEC §3.6.2) used to key routes by file, first declaration wins.
 * A file declaring `GET /orders/<id>` on one handler and `POST /pay` on another
 * labelled every finding in it `GET /orders/<id>` — including an injection on
 * the `POST /pay` handler, which is the route a scanner then probed. A route
 * now belongs to the handler it is declared on, and when the model does not say
 * which route reaches a claim the answer is `ambiguous`, with the candidates,
 * rather than whichever route happened to be written first.
 *
 * @flows ThreatModel -> #parser via buildRouteIndex -- "Route @flows indexed by handler scope"
 * @comment -- "Pure functions over the parsed model; the path is returned verbatim from the annotation and never resolved, fetched or joined to a base URL"
 */

import type { HttpRoute, SourceLocation, ThreatModelFlow } from '../types/index.js';
import { normalizeRef } from './coverage.js';
import { handlerScope, scopeEncloses, type HandlerScope } from './handler-scope.js';

export type { HttpRoute };

const ROUTE_CHANNEL_RE = /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\.(\/\S*)/i;

/**
 * Read a route channel from a flow mechanism, or null when it is not one.
 *
 *   `GET./orders/<id>`                     → GET  /orders/<id>
 *   `post./pay?amount (json body)`         → POST /pay
 *   `GET./websocket/attach?endpointId&id`  → GET  /websocket/attach
 *   `tar.NewReader`, `HTTPS`, `TLS 1.3`    → null
 *
 * The path is the run of non-space characters after `METHOD.`, cut at the first
 * `?` (a query hint) with any `(…)` note removed. It is returned verbatim — no
 * base path is assumed and nothing is decoded.
 */
export function parseRouteChannel(mechanism: string | null | undefined): HttpRoute | null {
  if (!mechanism) return null;
  const m = ROUTE_CHANNEL_RE.exec(mechanism.trim());
  if (!m) return null;
  const path = m[2].split('?')[0].replace(/\s*\(.*?\)\s*/g, '').trim();
  if (!path) return null;
  return { method: m[1].toUpperCase(), path };
}

/** One declared route, with where it was declared. */
export interface RouteDeclaration extends HttpRoute {
  file: string;
  line: number;
}

/**
 * Which route reaches a claim.
 *
 * `scope` says how the route was found, strongest first: declared on the claim's
 * own handler, declared for the claim's whole file, or the one route into the
 * claim's asset when its file declares none. `ambiguous` carries every route the
 * model leaves in contention, so a consumer can choose — or refuse — knowingly.
 */
export type RouteAttribution =
  | { status: 'attributed'; scope: 'handler' | 'file' | 'asset'; route: RouteDeclaration }
  | { status: 'ambiguous'; candidates: RouteDeclaration[] };

export interface RouteIndex {
  /** The route reaching a claim on `asset` at `location`, or null when the model declares none. */
  routeFor(asset: string, location: SourceLocation): RouteAttribution | null;
}

interface IndexedRoute {
  decl: RouteDeclaration;
  /** Null for a route declared at file level. */
  scope: HandlerScope | null;
}

/** Collapse routes that name the same METHOD and path; the first declaration speaks for them. */
function distinct(routes: IndexedRoute[]): IndexedRoute[] {
  const seen = new Set<string>();
  return routes.filter(r => {
    const key = `${r.decl.method} ${r.decl.path}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function decide(routes: IndexedRoute[], scope: 'handler' | 'file' | 'asset'): RouteAttribution | null {
  const unique = distinct(routes);
  if (unique.length === 0) return null;
  if (unique.length === 1) return { status: 'attributed', scope, route: unique[0].decl };
  return { status: 'ambiguous', candidates: unique.map(r => r.decl) };
}

/**
 * Index a model's route `@flows` by file and by target asset.
 *
 * `assetKey` canonicalises asset refs for the asset fallback; pass the model's
 * canonicaliser so `#orders` and `Shop.Orders` meet. Defaults to `normalizeRef`.
 */
export function buildRouteIndex(
  flows: ThreatModelFlow[],
  assetKey: (ref: string) => string = normalizeRef,
): RouteIndex {
  const byFile = new Map<string, IndexedRoute[]>();
  const byAsset = new Map<string, IndexedRoute[]>();
  for (const f of flows) {
    const route = f.route ?? parseRouteChannel(f.mechanism);
    if (!route || !f.location?.file) continue;
    const entry: IndexedRoute = {
      decl: { method: route.method, path: route.path, file: f.location.file, line: f.location.line },
      scope: handlerScope(f.location),
    };
    const inFile = byFile.get(f.location.file);
    if (inFile) inFile.push(entry); else byFile.set(f.location.file, [entry]);
    if (f.target) {
      const key = assetKey(f.target);
      const intoAsset = byAsset.get(key);
      if (intoAsset) intoAsset.push(entry); else byAsset.set(key, [entry]);
    }
  }

  return {
    routeFor(asset, location) {
      const inFile = byFile.get(location.file) ?? [];
      if (inFile.length > 0) {
        const own = handlerScope(location);
        if (own) {
          // 1. Declared on this claim's handler, or on code enclosing it.
          const onHandler = inFile.filter(r => r.scope && scopeEncloses(r.scope, own));
          const answer = decide(onHandler, 'handler');
          if (answer) return answer;
        }
        // 2. Declared for the whole file.
        const fileLevel = decide(inFile.filter(r => !r.scope), 'file');
        if (fileLevel) return fileLevel;
        // 3. Only handler-level routes remain, and none is this claim's own.
        //    For a file-level claim the file's single route is the file's route.
        //    For a claim on another handler, every one of them is a guess.
        const rest = decide(inFile, 'file');
        if (own && rest?.status === 'attributed') return { status: 'ambiguous', candidates: [rest.route] };
        return rest;
      }
      // 4. The file declares no route: the asset's inbound route, if it has one.
      return decide(byAsset.get(assetKey(asset)) ?? [], 'asset');
    },
  };
}
