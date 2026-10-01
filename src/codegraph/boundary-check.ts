/**
 * GuardLink Code Graph — declared boundaries checked against what the graph measured.
 *
 * A `@boundary` is a claim: that trust changes between two sides, and, in its
 * description, what holds the line. Nothing used to check one. With a code graph
 * three parts of that claim can be compared with the code:
 *
 *   boundary-access-contradicted  the description says the inner side is behind
 *                                 a login (or an admin check), and a route on that
 *                                 side is classified below it — e.g. public
 *   boundary-access-unknown       the same claim, where the graph could not decide
 *                                 a route's level: reported unknown with its reason,
 *                                 never read as public or as authenticated
 *   boundary-missing              a route handler reaches a classified sink, and no
 *                                 asset its file names declares a boundary to the
 *                                 outside
 *   boundary-unused               no declared flow crosses a boundary and no entry
 *                                 point the graph recognises reaches either side
 *
 * Every one is a WARNING about the annotations, never a finding and never a
 * SARIF result: the graph's measurement disagrees with what a human wrote, and a
 * human decides which is wrong.
 *
 * WHICH SIDE IS INSIDE
 * `@boundary` is undirected. The outer side is inferred the way `guardlink paths`
 * infers entries: an endpoint the model does not declare as an asset is outside
 * the system, and so is a declared `External.*` asset. A boundary with exactly
 * one outer side has the other as its inner side; with two declared inner-looking
 * sides its direction is unknown and the access checks skip it rather than guess.
 *
 * WHICH ROUTES ARE ON A SIDE
 * A route belongs to an asset when its handler's file carries an annotation that
 * names the asset. That is the same file-level join the worklist's `[file]` state
 * uses, and it is deliberately coarse: a file naming two assets puts its routes on
 * both.
 *
 * THE GRAPH IS OPTIONAL
 * With no usable worklist this returns nothing, so a caller that runs it without a
 * graph prints exactly what it printed before. The access checks additionally
 * need the graph's `classified` auth verdict.
 *
 * @flows #codegraph -> #cli via checkBoundaries -- "Boundary diagnostics from the worklist and the parsed model, for validate --code-graph and guardlink_validate"
 * @comment -- "Pure over a parsed model and an already-loaded worklist: no process, no file, no network. The description is matched for a stated access level and quoted back, so a reader sees the exact word the check read"
 */
import type { ThreatModel, ThreatModelBoundary, ParseDiagnostic } from '../types/index.js';
import { canonicaliser } from '../parser/canonical-ref.js';
import { accessUsable, worklistUsable, type Worklist, type WorklistEntry, type RouteAccess } from './index.js';

/** How many routes one diagnostic names before it says how many more there are. */
const ROUTES_PER_DIAGNOSTIC = 5;

const LEVEL_RANK: Record<string, number> = { public: 0, authenticated: 1, elevated: 2 };

/** A description that says the line is open, or before login, states no access level. */
const OPEN_WORDS = /\b(un-?authenticated|anonymous|pre-?auth\w*|no (?:auth\w*|login)|without (?:auth\w*|login)|not (?:authenticated|logged[- ]in))\b/i;
const ELEVATED_WORDS = /\b(admin\w*|roles?|permissions?|privileg\w*|elevated|superuser)\b/i;
const AUTHENTICATED_WORDS = /\b(authenticat\w*|authori[sz]\w*|logged[- ]in|login|sign(?:ed)?[- ]in|api[- ]?keys?|bearer|jwt|oauth\w*|credentials?)\b/i;

export interface StatedAccess {
  level: 'authenticated' | 'elevated';
  /** The word the level was read from, quoted back in the diagnostic. */
  word: string;
}

/**
 * The access level a boundary's prose says its inner side requires, or null
 * when it states none. A heuristic over words, so the diagnostic always quotes
 * the word it matched.
 */
export function statedAccess(text: string): StatedAccess | null {
  if (!text || OPEN_WORDS.test(text)) return null;
  const elevated = ELEVATED_WORDS.exec(text);
  if (elevated) return { level: 'elevated', word: elevated[0] };
  const authenticated = AUTHENTICATED_WORDS.exec(text);
  if (authenticated) return { level: 'authenticated', word: authenticated[0] };
  return null;
}

const norm = (file: string): string => file.replace(/\\/g, '/').replace(/^\.\//, '');

/** `callee at file:line` → file. */
const exampleFile = (example: string): string | null => {
  const m = / at (.+):\d+$/.exec(example);
  return m ? norm(m[1]) : null;
};

function boundaryName(b: ThreatModelBoundary): string {
  return b.id ? `#${b.id}` : `the boundary between ${b.asset_a} and ${b.asset_b}`;
}

function routeWhere(e: WorklistEntry): string {
  return `${e.file}${e.line != null ? `:${e.line}` : ''} ${e.name}`.trim();
}

function listed(items: string[]): string {
  const shown = items.slice(0, ROUTES_PER_DIAGNOSTIC).join('; ');
  const more = items.length - ROUTES_PER_DIAGNOSTIC;
  return more > 0 ? `${shown}; and ${more} more` : shown;
}

/**
 * Compare every declared boundary with the code graph. Empty when the worklist
 * is not usable; the access checks also need the classified auth verdict.
 */
export function checkBoundaries(model: ThreatModel, w: Worklist | null | undefined): ParseDiagnostic[] {
  if (!w || !worklistUsable(w)) return [];
  const key = canonicaliser(model);
  const declared = new Map<string, string[]>();
  for (const a of model.assets ?? []) declared.set(key(a.id || a.path.join('.')), a.path);
  /** Outside the system: undeclared, or a declared External.* asset. */
  const isOuter = (k: string): boolean => {
    const path = declared.get(k);
    return !path || path[0]?.toLowerCase() === 'external';
  };

  // Which declared, inner-looking assets each file names. Flows are left out: a
  // flow line names both of its ends, and would put a file on both sides.
  const assetsByFile = new Map<string, Set<string>>();
  const note = (file: string, ref: string | undefined) => {
    if (!ref) return;
    const k = key(ref);
    if (!declared.has(k) || isOuter(k)) return;
    const f = norm(file);
    const set = assetsByFile.get(f) ?? new Set<string>();
    set.add(k);
    assetsByFile.set(f, set);
  };
  for (const r of model.exposures ?? []) note(r.location.file, r.asset);
  for (const r of model.mitigations ?? []) note(r.location.file, r.asset);
  for (const r of model.confirmed ?? []) note(r.location.file, r.asset);
  for (const r of model.data_handling ?? []) note(r.location.file, r.asset);
  for (const r of model.assumptions ?? []) note(r.location.file, r.asset);
  for (const r of model.audits ?? []) note(r.location.file, r.asset);
  for (const r of model.validations ?? []) note(r.location.file, r.asset);
  for (const r of model.ownership ?? []) note(r.location.file, r.asset);
  // A boundary to the outside is written where its inner side lives; one between
  // two inside assets says nothing about which of them this file is.
  for (const r of model.boundaries ?? []) {
    if (isOuter(key(r.asset_a))) note(r.location.file, r.asset_b);
    if (isOuter(key(r.asset_b))) note(r.location.file, r.asset_a);
  }

  const entriesOf = (asset: string): WorklistEntry[] =>
    w.entries.filter(e => assetsByFile.get(norm(e.file))?.has(asset));

  const diagnostics: ParseDiagnostic[] = [];
  const at = (b: ThreatModelBoundary) => ({ file: b.location.origin_file ?? b.location.file, line: b.location.origin_line ?? b.location.line });

  // ── Stated versus measured ──
  if (accessUsable(w)) {
    for (const b of model.boundaries ?? []) {
      const ka = key(b.asset_a);
      const kb = key(b.asset_b);
      const inner = isOuter(ka) && !isOuter(kb) ? kb : isOuter(kb) && !isOuter(ka) ? ka : null;
      if (!inner) continue;
      const assumptions = (model.assumptions ?? []).filter(a => key(a.asset) === inner).map(a => a.description ?? '');
      const stated = [b.description ?? '', ...assumptions].map(statedAccess).find(s => s !== null) ?? null;
      if (!stated) continue;
      const below: string[] = [];
      const unknown: string[] = [];
      for (const e of entriesOf(inner)) {
        for (const a of e.access) {
          if (a.level === 'unknown') unknown.push(`${a.route} (${routeWhere(e)}) is unknown: ${a.unknown_reason || 'no reason given'}`);
          else if ((LEVEL_RANK[a.level] ?? 0) < LEVEL_RANK[stated.level]) below.push(`${a.route} (${routeWhere(e)}) is ${describeLevel(a)}`);
        }
      }
      const claim = `${boundaryName(b)} says the ${key(b.asset_a) === inner ? b.asset_a : b.asset_b} side is ${stated.level} ("${stated.word}")`;
      if (below.length > 0) {
        diagnostics.push({
          level: 'warning', code: 'boundary-access-contradicted', ...at(b),
          message: `${claim}, but the code graph classifies ${below.length} route(s) there below that: ${listed(below)}. Either the boundary's description or the route's guard is wrong; this is a claim to verify, not a finding`,
        });
      }
      if (unknown.length > 0) {
        diagnostics.push({
          level: 'warning', code: 'boundary-access-unknown', ...at(b),
          message: `${claim}; the code graph could not decide ${unknown.length} route(s) there, so the claim is unchecked for them: ${listed(unknown)}`,
        });
      }
    }
  }

  // ── Missing crossing ──
  const hasOuterBoundary = new Set<string>();
  for (const b of model.boundaries ?? []) {
    const ka = key(b.asset_a);
    const kb = key(b.asset_b);
    if (isOuter(ka) && !isOuter(kb)) hasOuterBoundary.add(kb);
    if (isOuter(kb) && !isOuter(ka)) hasOuterBoundary.add(ka);
  }
  const missingByFile = new Map<string, { entries: WorklistEntry[]; assets: string[] }>();
  for (const e of w.entries) {
    if (e.routes.length === 0 || e.reaches.length === 0) continue;
    const assets = [...(assetsByFile.get(norm(e.file)) ?? [])];
    if (assets.length === 0 || assets.some(a => hasOuterBoundary.has(a))) continue;
    const slot = missingByFile.get(norm(e.file)) ?? { entries: [], assets };
    slot.entries.push(e);
    missingByFile.set(norm(e.file), slot);
  }
  for (const [file, { entries, assets }] of missingByFile) {
    const routes = entries.map(e => {
      const access = new Map(e.access.map(a => [a.route, a]));
      const tags = e.routes.map(r => (access.has(r) ? `${r} [${describeLevel(access.get(r)!)}]` : r)).join(', ');
      return `${tags} → ${e.name} reaches ${e.reaches.map(c => c.class).join(', ')}`;
    });
    diagnostics.push({
      level: 'warning', code: 'boundary-missing', file, line: entries[0].line ?? 1,
      message: `Route handler(s) here reach classified sinks, and no asset this file names (${assets.map(a => `#${a}`).join(', ')}) declares a @boundary to anything outside the model (a caller such as Client, or an External.* asset): ${listed(routes)}`,
    });
  }

  // ── Unused boundary ──
  const pair = (a: string, b: string) => [a, b].sort().join('\u0000');
  const flowPairs = new Set((model.flows ?? []).map(f => pair(key(f.source), key(f.target))));
  const reachedFiles = new Set<string>();
  for (const e of w.entries) {
    reachedFiles.add(norm(e.file));
    for (const c of e.reaches) {
      const f = exampleFile(c.example);
      if (f) reachedFiles.add(f);
    }
  }
  const reachedAssets = new Set<string>();
  for (const f of reachedFiles) for (const a of assetsByFile.get(f) ?? []) reachedAssets.add(a);
  for (const b of model.boundaries ?? []) {
    const ka = key(b.asset_a);
    const kb = key(b.asset_b);
    if (flowPairs.has(pair(ka, kb))) continue;
    if (reachedAssets.has(ka) || reachedAssets.has(kb)) continue;
    diagnostics.push({
      level: 'warning', code: 'boundary-unused', ...at(b),
      message: `${boundaryName(b)} has no declared @flows across it, and no entry point the code graph recognises reaches either side. It may be stale, or the traffic across it enters somewhere the graph does not recognise (a CLI command, a consumer, another framework) — add the @flows that crosses it, or remove it`,
    });
  }

  return diagnostics;
}

function describeLevel(a: RouteAccess): string {
  const why = a.level === 'unknown' ? a.unknown_reason : a.basis;
  return why ? `${a.level} (${why})` : a.level;
}

/** One stderr line saying what the graph contributed to the boundary checks. */
export function boundaryCheckSummaryLine(w: Worklist, diagnostics: ParseDiagnostic[]): string {
  if (w.status === 'off') return 'Boundary checks: code graph switched off';
  if (w.status !== 'available') return `Boundary checks: not run — ${w.note}`;
  if (!worklistUsable(w)) return `Boundary checks: not run — the code graph's worklist is withheld (${w.withheld_reason})`;
  const access = accessUsable(w) ? '' : `; stated-versus-measured access skipped (${w.access_withheld_reason || 'no access levels'})`;
  return `Boundary checks (code graph via ${w.via}): ${(w.entries.length)} entry point(s) read, ${diagnostics.length} warning(s)${access}`;
}
