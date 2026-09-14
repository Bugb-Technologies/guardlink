/**
 * GuardLink Workspace — whose `#listing` is this? (mark 8)
 *
 * `combineModels` concatenates N repositories into one `ThreatModel`, and at
 * that moment two teams' independently declared `#listing` become the same
 * string. The coverage join is `(asset, threat)` on strings, so a `@mitigates`
 * written against one team's asset silently answered for the other team's —
 * measured on a four-repo estate as
 *
 *     1 mitigations | 2 exposures | 0 unmitigated          ← wrong
 *     ⚠ Tag "listing" defined in orders-api (owner) and also in: billing-api
 *
 * Two teams exposed, one control, nothing reported open. The warning was right;
 * the count was not. `tag_registry` already resolved an `owner_repo` for every
 * tag and the join simply never asked.
 *
 * This module turns that ownership into the namespace `buildCoverageIndex`
 * needs: two relations may only join when their asset resolves to the same
 * repository's declaration of it.
 *
 * ── Assets only, and why not threats ────────────────────────────────
 *
 * A colliding ASSET id means two different things: `#listing` in orders-api is
 * a different endpoint from `#listing` in billing-api, and a control over one
 * does not reach the other.
 *
 * A colliding THREAT id means the same thing twice. A shared weakness
 * vocabulary is the normal and healthy shape of an estate — every repository's
 * `.guardlink/definitions` declaring `#sqli` is two teams agreeing, not two
 * teams colliding. Scoping that dimension too would re-open a cross-repo
 * finding for every repository that declares the standard taxonomy locally,
 * which is a flood with no defect behind it. Controls never enter the join at
 * all.
 *
 * So the narrowing is one dimension wide, deliberately.
 *
 * ── A collision is a DISAGREEMENT, not a repeated id ────────────────
 *
 * Two repositories both declaring `#listing` is not by itself a collision, and
 * treating it as one was wrong in a way that only showed up against a realistic
 * estate. A platform team that ships a single `definitions.ts` into every
 * repository — which is a normal way to run one, and what
 * `tests/merge-verdict.test.ts` scaffolds — makes EVERY asset "defined in" N
 * repos while meaning exactly one thing. Scoping on `also_defined_in` alone cut
 * every legitimate cross-repo join in such a workspace: the control in
 * platform-authz stopped covering the exposure in orders-api, and the estate
 * grew findings nobody had introduced.
 *
 * That is the same mistake in the opposite direction from mark 8 — an invented
 * finding rather than a silenced one — and it is exactly the argument made just
 * above about threats, which applies to any tag declared identically wherever it
 * is declared. So the registry records whether the definers actually DISAGREE
 * (`definitions_differ`, from the declared path and description), and only a
 * genuine disagreement narrows anything.
 *
 * ── It can only re-open, never hide ─────────────────────────────────
 *
 * Like the anchor rule in `parser/coverage.ts`, this starts from the pair match
 * the old key computed and only ever subtracts: a scope that fires splits one
 * bucket into two and a relation can lose coverage, never gain it. A tag with
 * one definer, or none, scopes to the empty namespace and joins exactly as it
 * did before — which is every tag in every single-repository model, and why
 * nothing outside `merge` passes this.
 *
 * @flows TagRegistry -> #merge-engine via buildOwnerScope -- "Recorded tag ownership becomes the namespace the coverage join is scoped by"
 * @comment -- "Reads also_defined_in and definitions_differ, so a merged report written before those fields existed scopes to nothing and answers exactly as the build that wrote it did"
 * @comment -- "A tag declared identically in every repo that declares it is one shared vocabulary, not a collision: scoping it would invent a finding in every workspace that ships one definitions file to all repos"
 */

import type { SitedRelation } from '../parser/coverage.js';
import { normalizeRef } from '../parser/coverage.js';
import type { TagOwnership } from './types.js';

/** A relation's namespace for the coverage join. `''` means "unambiguous". */
export type OwnerScope = (r: SitedRelation) => string;

/** The scope every single-repository model uses: none. */
export const NO_OWNER_SCOPE: OwnerScope = () => '';

/**
 * Which repository a record in a COMBINED model came from.
 *
 * `prefixLocation` guarantees every path in a combined model is
 * `<repo>/<path-as-written>`, so the first segment is the repo — but only if it
 * names one we know. An unrecognised prefix returns null and the relation falls
 * back to owner resolution, which is the conservative direction: it joins with
 * the owner's records rather than being split into a namespace of its own.
 */
export function repoOfPath(file: string | undefined, repoNames: ReadonlySet<string>): string | null {
  if (!file) return null;
  const first = file.replaceAll('\\', '/').split('/')[0];
  return repoNames.has(first) ? first : null;
}

/**
 * Build the asset-ownership scope for a combined model.
 *
 * @param registry     the merged report's `tag_registry`, carrying `also_defined_in`
 * @param repoNames    every repo in the merge, for reading the path prefix
 * @param assetKey     the combined model's canonicaliser, so `Svc.Listing` and
 *                     `#listing` resolve to one key exactly as coverage does
 */
export function buildOwnerScope(
  registry: readonly TagOwnership[],
  repoNames: ReadonlySet<string>,
  assetKey: (ref: string) => string = normalizeRef,
): OwnerScope {
  /** canonical asset key → every repo that declares it, owner first. */
  const definers = new Map<string, string[]>();

  for (const entry of registry) {
    if (entry.kind !== 'asset') continue;
    const others = entry.also_defined_in ?? [];
    if (others.length === 0) continue; // unambiguous — never scoped
    // Declared identically everywhere it is declared: one shared vocabulary
    // distributed across the estate, not two teams colliding. Scoping it would
    // cut every legitimate cross-repo join in any workspace that ships one
    // definitions file to every repo — which is a normal way to run an estate,
    // and is what `tests/merge-verdict.test.ts` scaffolds. A report written
    // before this field carries `undefined` and is left unscoped for the same
    // reason `also_defined_in`'s absence is: never invent a collision.
    if (entry.definitions_differ !== true) continue;
    const key = assetKey(entry.tag);
    const seen = definers.get(key) ?? [];
    for (const repo of [entry.owner_repo, ...others]) {
      if (!seen.includes(repo)) seen.push(repo);
    }
    definers.set(key, seen);
  }

  if (definers.size === 0) return NO_OWNER_SCOPE;

  return (r: SitedRelation): string => {
    const key = assetKey(r.asset);
    const repos = definers.get(key);
    if (!repos) return '';
    // A repo that declares the tag itself means its OWN asset. Anything else —
    // the sibling repo where the control lives — means the owner's.
    const here = repoOfPath(r.location?.file, repoNames);
    return here && repos.includes(here) ? here : repos[0];
  };
}

/** True when this scope actually narrows anything. */
export function scopeIsActive(scope: OwnerScope): boolean {
  return scope !== NO_OWNER_SCOPE;
}
