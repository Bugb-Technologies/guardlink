/**
 * GuardLink init — content preservation guards (D24).
 *
 * `--force` used to mean "overwrite everything", which included the one file in
 * a GuardLink repo that is entirely hand-written: the definitions file. During
 * Phase 4 that overwrote 38 declarations with the empty template, with no
 * warning and no prompt. The file happened to be committed; a repo where it was
 * not would have lost the threat model outright.
 *
 * The rule this module encodes: `--force` re-scaffolds, it does not destroy
 * authored content. A definitions file holding declarations the template does
 * not, and a `config.json` carrying settings the template does not, are user
 * work product. They survive `--force` and are reported as preserved. Genuine
 * overwrite intent is spelled `--reset`, which is its own confirmation.
 *
 * @exposes #init to #arbitrary-write [high] cwe:CWE-73 -- "Decides whether init may overwrite an existing definitions/config file"
 * @mitigates #init against #arbitrary-write using #config-validation -- "Overwrite refused when the target parses to declarations the template lacks; --reset required to override"
 * @flows DefinitionsFile -> #init via definitionsArePopulated -- "Existing declarations read to decide preservation"
 * @flows ConfigFile -> #init via configIsCustomised -- "Existing config compared against template defaults"
 * @comment -- "Fail-closed: an unreadable or unparseable existing file is treated as populated, never as empty"
 */

import { parseString } from '../parser/parse-file.js';

/**
 * Fields `init` is authoritative for. A difference in one of these is not
 * user configuration worth preserving — it is the identity/mode the run was
 * asked to write. Everything else in `config.json` (include, exclude, and any
 * key a user or a later feature added) counts as authored.
 *
 * `annotation_mode` is deliberately NOT here. A recorded mode that differs from
 * the one this run would write is exactly the case where silently rewriting the
 * file relocates every future annotation, so it counts as authored and the file
 * is preserved. Changing mode on an existing repo is `guardlink migrate --to`,
 * which does a preserving read-modify-write of that one key and moves the
 * annotations to match.
 */
const INIT_OWNED_CONFIG_KEYS = new Set(['version', 'project', 'language', 'definitions']);

/** Declaration verbs — the annotations that only ever live in a definitions file. */
const DECLARATION_VERBS = new Set(['asset', 'threat', 'control']);

/**
 * The declaration ids a definitions file declares, as `verb:id` pairs.
 *
 * `fileName` matters: it selects the comment-stripping rules, so a `.py`
 * definitions file is read as Python and a `.gal` one as raw annotation text.
 */
export function declarationIds(content: string, fileName: string): Set<string> {
  const ids = new Set<string>();
  for (const a of parseString(content, fileName).annotations) {
    if (!DECLARATION_VERBS.has(a.verb)) continue;
    const id = (a as { id?: string }).id;
    if (id) ids.add(`${a.verb}:${id}`);
  }
  return ids;
}

/**
 * Does the existing definitions file hold declarations the template does not?
 *
 * Compared against the template rather than against zero so the guard keeps
 * working if the template ever ships starter declarations of its own — the
 * question is "would overwriting lose something", not "is this file empty".
 */
export function definitionsArePopulated(
  existing: string,
  template: string,
  fileName: string,
): boolean {
  const templateIds = declarationIds(template, fileName);
  for (const id of declarationIds(existing, fileName)) {
    if (!templateIds.has(id)) return true;
  }
  return false;
}

/**
 * Does the existing config carry settings the template would not write?
 *
 * Unparseable JSON counts as customised: it is something a human typed that we
 * cannot read, which is the last content to overwrite silently.
 */
export function configIsCustomised(existing: string, template: string): boolean {
  let a: Record<string, unknown>;
  let b: Record<string, unknown>;
  try {
    a = JSON.parse(existing);
    b = JSON.parse(template);
  } catch {
    return true;
  }
  if (a === null || typeof a !== 'object' || Array.isArray(a)) return true;

  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  for (const key of keys) {
    if (INIT_OWNED_CONFIG_KEYS.has(key)) continue;
    if (JSON.stringify(a[key]) !== JSON.stringify(b[key])) return true;
  }
  return false;
}
