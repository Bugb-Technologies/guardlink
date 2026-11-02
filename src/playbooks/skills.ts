/**
 * The same method as a skill file, so a developer's own agent session can run
 * it without going through the CLI. `guardlink init` writes these under
 * `.claude/skills/`; the generated marker is how `sync` tells a file it wrote
 * from one a person edited.
 *
 * @comment -- "Frontmatter is the two keys every skill loader reads (name, description); the body is the playbook verbatim plus how to invoke the CLI equivalent"
 */
import type { Playbook } from './types.js';
import { TRANSLATE_HEADER, TRANSLATE_METHOD_A, TRANSLATE_METHOD_B } from './translate.js';

export const SKILL_GENERATED_MARKER = '<!-- guardlink:generated -->';

export interface SkillFile {
  /** Repo-relative path. */
  path: string;
  content: string;
}

export function skillNameFor(pb: Playbook): string {
  return `guardlink-${pb.kind}-${pb.id}`;
}

export function skillFileFor(pb: Playbook): SkillFile {
  const name = skillNameFor(pb);
  const invoke = pb.kind === 'annotate'
    ? `\`guardlink annotate --playbook ${pb.id} "<scope>"\` runs this method through the CLI with the gate; in a session, follow it directly, then run \`guardlink lint . --since HEAD\` before you finish.`
    : `\`guardlink threat-report <framework> --shape ${pb.id}\` produces this shape through the CLI; in a session, apply it on top of the framework you are asked for.`;
  const description = `${pb.summary} Use when asked to ${pb.kind === 'annotate' ? 'annotate' : 'report on'} a GuardLink threat model this way.`;
  const content = `---
name: ${name}
description: ${description.replace(/\n/g, ' ')}
---
${SKILL_GENERATED_MARKER}

# ${pb.title} (${pb.kind})

${pb.summary}

${invoke}

${pb.body.trim()}
`;
  return { path: `.claude/skills/${name}/SKILL.md`, content };
}

/**
 * The generated `guardlink-translate` skill: the same method `guardlink translate`
 * runs, so an agent in a session follows it directly instead of launching a child
 * agent through the CLI launcher. The method is the shared text in
 * `./translate.ts`; the per-run threat model and the CXG skeleton excerpts the
 * CLI bakes in are fetched by the agent instead, so the file carries no live data.
 *
 * @comment -- "One fixed skill, not per-playbook: translate has a single method. Body is TRANSLATE_HEADER + METHOD_A + METHOD_B verbatim, with a live-model note replacing the per-run summary and a skeleton-discovery line in place of the baked-in excerpts"
 */
export function translateSkillFile(): SkillFile {
  const name = 'guardlink-translate';
  const summary = 'Translate GuardLink threat-model findings into CERT-X-GEN (CXG) pentest templates. Generation only — never execute a template.';
  const description = `${summary} Use when asked to translate threats into CXG templates or author pentest templates from the threat model.`;
  const invoke = 'In a session, follow this directly; `guardlink translate --stdout` prints the same prompt with live data.';

  // The agent fetches what the CLI would otherwise bake in: the per-run model
  // summary and the CXG skeleton excerpts.
  const liveModel = `## Current Threat Model
This method needs the project's live threat model — fetch it yourself, do not work from a copy:
- \`guardlink lookup unmitigated\` (or the \`guardlink_lookup\` MCP tool with \`unmitigated\`) for the open exposures to write templates for.
- \`guardlink parse\` (or \`guardlink_parse\`) for the full model.
The user's request for this run is the scope: translate the pentest-confirmable exposures it points at.`;
  const skeletonDiscovery = 'Discover the skeleton on this machine: `cxg template --help`, and the skeleton files under the CXG templates directory (`~/.cert-x-gen/templates/official/templates/skeleton/`, or `$GUARDLINK_CXG_ROOT`). `guardlink translate --stdout` prints this same method with those excerpts embedded inline.';

  const body = `${TRANSLATE_HEADER}${liveModel}

${TRANSLATE_METHOD_A} ${skeletonDiscovery}

${TRANSLATE_METHOD_B}`;

  const content = `---
name: ${name}
description: ${description.replace(/\n/g, ' ')}
---
${SKILL_GENERATED_MARKER}

# Translate (translate)

${summary}

${invoke}

${body.trim()}
`;
  return { path: `.claude/skills/${name}/SKILL.md`, content };
}
