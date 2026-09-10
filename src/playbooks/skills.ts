/**
 * The same method as a skill file, so a developer's own agent session can run
 * it without going through the CLI. `guardlink init` writes these under
 * `.claude/skills/`; the generated marker is how `sync` tells a file it wrote
 * from one a person edited.
 *
 * @comment -- "Frontmatter is the two keys every skill loader reads (name, description); the body is the playbook verbatim plus how to invoke the CLI equivalent"
 */
import type { Playbook } from './types.js';

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
