/**
 * The same method as a skill file, so a developer's own agent session can run
 * it without going through the CLI. `guardlink init` writes these under
 * `.claude/skills/`; the generated marker is how `sync` tells a file it wrote
 * from an authored file without that marker. Remove the marker to take ownership.
 *
 * @comment -- "Frontmatter is the two keys every skill loader reads (name, description); the body is the playbook verbatim plus how to invoke the CLI equivalent"
 */
import type { Playbook } from './types.js';
import { ANNOTATE_PLAYBOOKS } from './annotate.js';
import { REPORT_SHAPES } from './report.js';
import { TRANSLATE_GUIDE } from './translate.js';

export const SKILL_GENERATED_MARKER = '<!-- guardlink:generated -->';

export interface SkillFile {
  /** Repo-relative path. */
  path: string;
  content: string;
}

/** Translation is a workflow, not an annotate method or report shape. */
export function translateSkillFile(): SkillFile {
  return {
    path: '.claude/skills/guardlink-translate/SKILL.md',
    content: `---
name: guardlink-translate
description: Generate cxg scanner templates for an everyday code change, review them, then run selected tests separately. Use for per-change developer security checks or translating GuardLink exposures into tests.
---
${SKILL_GENERATED_MARKER}

# GuardLink translate

${TRANSLATE_GUIDE}
`,
  };
}

export function managedSkillFiles(): SkillFile[] {
  return [
    ...[...ANNOTATE_PLAYBOOKS, ...REPORT_SHAPES.filter(s => s.id !== 'full')].map(skillFileFor),
    translateSkillFile(),
  ];
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
