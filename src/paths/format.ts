/**
 * GuardLink Paths — human-readable output formatter.
 *
 * @comment -- "Pure string formatting; no I/O. Every hop prints its file:line because a path that cannot be walked in an editor is an assertion rather than a finding, and the empty case states which kind of empty it is — no undefended route in the annotated graph is not the same claim as no undefended route in the code"
 */

import type { PathFinding, EndpointClassification } from './index.js';

/** `UserInput --req.body--> #api --writeFileSync--> FileSystem` */
function renderChain(finding: PathFinding): string {
  const parts: string[] = [finding.chain[0]];
  finding.hops.forEach((hop, i) => {
    parts.push(hop.via.label ? `--${hop.via.label}-->` : '-->');
    parts.push(finding.chain[i + 1]);
  });
  return parts.join(' ');
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

export function formatPaths(
  findings: PathFinding[],
  endpoints: EndpointClassification,
  opts: { includeMitigated?: boolean } = {},
): string {
  const lines: string[] = [];

  lines.push(
    `Flow graph: ${plural(endpoints.entries.length, 'entry', 'entries')}, ` +
    `${plural(endpoints.exits.length, 'exit', 'exits')}`,
  );
  lines.push('');

  if (findings.length === 0) {
    lines.push(opts.includeMitigated
      ? 'No source-to-sink paths run through a declared asset.'
      : 'No unmitigated source-to-sink paths found.');
    lines.push('');
    lines.push('This is derived from @flows and @mitigates annotations, not from reading code.');
    lines.push('An empty result means the annotated graph holds no undefended route —');
    lines.push('not that none exists. Add @flows where data moves to widen the search.');
    return lines.join('\n');
  }

  lines.push(`${plural(findings.length, 'path', 'paths')} from an entry point to a sink, through a declared asset`);
  const crossing = findings.filter(f => f.crossesBoundary).length;
  if (crossing > 0) lines.push(`${crossing} of them cross a declared trust boundary`);
  lines.push('');

  findings.forEach((finding, i) => {
    const tags: string[] = [];
    if (finding.crossesBoundary) tags.push(`crosses ${finding.boundariesCrossed.join(', ')}`);
    if (finding.mitigated) tags.push(`mitigated by ${finding.controlsOnPath.join(', ')}`);

    lines.push(`${i + 1}. ${renderChain(finding)}`);
    if (tags.length > 0) lines.push(`   ${tags.join('  |  ')}`);
    for (const hop of finding.hops) lines.push(`     ${hop.via.file}:${hop.via.line}`);
    lines.push('');
  });

  lines.push('Each hop above is an existing @flows annotation. Nothing here was inferred by a model.');
  if (!opts.includeMitigated) {
    lines.push('Paths already covered by a control are hidden — pass --all to include them.');
  }

  return lines.join('\n');
}
