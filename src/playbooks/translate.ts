import { DEFAULT_SECURITY_TESTS_DIR } from '../parser/security-tests.js';

/** Developer workflow shared by the standalone skill and translation prompt. */
export function buildTranslateGuide(securityTestsDir = DEFAULT_SECURITY_TESTS_DIR): string {
  return `## Developer check — generate, then run
Use a fast, per-change annotate → translate → test → fix cycle for everyday developer testing. GuardLink + cxg can support scoped checks without Bravos; Bravos template authoring remains the tested authoring path, so inspect and validate standalone output against the installed cxg. A quick check is not a full pentest. For specialized, annotation-guided deep verification, \`bravos auto\` provides low-friction setup and real traffic; runs can take hours.

1. Keep code and its annotations current in the same change, including after each test/fix round. Run \`guardlink validate .\` and \`guardlink lint . --since <base>\`.
2. Request \`guardlink_translate\` with the changed paths and threats, or run \`guardlink translate --stdout "<changed paths and threats>"\` without MCP; both return the prompt for you, the calling agent. A bare \`guardlink translate\` (or \`--headless --agent\`) launches a separate authoring agent instead. Translation defaults to polyglot scanner templates; \`--contract probe\` selects JavaScript probes. Both are generation-only: no scan, test execution or runtime confirmation. There is no translate \`--since\` flag; scope the request explicitly (or use the CLI's \`--feature\` filter).
3. Author templates under \`.guardlink/cxg-templates/\` and an index mapping exposures to files, including audit-only items and gaps. Preserve unrelated templates and authored tests. Review the index against the requested change, inspect the generated code, and validate templates with the installed cxg template commands discovered through help.
4. Execute the selected tests separately with \`cxg scan\` or the repository's configured runner, using its actual scope and target options. Scanner templates are distinct from browser pentest probes. Save cxg findings under \`.guardlink/pentest-findings/\`. Record what ran, evidence, failures, skips and prerequisites; generated files alone prove no behavior.
5. Retain useful regression tests in the repository's durable suite. Generated templates under \`.guardlink/cxg-templates/\` do not automatically become curated tests in \`${securityTestsDir}/\`. Keep the regression after a fix: a mitigation can remove an exposure from translation's candidate list. Before opening or updating a pull request, run the entire configured \`${securityTestsDir}/\` suite (\`security_tests_dir\` in \`.guardlink/config.json\`, default \`security\`) with its configured runner. A pre-review tool's recorded complete execution satisfies this once. Report absent suites as not applicable and skipped, partial or unavailable execution as incomplete, never a pass. For live regressions, you may start a target and use already configured auth profiles: tell the user when doing so, and never fabricate credentials or authorization.

Generation is complete when the requested scope is accounted for in the template index or explicit gaps. Execution is a separate result with its own evidence and coverage.`;
}

export const TRANSLATE_GUIDE = buildTranslateGuide();
