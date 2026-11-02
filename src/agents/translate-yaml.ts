/**
 * Read-only scanner-template validation; never loads a template into its execution engine.
 * @exposes #agent-launcher to #insecure-deser [medium] -- "validateScannerYaml parses files written by the author agent"
 * @mitigates #agent-launcher against #insecure-deser using #config-validation -- "Bounded YAML parsing plus explicit AuthorInfo shape check precede the CXG schema validator"
 * @exposes #agent-launcher to #child-proc-injection [high] -- "validateScannerYaml invokes the installed cxg template validator"
 * @mitigates #agent-launcher against #child-proc-injection using #param-commands -- "Fixed cxg binary and template validate subcommand, absolute file path as argv, no shell and update checks disabled"
 * @flows AgentProcess -> #agent-launcher via validateScannerYaml -- "Author-written YAML is parsed and schema-checked as data, never executed"
 * @effects execute on #agent-launcher -- "Runs cxg template validate only, bounded to 30 seconds and 1 MiB of output; never scans or executes a template"
 * @audit #agent-launcher -- "The installed cxg executable is operator-trusted; schema checks do not prove the detection logic"
 */
import { spawnSync } from 'node:child_process';
import { readFileSync, statSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parseDocument } from 'yaml';

export function validateScannerYaml(file: string): string[] {
  let validatorHome: string | undefined;
  try {
    if (statSync(file).size > 2 * 1024 * 1024) return ['YAML template exceeds 2 MiB'];
    const doc = parseDocument(readFileSync(file, 'utf8'));
    if (doc.errors.length) return doc.errors.map(e => `Invalid YAML: ${e.message}`);
    const value = doc.toJS({ maxAliasCount: 100 });
    const author = value?.author;
    if (!author || typeof author !== 'object' || Array.isArray(author) || typeof author.name !== 'string' || !author.name.trim()) {
      return ['author must be an AuthorInfo object/mapping with a nonempty name string, never a scalar'];
    }
    for (const key of ['email', 'github']) {
      if (author[key] != null && typeof author[key] !== 'string') return [`author.${key} must be a string or null`];
    }
    for (const request of value?.http || []) {
      for (const path of request?.path || []) {
        if (typeof path === 'string' && (/\{\{.*?\}\}/.test(path) || !path.startsWith('/') || path.startsWith('//'))) {
          return ['Use relative HTTP paths with concrete parameters; unresolved placeholders (including BaseURL/RootURL) are not portable scanner requests'];
        }
      }
    }
    validatorHome = mkdtempSync(join(tmpdir(), 'guardlink-cxg-validate-'));
    const result = spawnSync('cxg', ['template', 'validate', resolve(file), '--json', '--disable-update-check'], {
      encoding: 'utf8', shell: false, timeout: 30000, maxBuffer: 1024 * 1024,
      // Older validators persist updater preferences even for template validate.
      // This is the child's actual home, not a change to the parent environment.
      env: { ...process.env, CERT_X_GEN_HOME: validatorHome, HOME: validatorHome, USERPROFILE: validatorHome },
    });
    if (result.error) return [`Cannot validate scanner YAML with cxg: ${result.error.message}`];
    if (result.status !== 0) return [`cxg template validate failed (${result.signal || result.status}): ${(result.stderr || result.stdout).slice(-2000)}`];
    // Some installed versions prefix --json output with a banner and progress lines.
    const start = result.stdout.search(/^\[\s*\{/m);
    const end = result.stdout.lastIndexOf(']');
    if (start < 0 || end < start) return ['cxg template validate returned no JSON validation result'];
    const rows: unknown = JSON.parse(result.stdout.slice(start, end + 1));
    if (!Array.isArray(rows) || rows.length !== 1) return ['cxg template validate returned an unexpected result count'];
    const row = rows[0];
    if (row?.passed !== true || row?.error || row?.diagnostics?.some((d: any) => d.severity === 'error')) {
      return [row?.error || row?.diagnostics?.filter((d: any) => d.severity === 'error').map((d: any) => d.message).join('; ') || 'CXG schema validation did not pass'];
    }
    return [];
  } catch (error) {
    return [`Invalid scanner YAML: ${(error as Error).message}`];
  } finally { if (validatorHome) rmSync(validatorHome, { recursive: true, force: true }); }
}
