/**
 * GuardLink Suggest — Annotation suggestion engine.
 *
 * Analyzes code for patterns that warrant security annotations:
 *   - Function names suggesting security-relevant operations
 *   - Dangerous imports/patterns (eval, exec, SQL, file I/O, crypto)
 *   - HTTP handlers, auth checks, input parsing
 *   - Missing annotations on files that handle sensitive data
 *
 * Designed for both file-based and diff-based analysis (§8.2).
 *
 */

import { readFileSync, existsSync } from 'node:fs';
import { join, extname } from 'node:path';
import type { ThreatModel } from '../types/index.js';

export interface SuggestOptions {
  root: string;
  model: ThreatModel;
  file?: string;     // Analyze specific file
  diff?: string;     // Analyze git diff text
}

export interface Suggestion {
  file: string;
  line?: number;
  annotation: string;        // The annotation text to add
  reason: string;             // Why this annotation is suggested
  confidence: 'high' | 'medium' | 'low';
  category: string;           // 'exposure' | 'mitigation' | 'asset' | 'flow' | 'data_handling'
}

export async function suggestAnnotations(opts: SuggestOptions): Promise<Suggestion[]> {
  const suggestions: Suggestion[] = [];

  if (opts.diff) {
    suggestFromDiff(opts.diff, opts.model, suggestions);
  } else if (opts.file) {
    const fullPath = join(opts.root, opts.file);
    if (existsSync(fullPath)) {
      const content = readFileSync(fullPath, 'utf-8');
      suggestFromFile(opts.file, content, opts.model, suggestions);
    }
  }

  // Deduplicate and sort by confidence
  const seen = new Set<string>();
  const confOrder = { high: 0, medium: 1, low: 2 };
  return suggestions
    .filter(s => {
      const key = `${s.file}:${s.line}:${s.annotation}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .sort((a, b) => confOrder[a.confidence] - confOrder[b.confidence]);
}

// ─── Pattern definitions ─────────────────────────────────────────────

interface CodePattern {
  regex: RegExp;
  category: string;
  annotation: (match: RegExpMatchArray, file: string) => string;
  reason: string;
  confidence: 'high' | 'medium' | 'low';
}

const PATTERNS: CodePattern[] = [
  // SQL / database
  {
    regex: /(?:execute|query|raw_sql|cursor\.execute|\.query\(|knex\.|sequelize\.|prisma\.)\s*\(/i,
    category: 'exposure',
    annotation: (_m, f) => `@exposes ${assetFromFile(f)} to #sqli with Insufficient input validation`,
    reason: 'Database query detected — potential SQL injection if inputs are not parameterized',
    confidence: 'high',
  },
  // Command execution
  {
    regex: /(?:exec|spawn|execSync|child_process|subprocess|os\.system|os\.popen|Runtime\.exec)\s*\(/i,
    category: 'exposure',
    annotation: (_m, f) => `@exposes ${assetFromFile(f)} to #cmd-injection with Unsanitized command arguments`,
    reason: 'Command execution detected — potential command injection',
    confidence: 'high',
  },
  // File I/O with user input
  {
    regex: /(?:readFile|writeFile|open\(|fopen|fs\.read|Path\.resolve|path\.join).*(?:req\.|request\.|params|query|body)/i,
    category: 'exposure',
    annotation: (_m, f) => `@exposes ${assetFromFile(f)} to #path-traversal with User-controlled file path`,
    reason: 'File operation with user-influenced path — potential path traversal',
    confidence: 'high',
  },
  // eval / dynamic code
  {
    regex: /(?:eval\(|new\s+Function\(|exec\(|compile\(|setInterval\(|setTimeout\().*(?:req|input|user|param|body)/i,
    category: 'exposure',
    annotation: (_m, f) => `@exposes ${assetFromFile(f)} to #code-injection with Dynamic code execution`,
    reason: 'Dynamic code execution with potential user input',
    confidence: 'high',
  },
  // Auth/login handlers
  {
    regex: /(?:def\s+login|function\s+login|authenticate|verify_password|check_credentials|signIn)/i,
    category: 'asset',
    annotation: (_m, f) => `@asset ${assetFromFile(f)} -- "Authentication handler"`,
    reason: 'Authentication-related function — should be declared as security-relevant asset',
    confidence: 'medium',
  },
  // Input validation / sanitization
  {
    regex: /(?:sanitize|validate|escape|htmlEscape|xss|dompurify|bleach|strip_tags)/i,
    category: 'mitigation',
    annotation: (_m, f) => `@control Input_Validation (#input-validation) -- "Sanitizes user input"`,
    reason: 'Input validation/sanitization detected — should be documented as a control',
    confidence: 'medium',
  },
  // CORS configuration
  {
    regex: /(?:cors|Access-Control-Allow-Origin|allowed_origins)/i,
    category: 'mitigation',
    annotation: (_m, f) => `@control CORS_Policy (#cors-policy) -- "Restricts cross-origin requests"`,
    reason: 'CORS configuration detected',
    confidence: 'medium',
  },
  // Rate limiting
  {
    regex: /(?:rate.?limit|throttle|RateLimiter|express-rate-limit|slowapi)/i,
    category: 'mitigation',
    annotation: (_m, f) => `@control Rate_Limiting (#rate-limit) -- "Limits request frequency"`,
    reason: 'Rate limiting detected',
    confidence: 'medium',
  },
  // Crypto / hashing
  {
    regex: /(?:bcrypt|scrypt|argon2|pbkdf2|hashlib|crypto\.createHash|md5|sha256)/i,
    category: 'mitigation',
    annotation: (_m, f) => `@control Crypto_Hashing (#crypto-hash) -- "Cryptographic hashing for sensitive data"`,
    reason: 'Cryptographic hashing detected',
    confidence: 'medium',
  },
  // HTTP handlers
  {
    regex: /(?:@app\.(?:get|post|put|delete|patch)|router\.(?:get|post|put|delete)|@GetMapping|@PostMapping|@RequestMapping)/i,
    category: 'flow',
    annotation: (_m, f) => `@handles ${assetFromFile(f)} -- "HTTP request handler"`,
    reason: 'HTTP endpoint handler — represents an entry point for user data',
    confidence: 'medium',
  },
  // Secrets / credentials
  {
    regex: /(?:API_KEY|SECRET_KEY|PASSWORD|TOKEN|PRIVATE_KEY|AWS_ACCESS|DATABASE_URL)\s*[=:]/i,
    category: 'data_handling',
    annotation: (_m, f) => `@data ${assetFromFile(f)} stores secrets -- "Contains credentials or API keys"`,
    reason: 'Hardcoded secret or credential reference detected',
    confidence: 'high',
  },
  // Deserialization
  {
    regex: /(?:pickle\.load|yaml\.load\(|yaml\.unsafe_load|JSON\.parse|deserialize|unmarshal|ObjectInputStream)/i,
    category: 'exposure',
    annotation: (_m, f) => `@exposes ${assetFromFile(f)} to #unsafe-deser with Deserialization of untrusted data`,
    reason: 'Deserialization detected — potential unsafe deserialization if input is untrusted',
    confidence: 'medium',
  },
  // SSRF patterns
  {
    regex: /(?:fetch|requests\.get|urllib|http\.get|axios|HttpClient).*(?:req\.|request\.|params|query|body|url)/i,
    category: 'exposure',
    annotation: (_m, f) => `@exposes ${assetFromFile(f)} to #ssrf with User-controlled URL`,
    reason: 'HTTP request with user-influenced URL — potential SSRF',
    confidence: 'medium',
  },
  // Template rendering (XSS)
  {
    regex: /(?:render_template|innerHTML|dangerouslySetInnerHTML|v-html|ng-bind-html|\|safe\b|mark_safe)/i,
    category: 'exposure',
    annotation: (_m, f) => `@exposes ${assetFromFile(f)} to #xss with Unescaped output rendering`,
    reason: 'Unsafe HTML rendering detected — potential XSS',
    confidence: 'high',
  },
];

// ─── File analysis ───────────────────────────────────────────────────

function suggestFromFile(
  file: string, content: string, model: ThreatModel, out: Suggestion[],
): void {
  // Skip definition files and non-source
  if (file.includes('.guardlink/') || file.includes('node_modules/')) return;

  const lines = content.split('\n');

  // Check if file already has annotations
  const hasAnnotations = lines.some(l => /@(?:asset|threat|control|exposes|mitigates|accepts|flows|boundary|handles|comment|data|shield)\b/.test(l));

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pattern of PATTERNS) {
      const match = line.match(pattern.regex);
      if (match) {
        out.push({
          file,
          line: i + 1,
          annotation: pattern.annotation(match, file),
          reason: pattern.reason,
          confidence: hasAnnotations ? pattern.confidence : lowerConfidence(pattern.confidence),
          category: pattern.category,
        });
      }
    }
  }

  // Post-pass: suggest @comment on security-relevant functions with no nearby annotations or suggestions
  const FUNC_RE = /(?:(?:export\s+)?(?:async\s+)?function\s+(\w+)|(?:export\s+)?class\s+(\w+)|def\s+(\w+)|fn\s+(\w+)|func\s+(\w+))/i;
  const SEC_KEYWORDS = /auth|login|cred|token|secret|password|session|crypto|encrypt|decrypt|hash|key|cert|ssl|tls|api|admin|pay|billing|charge|invoice/i;
  const suggestedLines = new Set(out.map(s => s.line));

  for (let i = 0; i < lines.length; i++) {
    const funcMatch = lines[i].match(FUNC_RE);
    if (!funcMatch) continue;
    const funcName = funcMatch[1] || funcMatch[2] || funcMatch[3] || funcMatch[4] || funcMatch[5];
    const lineNum = i + 1;

    // Skip if already has a suggestion or annotation within 3 lines above
    const hasNearby = Array.from({ length: 4 }, (_, k) => lineNum - k).some(ln =>
      suggestedLines.has(ln) || (ln > 0 && ln <= lines.length && /@\w+/.test(lines[ln - 1]))
    );
    if (hasNearby) continue;

    // Only suggest for functions with security-relevant names or in security-relevant file paths
    if (SEC_KEYWORDS.test(funcName) || SEC_KEYWORDS.test(file)) {
      out.push({
        file,
        line: lineNum,
        annotation: `@comment -- "TODO: Document security relevance of ${funcName}"`,
        reason: `Security-relevant function '${funcName}' has no annotation — add at least @comment`,
        confidence: 'low',
        category: 'asset',
      });
    }
  }
}

// ─── Diff analysis ───────────────────────────────────────────────────

function suggestFromDiff(
  diff: string, model: ThreatModel, out: Suggestion[],
): void {
  // Parse unified diff format
  let currentFile = '';
  let lineNum = 0;

  for (const line of diff.split('\n')) {
    // File header: +++ b/path/to/file.ts
    const fileMatch = line.match(/^\+\+\+\s+b\/(.+)/);
    if (fileMatch) {
      currentFile = fileMatch[1];
      continue;
    }

    // Hunk header: @@ -old,count +new,count @@
    const hunkMatch = line.match(/^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@/);
    if (hunkMatch) {
      lineNum = parseInt(hunkMatch[1], 10);
      continue;
    }

    // Added lines (+ prefix)
    if (line.startsWith('+') && !line.startsWith('+++')) {
      const content = line.slice(1);
      for (const pattern of PATTERNS) {
        const match = content.match(pattern.regex);
        if (match) {
          out.push({
            file: currentFile,
            line: lineNum,
            annotation: pattern.annotation(match, currentFile),
            reason: `[New code] ${pattern.reason}`,
            confidence: pattern.confidence,
            category: pattern.category,
          });
        }
      }
      lineNum++;
    } else if (!line.startsWith('-')) {
      // Context line (no prefix) — increment line counter
      lineNum++;
    }
    // Removed lines (- prefix) — don't increment
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────

function assetFromFile(file: string): string {
  // Convert file path to a reasonable asset name suggestion
  const base = file
    .replace(/\.[^.]+$/, '')           // Remove extension
    .replace(/^src\/|^lib\/|^app\//, '') // Strip common prefixes
    .replace(/\//g, '.');              // Dots for path segments
  return base.split('.').map(s => s.charAt(0).toUpperCase() + s.slice(1)).join('.');
}

function lowerConfidence(c: 'high' | 'medium' | 'low'): 'high' | 'medium' | 'low' {
  if (c === 'high') return 'medium';
  return 'low';
}
