/**
 * GuardLink init — Project detection utilities.
 * Detects language, project name, and existing agent instruction files.
 */

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, basename } from 'node:path';

// ─── Types ───────────────────────────────────────────────────────────

export type ProjectLanguage =
  | 'typescript' | 'javascript' | 'python' | 'go' | 'rust'
  | 'java' | 'csharp' | 'ruby' | 'swift' | 'kotlin'
  | 'terraform' | 'unknown';

export interface AgentFile {
  /** Relative path from project root */
  path: string;
  /** Agent platform: claude, cursor, codex, copilot, windsurf, cline, gemini, generic */
  platform: string;
  /** Whether the file already exists */
  exists: boolean;
  /** Whether it already contains GuardLink instructions */
  hasGuardLink: boolean;
  /** Whether the agent's directory exists (e.g. .cursor/, .claude/) even if instruction file doesn't */
  dirDetected: boolean;
  /** The directory hint that was detected, if any */
  dirHint?: string;
}

export interface ProjectInfo {
  /** Project root directory */
  root: string;
  /** Detected project name */
  name: string;
  /** Primary language */
  language: ProjectLanguage;
  /** Comment prefix for the primary language */
  commentPrefix: string;
  /** File extension for definitions file */
  definitionsExt: string;
  /** Detected agent instruction files */
  agentFiles: AgentFile[];
  /** Whether .guardlink/ already exists */
  alreadyInitialized: boolean;
}

// ─── Agent file locations ────────────────────────────────────────────

const AGENT_FILE_SPECS: Array<{ path: string; platform: string; dirHint?: string }> = [
  { path: 'CLAUDE.md',                          platform: 'claude',   dirHint: '.claude' },
  { path: '.cursorrules',                        platform: 'cursor',   dirHint: '.cursor' },
  { path: '.cursor/rules/guardlink.mdc',        platform: 'cursor',   dirHint: '.cursor' },
  { path: 'AGENTS.md',                           platform: 'codex',    dirHint: '.codex' },
  { path: 'codex.md',                            platform: 'codex',    dirHint: '.codex' },
  { path: '.github/copilot-instructions.md',     platform: 'copilot',  dirHint: '.github' },
  { path: '.windsurfrules',                      platform: 'windsurf' },
  { path: '.clinerules',                         platform: 'cline' },
  { path: '.gemini/settings.json',               platform: 'gemini',   dirHint: '.gemini' },
];

// ─── Language detection ──────────────────────────────────────────────

const LANG_SIGNALS: Array<{ files: string[]; language: ProjectLanguage }> = [
  { files: ['tsconfig.json', 'tsconfig.build.json'],         language: 'typescript' },
  { files: ['package.json'],                                  language: 'javascript' },
  { files: ['pyproject.toml', 'setup.py', 'requirements.txt'], language: 'python' },
  { files: ['go.mod', 'go.sum'],                              language: 'go' },
  { files: ['Cargo.toml', 'Cargo.lock'],                      language: 'rust' },
  { files: ['pom.xml', 'build.gradle', 'build.gradle.kts'],  language: 'java' },
  { files: ['*.csproj', '*.sln'],                             language: 'csharp' },
  { files: ['Gemfile', 'Rakefile'],                           language: 'ruby' },
  { files: ['Package.swift'],                                 language: 'swift' },
  { files: ['build.gradle.kts'],                              language: 'kotlin' },
  { files: ['main.tf', 'variables.tf'],                       language: 'terraform' },
];

const LANG_CONFIG: Record<ProjectLanguage, { commentPrefix: string; ext: string }> = {
  typescript:  { commentPrefix: '//', ext: '.ts' },
  javascript:  { commentPrefix: '//', ext: '.js' },
  python:      { commentPrefix: '#',  ext: '.py' },
  go:          { commentPrefix: '//', ext: '.go' },
  rust:        { commentPrefix: '//', ext: '.rs' },
  java:        { commentPrefix: '//', ext: '.java' },
  csharp:      { commentPrefix: '//', ext: '.cs' },
  ruby:        { commentPrefix: '#',  ext: '.rb' },
  swift:       { commentPrefix: '//', ext: '.swift' },
  kotlin:      { commentPrefix: '//', ext: '.kt' },
  terraform:   { commentPrefix: '#',  ext: '.tf' },
  unknown:     { commentPrefix: '//', ext: '.ts' },
};

// ─── Detection functions ─────────────────────────────────────────────

export function detectProject(root: string): ProjectInfo {
  return {
    root,
    name: detectProjectName(root),
    language: detectLanguage(root),
    commentPrefix: LANG_CONFIG[detectLanguage(root)].commentPrefix,
    definitionsExt: LANG_CONFIG[detectLanguage(root)].ext,
    agentFiles: detectAgentFiles(root),
    alreadyInitialized: existsSync(join(root, '.guardlink')),
  };
}

function detectProjectName(root: string): string {
  // Try package.json
  const pkgPath = join(root, 'package.json');
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
      if (pkg.name) return pkg.name;
    } catch { /* ignore */ }
  }

  // Try Cargo.toml
  const cargoPath = join(root, 'Cargo.toml');
  if (existsSync(cargoPath)) {
    try {
      const cargo = readFileSync(cargoPath, 'utf-8');
      const m = cargo.match(/^name\s*=\s*"([^"]+)"/m);
      if (m) return m[1];
    } catch { /* ignore */ }
  }

  // Try go.mod
  const goModPath = join(root, 'go.mod');
  if (existsSync(goModPath)) {
    try {
      const goMod = readFileSync(goModPath, 'utf-8');
      const m = goMod.match(/^module\s+(\S+)/m);
      if (m) return m[1].split('/').pop() || m[1];
    } catch { /* ignore */ }
  }

  // Try pyproject.toml
  const pyprojectPath = join(root, 'pyproject.toml');
  if (existsSync(pyprojectPath)) {
    try {
      const pyp = readFileSync(pyprojectPath, 'utf-8');
      const m = pyp.match(/^name\s*=\s*"([^"]+)"/m);
      if (m) return m[1];
    } catch { /* ignore */ }
  }

  // Fallback: directory name
  return basename(root);
}

function detectLanguage(root: string): ProjectLanguage {
  let entries: string[];
  try {
    entries = readdirSync(root);
  } catch {
    return 'unknown';
  }

  for (const signal of LANG_SIGNALS) {
    for (const pattern of signal.files) {
      if (pattern.includes('*')) {
        const ext = pattern.replace('*', '');
        if (entries.some(e => e.endsWith(ext))) return signal.language;
      } else {
        if (entries.includes(pattern)) return signal.language;
      }
    }
  }

  // tsconfig.json takes priority over plain package.json for TS vs JS
  if (entries.includes('tsconfig.json')) return 'typescript';
  if (entries.includes('package.json')) return 'javascript';

  return 'unknown';
}

function detectAgentFiles(root: string): AgentFile[] {
  const results: AgentFile[] = [];

  for (const spec of AGENT_FILE_SPECS) {
    const fullPath = join(root, spec.path);
    const exists = existsSync(fullPath);
    let hasGuardLink = false;

    if (exists) {
      try {
        const content = readFileSync(fullPath, 'utf-8');
        hasGuardLink = content.includes('GuardLink') || content.includes('guardlink');
      } catch { /* ignore */ }
    }

    // Check if agent directory exists even when instruction file doesn't
    let dirDetected = false;
    if (spec.dirHint) {
      const dirPath = join(root, spec.dirHint);
      try {
        dirDetected = existsSync(dirPath) && statSync(dirPath).isDirectory();
      } catch { /* ignore */ }
    }

    results.push({
      path: spec.path,
      platform: spec.platform,
      exists,
      hasGuardLink,
      dirDetected,
      dirHint: spec.dirHint,
    });
  }

  return results;
}

/**
 * Get unique platforms that have been auto-detected via directory presence or existing files.
 * Used by the picker to separate "detected" from "optional" agents.
 */
export function getDetectedPlatforms(agentFiles: AgentFile[]): Map<string, string> {
  const detected = new Map<string, string>(); // platform → reason
  for (const af of agentFiles) {
    if (detected.has(af.platform)) continue;
    if (af.exists) {
      detected.set(af.platform, `found ${af.path}`);
    } else if (af.dirDetected && af.dirHint) {
      detected.set(af.platform, `found ${af.dirHint}/`);
    }
  }
  return detected;
}
