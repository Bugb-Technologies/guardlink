/**
 * Comment prefix stripping per §2.9.
 * Strips the host language's comment prefix to expose the annotation text.
 */

/**
 * Strip comment prefix from a single line, returning the inner text
 * or null if the line is not a comment.
 */
export function stripCommentPrefix(line: string): string | null {
  const trimmed = line.trimStart();

  // Single-line styles (order matters — longer prefixes first)
  const singlePrefixes = [
    '//',   // C-family, Rust, Go, JS, TS
    '#',    // Python, Ruby, Bash, YAML, Terraform
    '--',   // Haskell, Lua, SQL, Ada
    '%',    // LaTeX, Erlang, MATLAB
    ';',    // Lisp, Clojure, Assembly
    'REM ', // Batch (with trailing space)
    'REM\t',
    "'",    // VBA, VB.NET
  ];

  for (const prefix of singlePrefixes) {
    if (trimmed.startsWith(prefix)) {
      return trimmed.slice(prefix.length).trimStart();
    }
  }

  // Block comment line (already inside a block)
  // Strip leading * (Javadoc-style) or bare text in block
  if (trimmed.startsWith('*') && !trimmed.startsWith('*/')) {
    return trimmed.slice(1).trimStart();
  }

  // HTML/XML comment: <!-- ... -->
  const htmlMatch = trimmed.match(/^<!--\s*(.*?)\s*-->$/);
  if (htmlMatch) return htmlMatch[1];

  // Opening block comment on same line: /* ... */  or  /* ...
  const blockOpenClose = trimmed.match(/^\/\*\s*(.*?)\s*\*\/$/);
  if (blockOpenClose) return blockOpenClose[1];

  const blockOpen = trimmed.match(/^\/\*\s*(.*)$/);
  if (blockOpen) return blockOpen[1].trimStart();

  // Haskell block: {- ... -}
  const haskellBlock = trimmed.match(/^\{-\s*(.*?)\s*-\}$/);
  if (haskellBlock) return haskellBlock[1];

  // OCaml/Pascal: (* ... *)
  const ocamlBlock = trimmed.match(/^\(\*\s*(.*?)\s*\*\)$/);
  if (ocamlBlock) return ocamlBlock[1];

  return null;
}

/**
 * Detect file's primary comment style from extension.
 * Used for multi-line continuation detection.
 */
export function commentStyleForExt(ext: string): string {
  const map: Record<string, string> = {
    '.ts': '//', '.tsx': '//', '.js': '//', '.jsx': '//',
    '.java': '//', '.c': '//', '.cpp': '//', '.cc': '//',
    '.cs': '//', '.go': '//', '.rs': '//', '.swift': '//',
    '.kt': '//', '.scala': '//', '.dart': '//',
    '.py': '#', '.rb': '#', '.sh': '#', '.bash': '#',
    '.yml': '#', '.yaml': '#', '.tf': '#', '.r': '#',
    '.ex': '#', '.exs': '#', '.nim': '#', '.pl': '#',
    '.hs': '--', '.lua': '--', '.sql': '--', '.ada': '--',
    '.html': '<!--', '.xml': '<!--', '.svg': '<!--',
    '.css': '/*',
    '.tex': '%', '.erl': '%', '.m': '%',
    '.lisp': ';', '.cl': ';', '.clj': ';', '.asm': ';',
    '.bat': 'REM', '.cmd': 'REM',
    '.vb': "'", '.bas': "'",
  };
  return map[ext.toLowerCase()] || '//';
}
