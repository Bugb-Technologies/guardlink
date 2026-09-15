# Contributing to GuardLink

Thanks for your interest in contributing to GuardLink. This project aims to make threat modeling a natural part of writing code — contributions that further that goal are welcome.

## Getting Started

```bash
git clone https://github.com/Bugb-Technologies/guardlink.git
cd guardlink
npm install
npm run build
npm test
```

## Project Structure

```
src/
├── agents/       Unified agent launcher and config resolution
├── analyze/      AI threat report generation (STRIDE, DREAD, PASTA, etc.)
├── analyzer/     Coverage analysis, SARIF export, suggestion engine
├── cli/          CLI entry point and command handlers
├── dashboard/    HTML dashboard generation
├── diff/         Threat model diffing between git refs
├── init/         Project initialization and agent config templates
├── mcp/          MCP server (tools + resources for AI agents)
├── parser/       Annotation parser (regex-based, language-agnostic)
├── report/       Markdown report and Mermaid diagram generation
├── tui/          Interactive terminal interface
└── types/        TypeScript type definitions (ThreatModel schema)
```

## Development

```bash
npm run build     # Compile TypeScript
npm run dev       # Watch mode
npm test          # Run tests
npm run cli       # Run CLI without building (via tsx)
```

## What to Contribute

**High impact:**
- New language comment style support in the parser
- Additional suggestion patterns in the suggestion engine
- CI integration examples (GitLab CI, CircleCI, Jenkins)
- Documentation improvements and tutorials

**Medium impact:**
- New definition templates for common frameworks
- Test coverage for edge cases
- Performance improvements for large codebases

**Good first issues:**
- Add a comment style for a language not yet supported
- Write a test for an annotation edge case
- Improve error messages in the validator

## Pull Request Process

1. Create a feature branch from `main`
2. Write tests for new functionality
3. Ensure `npm test` and `npm run build` pass
4. Write a clear PR description explaining what changed and why
5. Link any related issues

## Code Style

- TypeScript strict mode
- No external runtime dependencies beyond what's in package.json
- Functions over classes where possible
- Explicit types on public APIs, inferred types internally

## Adding a Language

`src/parser/languages.ts` is the single registry of extension → comment marker, and everything else derives from it: the parser's scan glob, `clear`'s scan glob, the MCP context layer's "would the parser open this file", and the marker the write side falls back to. Add the extension there, add it to `EXTENSION_LANGUAGE` in `src/structure/grammars.ts` (`null` is a correct answer — file scope, reason `no-grammar`), and add its row to SPEC §2.9's extension column.

There used to be four copies of that list. They drifted, and an annotation in a `.php` or `.kts` file was read by nothing and — because both §2.12 diagnostics are asked of a file's lines — reported by nothing either. `tests/scanned-languages.test.ts` now fails if the copies diverge again.

**If the language has a block comment form, add its closer to `BLOCK_CLOSERS` in `src/parser/comment-strip.ts` in the same change.** That table is what `guardlink hypothesis confirm --write` consults before splicing a scan-controlled description into a claim's comment, so that the description cannot end the comment it is written into. A claim can only exist in a file the parser opens — so scanning a language whose closer is not listed is a comment-escape, reachable as soon as someone annotates such a file. Languages whose only comment form is a line comment (Python, Ruby, Bash, YAML, Erlang, LaTeX, INI, Batch) need no entry and must not get one: a line comment ends at a newline, and a written description is one line. The same test pins both directions.

## Generated Files

`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.cursor/rules/guardlink.mdc`, `.windsurfrules`,
`.clinerules`, `.github/copilot-instructions.md`, `.gemini/GEMINI.md` and `.guardlink/README.md`
are **written by `guardlink sync` from this repository's own model**. Do not hand-edit the region
between the `guardlink:begin` / `guardlink:end` markers — the next sync overwrites it. Change
`src/init/templates.ts` and run `guardlink sync .`; if you added or moved annotations, run it in the
same change so the committed block and the model agree.

The block asserts a threat model exists only when `annotations_parsed > 0`, and points at the
reference document this repository actually has (`docs/` by default, `.guardlink/` under
`--no-root-files`). Both are conditional on purpose: this file is written into other people's
repositories under our name, so a sentence that is only sometimes true has to be rendered only
sometimes.

## Numbers Shared With bugb-server

Two constants in `src/parser/acceptance.ts` — `DEFAULT_ACCEPTANCE_WARN_DAYS` (14) and
`MAX_ACCEPTANCE_WARN_DAYS` (365) — are **deliberately the server's**
`bugb_server/notify/config.py` values, and the reading of `0` (no warning at all) is matched too.
Both registers describe the same event, a signed risk acceptance running out of time, for the same
team. Two components disagreeing about whether an acceptance is in trouble is a worse defect than
either of them being silent, so moving one of these means moving both, in the same breath.

What is *not* shared is the trigger: the server is edge-triggered because it delivers messages, and
the gate is level-triggered because it describes a repository at the moment it runs.

## Annotation Spec Changes

Changes to the annotation grammar or ThreatModel schema require discussion in an issue first. The spec is designed to be stable — breaking changes need strong justification.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
