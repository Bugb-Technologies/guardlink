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

## Annotation Spec Changes

Changes to the annotation grammar or ThreatModel schema require discussion in an issue first. The spec is designed to be stable — breaking changes need strong justification.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
