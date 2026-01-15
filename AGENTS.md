# AGENTS.md — Agentic Coding Guidelines for CoreIdent

This file provides instructions for AI coding agents (Claude, Copilot, Cursor, etc.) working on this codebase.

## Build / Test Commands

```bash
# Restore and build entire solution
dotnet restore CoreIdent.sln

# Build (compile only)
dotnet build CoreIdent.sln

# Run all tests
dotnet test CoreIdent.sln

# Run tests with coverage (produces coverage.cobertura.xml)
dotnet test CoreIdent.sln --collect:"XPlat Code Coverage"

# Run single test project
dotnet test tests/CoreIdent.Core.Tests/CoreIdent.Core.Tests.csproj

# Run single test class
dotnet test tests/CoreIdent.Integration.Tests -v n --filter "FullyQualifiedName~TokenEndpointsTests"

# Watch mode (during development)
dotnet watch test --project tests/CoreIdent.Core.Tests

# Format code style
dotnet format

# Build a specific project
dotnet build src/CoreIdent.Core/CoreIdent.Core.csproj
```

## Code Style Guidelines

### General Principles
- **Security first** — Never log secrets, tokens, OTPs, or raw PII. Use redaction helpers for email/phone.
- **Fail fast** — Validate arguments early. Throw `ArgumentNullException` for null required params.
- **One responsibility per class/method** — Keep functions focused and small.
- **Interface-driven design** — All services have interfaces for testability. No `new` for services; inject via constructor.

### C# 14 Conventions
- **File-scoped namespaces**: `namespace Foo;` not `namespace Foo { }`
- **Primary constructors** where appropriate
- **Target-typed new**: `List<string> items = [];` not `new List<string>()`
- **Extension members** for `ClaimsPrincipal` utilities
- **Pattern matching** — Prefer `is` patterns over type checks + casts

### Naming
- Meaningful names; avoid abbreviations except well-known ones (`ct` for CancellationToken is fine)
- Interfaces: `I` prefix (e.g., `ITokenService`)
- Records for DTOs/value objects: suffix with `Request`, `Response`, `Options`, or `Result` as appropriate

### Types & Nullability
- **Nullable reference types enabled** — Fix nullable warnings, don't suppress with `!`
- **No type coercion** (`as any`, `@ts-ignore`, `@ts-expect-error`, etc.)
- Prefer `record` types for DTOs and value objects
- Use `CancellationToken` with default value in async APIs

### Imports & Formatting
- Remove unused usings before committing
- Run `dotnet format` when touching many files
- Follow existing style in the file you're editing

### NuGet Package Management
- **Prefer `dotnet add package` over manual XML edits** — This ensures consistent formatting and version resolution
  ```bash
  # Correct way to add a package
  dotnet add tests/CoreIdent.Testing/CoreIdent.Testing.csproj package Microsoft.Playwright
  
  # Avoid: Manually editing .csproj XML
  ```
- When manually adding packages is unavoidable, follow the existing `<PackageReference>` formatting in the project
- Never add comments inside `<ItemGroup>` blocks that describe why a package is added (commit messages serve this purpose)

### Error Handling
- **No empty catch blocks** — Always handle or log exceptions
- Use structured logging with `ILogger<T>`
- Include correlation context in logs

### XML Documentation
- **All public APIs require XML docs** (CS1591 is treated as error)
- User-facing APIs (DI/extension methods/endpoints): add practical guidance in `<remarks>`

### Testing
- **Use Shouldly** with explicit assertion messages:
  ```csharp
  result.ShouldNotBeNull("Token should be issued on successful authentication");
  client.AllowedScopes.ShouldContain("openid", "OIDC scope must be allowed");
  ```
- **Coverage gate**: Changes to `src/CoreIdent.Core/` require **>= 90% normalized merged line coverage**
- Write tests *before* or *alongside* implementation, not after
- Never commit code that breaks existing tests

### Commit Discipline
- **One feature per commit** — No multi-feature commits
- **Atomic commits** — Each commit should build and pass tests independently
- **Conventional commits**: `feat:`, `fix:`, `test:`, `docs:`, `chore:`, `refactor:`
- **No AI co-authorship** in commit messages

## Essential Documentation

| Document | Purpose |
|----------|---------|
| [`CLAUDE.md`](CLAUDE.md) | **Primary** — Complete development guidelines |
| [`docs/DEVPLAN.md`](docs/DEVPLAN.md) | Task-level checklist and roadmap |
| [`docs/Technical_Plan.md`](docs/Technical_Plan.md) | Technical specifications and RFC links |
| [`docs/Project_Overview.md`](docs/Project_Overview.md) | Architecture and vision |
| [`index.md`](index.md) | Component and folder overview |

## Before Making Changes

1. Read relevant sections of `DEVPLAN.md` and `Technical_Plan.md`
2. Check existing patterns in similar files
3. Write or outline tests first
4. Run diagnostics: `lsp_diagnostics` on changed files before completing

## What NOT To Do

- Don't commit without tests
- Don't bundle multiple features in one commit
- Don't skip security validation "for now"
- Don't add dependencies without justification
- Don't delete or weaken existing tests
- Don't hardcode configuration values
- Don't log sensitive data
- Don't leave code in broken state
