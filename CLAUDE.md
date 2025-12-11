# CLAUDE.md — AI Assistant Guidelines for CoreIdent

This file provides instructions for AI assistants (Claude, Copilot, etc.) working on this codebase.

## Project Documentation

**Always read these documents before making changes:**

| Document | Purpose |
|----------|---------|
| [`docs/0.4/Project_Overview.md`](docs/0.4/Project_Overview.md) | Vision, architecture, phased roadmap |
| [`docs/0.4/Technical_Plan.md`](docs/0.4/Technical_Plan.md) | Specifications, interfaces, .NET 10 reference links |
| [`docs/0.4/DEVPLAN.md`](docs/0.4/DEVPLAN.md) | **Task-level checklist** — drives implementation |

## Development Workflow

### DEVPLAN.md Drives Development

- Treat `DEVPLAN.md` as the authoritative task list
- Work through features in order unless dependencies require otherwise
- Mark checkboxes `[x]` as tasks are completed
- Update the document if implementation reveals needed changes

### Commit Discipline

- **One feature per commit** — No multi-feature commits
- **Tests before commit** — Always have automated tests passing before committing
- **Atomic commits** — Each commit should build and pass tests independently
- **Conventional commits** — Use prefixes: `feat:`, `fix:`, `test:`, `docs:`, `chore:`, `refactor:`

### Testing Requirements

- **Unit tests required** for all new services, stores, and utilities
- **Integration tests required** for all endpoints
- Write tests *before* or *alongside* implementation, not after
- If a feature cannot be tested automatically, document why and what manual verification was done
- Never commit code that breaks existing tests

## Code Priorities

**In order of importance:**

### 1. Security First

- Never store secrets in code or logs
- Validate all inputs
- Use parameterized queries (EF Core handles this)
- Hash sensitive data (tokens, passwords)
- Follow OAuth/OIDC RFCs exactly — security specs exist for a reason
- When in doubt, fail closed (deny access)

### 2. Brevity with Comprehensibility

- Prefer concise code that's still readable
- Avoid over-engineering — solve the problem at hand
- Use meaningful names; avoid abbreviations except well-known ones (`ct` for CancellationToken is fine)
- One responsibility per class/method
- If a method needs extensive comments to explain, consider refactoring

### 3. General Best Practices

- **Interface-driven design** — All services have interfaces for testability
- **Dependency injection** — No `new` for services; inject via constructor
- **Async all the way** — Use `async`/`await` consistently; accept `CancellationToken`
- **Fail fast** — Validate arguments early; throw `ArgumentNullException` for null required params
- **Immutable where possible** — Prefer `record` types for DTOs and value objects
- **No magic strings** — Use constants or configuration
- **Logging** — Use structured logging with `ILogger<T>`; include correlation context

## Code Style

- **C# 14** features are encouraged (extension members, etc.)
- **File-scoped namespaces** — `namespace Foo;` not `namespace Foo { }`
- **Primary constructors** where appropriate
- **Target-typed new** — `List<string> items = [];` not `new List<string>()`
- **Pattern matching** — Prefer `is` patterns over type checks + casts
- Follow existing code style in the file you're editing

## Project Structure

```
src/
  CoreIdent.Core/              # Interfaces, models, core services
  CoreIdent.Storage.EntityFrameworkCore/  # EF Core implementations
  CoreIdent.Client/            # OAuth client library
  CoreIdent.Providers.*/       # External provider integrations
  CoreIdent.UI.Web/            # Razor/Blazor components
tests/
  CoreIdent.Core.Tests/        # Unit tests
  CoreIdent.Integration.Tests/ # Integration tests
  CoreIdent.Testing/           # Shared test infrastructure
```

## Before You Start Coding

1. Read the relevant section of `DEVPLAN.md`
2. Understand the interfaces and contracts in `Technical_Plan.md`
3. Check if there are existing patterns in the codebase to follow
4. Write or outline tests first
5. Implement the feature
6. Run all tests
7. Commit with a clear message referencing the feature

## When Stuck

- Check the reference links in `Technical_Plan.md` for .NET 10 docs and RFCs
- Look at how similar features are implemented in the codebase
- If an RFC is ambiguous, prefer the more secure interpretation
- Ask the user for clarification rather than guessing on security-sensitive decisions

## Do NOT

- Commit without tests
- Bundle multiple features in one commit
- Skip security validation "for now"
- Add dependencies without justification
- Delete or weaken existing tests
- Hardcode configuration values
- Log sensitive data (tokens, passwords, PII)
