# CLAUDE.md — AI Assistant Guidelines for CoreIdent

This file provides instructions for AI assistants (Claude, Copilot, etc.) working on this codebase.

## Project Documentation

**Always read these documents before making changes:**

| Document | Purpose |
|----------|---------|
| [`docs/Project_Overview.md`](docs/Project_Overview.md) | Vision, architecture, phased roadmap |
| [`docs/Technical_Plan.md`](docs/Technical_Plan.md) | Specifications, interfaces, .NET 10 reference links |
| [`docs/DEVPLAN.md`](docs/DEVPLAN.md) | **Task-level checklist** — drives implementation |
| [`docs/Passkeys.md`](docs/Passkeys.md) | Passkeys (WebAuthn) setup guide |

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
- **Use Shouldly assertions with explicit messages** — every assertion should include a descriptive message clarifying expected vs. actual

### Package Management

- Prefer the `dotnet` CLI over manually editing `*.csproj` XML
- Before changing package versions, run `dotnet list <proj> package --outdated`
- Upgrade using `dotnet add <proj> package <PackageId> --version <latest>` and keep versions on the latest stable unless the plan requires otherwise

### Documentation Standards

- Keep all documentation in sync with code
- Update with new features and breaking changes
  - README.md for high-level feature descriptions
  - docs/Developer_Guide.md for detailed consuming developer guides
  - docs/README_Detailed.md for summary guides not covered in the root level README
- Document configuration options and environment variables
- Add code comments for non-obvious logic or complex algorithms
- Update this CLAUDE.md document as implementation details evolve

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
  CoreIdent.Core/                        # Interfaces, models, core services, endpoints
  CoreIdent.Storage.EntityFrameworkCore/ # EF Core store implementations
  CoreIdent.Adapters.DelegatedUserStore/ # Adapter for existing user stores
  CoreIdent.Passkeys/                    # Passkey/WebAuthn support
  CoreIdent.Passkeys.AspNetIdentity/     # Passkey integration with ASP.NET Identity
  CoreIdent.Passwords.AspNetIdentity/    # Password integration with ASP.NET Identity
  CoreIdent.Aspire/                      # .NET Aspire integration (health checks, tracing)
  CoreIdent.Cli/                         # CLI tool (dotnet coreident)
  CoreIdent.Templates/                   # dotnet new template pack
tests/
  CoreIdent.Core.Tests/                  # Unit tests
  CoreIdent.Integration.Tests/           # Integration tests
  CoreIdent.Testing/                     # Shared test infrastructure
  CoreIdent.TestHost/                    # Runnable test server
  CoreIdent.Cli.Tests/                   # CLI tests
  CoreIdent.Templates.Tests/             # Template tests
templates/
  coreident-api/                         # Minimal API template
  coreident-server/                      # Full server template with consent UI
  coreident-api-fsharp/                  # F# template
website/
  index.html, features.html, style.css   # Project website

## Before You Start Coding

1. Read the relevant section of `DEVPLAN.md`
2. Understand the interfaces and contracts in `Technical_Plan.md`
3. Check if there are existing patterns in the codebase to follow
4. Write or outline tests first
5. Implement the feature
6. Run all tests
7. Commit with a clear message referencing the feature

## Coding Standards / Quality Gates (Do Not Skip)

- **Build cleanliness**
  - Ensure packable library projects build with **no warnings** (or explicitly documented accepted warnings)
  - Keep nullable enabled (`<Nullable>enable</Nullable>`) and fix nullable warnings as they appear
- **XML documentation**
  - All public APIs must have XML docs (CS1591 treated as error)
  - If a public API is user-facing (DI/extension methods/endpoints), prefer adding practical guidance in `<remarks>`
- **Public endpoint documentation**
  - Whenever adding/modifying endpoints, update `docs/Developer_Guide.md`
  - Maintain an OpenAPI/Swagger plan (and implementation when scheduled) so endpoints are discoverable
- **Formatting and hygiene**
  - Run `dotnet format` when touching many files / style-heavy changes
  - Avoid unused usings and dead code paths
- **Security / logging**
  - Do not log secrets, tokens, OTPs, magic links, or raw PII
  - Prefer redaction helpers for email/phone values in logs
- **Docs stay in sync**
  - If code changes affect configuration, routes, DI, or behaviors, update docs in the same PR

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
- Add AI co-authorship to commits (no `Co-authored-by: Claude` or similar)
