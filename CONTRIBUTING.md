# Contributing

Thanks for your interest in contributing to CoreIdent!

## Key areas for contribution

- **External providers** — Microsoft, GitHub, Apple (see `src/CoreIdent.Providers.Google/` for the pattern)
- **Storage adapters** — MongoDB, Redis, etc. (implement `IUserStore`, `IClientStore`, etc.)
- **UI themes** — Razor/Blazor components for login, consent, account management
- **Documentation** — Guides, examples, translations
- **Bug fixes** — Check [GitHub Issues](https://github.com/stimpy77/CoreIdent/issues)

## Submitting changes

1. Fork the repository and create a feature branch from `main`
2. Follow the coding standards in `CLAUDE.md` (they apply to humans too)
3. Write tests before or alongside your code — all PRs must include tests
4. Use conventional commit prefixes: `feat:`, `fix:`, `test:`, `docs:`, `chore:`, `refactor:`
5. One feature per commit — keep commits atomic
6. Ensure `dotnet test CoreIdent.sln` passes before submitting
7. Open a pull request against `main` with a clear description

## Development environments

### Option A: Dev Container (recommended)

This repo includes a VS Code Dev Container configuration under `.devcontainer/`.

Prerequisites:

- VS Code
- Docker Desktop (or another Docker runtime)
- VS Code extension: `Dev Containers` (`ms-vscode-remote.remote-containers`)

Steps:

1. Open this repo in VS Code.
2. Run: `Dev Containers: Reopen in Container`.
3. In the container, restore/build/test:

```bash
dotnet restore CoreIdent.sln
dotnet test CoreIdent.sln
```

## Test coverage

CoreIdent uses Coverlet's cross-platform data collector for coverage.

Run coverage for the full solution:

```bash
dotnet test CoreIdent.sln --collect:"XPlat Code Coverage"
```

Run coverage for a single test project:

```bash
dotnet test tests/CoreIdent.Integration.Tests/CoreIdent.Integration.Tests.csproj --collect:"XPlat Code Coverage"
```

Coverage artifacts are emitted under each test project's `TestResults/` directory as `coverage.cobertura.xml`.

Coverage notes:

- All tests should include descriptive assertion messages (see `CLAUDE.md` for the expected Shouldly style).

Dev container notes:

- The container image includes the .NET 10 SDK.
- SQLite tooling is installed in the container for convenience.

### Option B: Local

Prerequisites:

- .NET 10 SDK

Then:

```bash
dotnet restore CoreIdent.sln
dotnet test CoreIdent.sln
```
