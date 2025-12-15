# Contributing

Thanks for your interest in contributing to CoreIdent.

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

Notes:

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
