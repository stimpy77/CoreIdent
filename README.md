# CoreIdent

**Holistic, open-source authentication and identity for .NET 10+**

[![Build Status](https://github.com/stimpy77/CoreIdent/actions/workflows/dotnet.yml/badge.svg?branch=main)](https://github.com/stimpy77/CoreIdent/actions/workflows/dotnet.yml)
[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![.NET 10](https://img.shields.io/badge/.NET-10-512BD4)](https://dotnet.microsoft.com/)
[![Open in Codespaces](https://img.shields.io/badge/Open%20in-Codespaces-blue?logo=github)](https://codespaces.new/stimpy77/CoreIdent?quickstart=1)

---

CoreIdent is a **holistic, open-source authentication and identity toolkit** for .NET 10+.

It’s designed to cover the practical spectrum—from **“I just need auth in my app”** to **running a full OAuth 2.0 / OpenID Connect server**—with a **passwordless-first** roadmap (email magic links, passkeys) and a strong focus on developer experience.

CoreIdent aims to grow into a single solution for:

- **Embedded auth for apps** (drop-in defaults)
- **External providers** (Google/Microsoft/GitHub, etc.)
- **Identity server capabilities** (OAuth 2.0 / OIDC)
- **Client libraries** for common .NET app types

CoreIdent 0.4 currently provides a clean, testable core for:

- **Issuing tokens** (JWT access tokens, refresh tokens)
- **Standards endpoints** (discovery + JWKS)
- **Core OAuth flows** (including Authorization Code + PKCE)
- **Pluggable persistence** (in-memory defaults, EF Core implementations)
- **Resource-owner convenience endpoints** (`/auth/register`, `/auth/login`, `/auth/profile`)
- **CLI tool** (`dotnet coreident`) for init/key generation/client helper/migrations
- **Metrics** via `System.Diagnostics.Metrics` (optional)

## Status

CoreIdent **0.4 is a ground-up rewrite** on .NET 10.

- **Prerequisite**: .NET 10 SDK
- **Legacy**: the prior 0.3.x implementation is tagged [`legacy-0.3.x-main`](../../tree/legacy-0.3.x-main)

## What CoreIdent 0.4 provides today

- **Token endpoint** (`/auth/token`)
  - `client_credentials`
  - `refresh_token`
  - `authorization_code` (PKCE required)
  - `password` (deprecated; logs a warning)
- **Authorization endpoint + consent UI** (`/auth/authorize`, `/auth/consent`)
- **Token revocation** (RFC 7009) and **introspection** (RFC 7662)
- **OIDC discovery document** and **JWKS publishing** (public keys only)
- **Resource-owner convenience endpoints** (`/auth/register`, `/auth/login`, `/auth/profile`)
- **In-memory stores** by default + **EF Core store implementations**
- **Test infrastructure** under `tests/` (fixtures + integration coverage)

## What’s next

- **Passwordless authentication** (email magic links, passkeys)
- **External providers** (Google/Microsoft/GitHub, etc.)
- **Client libraries** and broader “drop-in auth for apps” experiences

## Getting started

### 1) Minimal “OAuth server” host

```csharp
using CoreIdent.Core.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCoreIdent(o =>
{
    o.Issuer = "https://issuer.example";
    o.Audience = "https://resource.example";
});

// Production: prefer RSA/ECDSA.
builder.Services.AddSigningKey(o => o.UseRsa("/path/to/private-key.pem"));

var app = builder.Build();
app.MapCoreIdentEndpoints();
app.Run();
```

### 2) Use EF Core persistence

```csharp
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Extensions;
using Microsoft.EntityFrameworkCore;

builder.Services.AddCoreIdent(o =>
{
    o.Issuer = "https://issuer.example";
    o.Audience = "https://resource.example";
});

builder.Services.AddSigningKey(o => o.UseRsa("/path/to/private-key.pem"));

builder.Services.AddDbContext<CoreIdentDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("CoreIdent")));

builder.Services.AddEntityFrameworkCoreStores();
```

## Documentation

- **Developer Guide (recommended starting point)**
  - [docs/0.4/Developer_Guide.md](docs/0.4/Developer_Guide.md)
- **Project docs**
  - [docs/0.4/Project_Overview.md](docs/0.4/Project_Overview.md)
  - [docs/0.4/Technical_Plan.md](docs/0.4/Technical_Plan.md)
  - [docs/0.4/DEVPLAN.md](docs/0.4/DEVPLAN.md)
- **CLI reference**
  - [docs/0.4/CLI_Reference.md](docs/0.4/CLI_Reference.md)
- **Detailed reference**
  - [docs/0.4/README_Detailed.md](docs/0.4/README_Detailed.md)

## Contributing

If you want to contribute, start with [docs/0.4/DEVPLAN.md](docs/0.4/DEVPLAN.md) and the integration tests in [tests/](tests/).

## License

[MIT License](LICENSE)
