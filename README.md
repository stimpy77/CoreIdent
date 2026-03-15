# CoreIdent

**Open-source OAuth 2.1 / OIDC toolkit for .NET 10+**

[![Build Status](https://github.com/stimpy77/CoreIdent/actions/workflows/dotnet.yml/badge.svg?branch=main)](https://github.com/stimpy77/CoreIdent/actions/workflows/dotnet.yml)
[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![.NET 10](https://img.shields.io/badge/.NET-10-512BD4)](https://dotnet.microsoft.com/)
[![Open in Codespaces](https://img.shields.io/badge/Open%20in-Codespaces-blue?logo=github)](https://codespaces.new/stimpy77/CoreIdent?quickstart=1)

---

CoreIdent is a **complete, open-source authentication toolkit** for .NET 10+. Add secure OAuth 2.1 / OpenID Connect to your app in minutes—with full code-level control and no vendor lock-in.

```csharp
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCoreIdent(o => {
    o.Issuer = "https://auth.example.com";
    o.Audience = "https://api.example.com";
});
builder.Services.AddSigningKey(o => o.UseRsa("/path/to/key.pem"));

var app = builder.Build();
app.MapCoreIdentEndpoints();
app.Run();
```

**That's it.** You now have token issuance, OIDC discovery, JWKS, and more.

## Features

* **OAuth 2.1 compliant** — PKCE enforced, no implicit/hybrid flows, exact redirect URI matching
* **Token endpoint** — `client_credentials`, `refresh_token`, `authorization_code` (PKCE required)
* **Authorization Code + PKCE** — Full flow with consent UI and incremental consent
* **OIDC discovery & JWKS** — Standards-compliant metadata and public key publishing
* **Token revocation** (RFC 7009) & **introspection** (RFC 7662)
* **Passwordless authentication** — Email magic links, passkeys/WebAuthn, SMS OTP
* **External providers** — Google, Microsoft, GitHub, Apple (via `CoreIdent.Providers.*`)
* **Pluggable storage** — In-memory for dev, EF Core for production
* **Secure by default** — RS256/ES256 signing, refresh token rotation, theft detection
* **F# first-class** — Templates, samples, verified API compatibility
* **CLI tool** — `dotnet coreident init`, key generation, client management
* **Client libraries** — MAUI, WPF, Console, Blazor with secure token storage
* **Metrics** — OpenTelemetry-compatible via `System.Diagnostics.Metrics`
* **Aspire integration** — Health checks, distributed tracing, service defaults

## Quick Start

### Option 1: Use the Test Host

```bash
dotnet run --project tests/CoreIdent.TestHost
```

Visit `/.well-known/openid-configuration` to see the discovery document.

### Option 2: Use Templates

```bash
dotnet new install CoreIdent.Templates
dotnet new coreident-server -n MyAuthServer
cd MyAuthServer && dotnet run
```

**Available templates:**
- `coreident-api` — Minimal API with token endpoints
- `coreident-server` — Full server with consent UI and passkeys
- `coreident-api-fsharp` — F# version

## Add EF Core Persistence

```csharp
builder.Services.AddDbContext<CoreIdentDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("CoreIdent")));
builder.Services.AddEntityFrameworkCoreStores();
```

## Documentation

| Guide | Description |
|-------|-------------|
| [Developer Guide](docs/Developer_Guide.md) | **Start here** — Configuration, endpoints, persistence |
| [Passkeys Guide](docs/Passkeys.md) | WebAuthn/passkey setup |
| [CLI Reference](docs/CLI_Reference.md) | `dotnet coreident` commands |
| [Aspire Integration](docs/Aspire_Integration.md) | Health checks, tracing, service defaults |
| [Project Overview](docs/Project_Overview.md) | Architecture and vision |
| [Development Plan](docs/DEVPLAN.md) | Roadmap and task checklist |

## Why CoreIdent?

| | CoreIdent | Duende IdentityServer | OpenIddict | Keycloak |
|---|---|---|---|---|
| **License** | MIT (free) | Commercial (RPL) | Apache 2.0 | Apache 2.0 |
| **Deployment** | NuGet package | NuGet package | NuGet package | Separate Java server |
| **Auth model** | Passwordless-first | Password-first | BYO | Password-first |
| **DX** | CLI + templates + Aspire | Manual setup | Manual setup | Admin console |
| **F# support** | First-class | No | No | N/A |

See [docs/Project_Overview.md](docs/Project_Overview.md#why-coreident) for detailed comparisons.

## Contributing

CoreIdent is MIT-licensed and open source. See [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

## License

[MIT](LICENSE)
