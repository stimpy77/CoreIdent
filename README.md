# CoreIdent

**Holistic, open-source authentication and identity for .NET 10+**

[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![.NET 10](https://img.shields.io/badge/.NET-10-512BD4)](https://dotnet.microsoft.com/)

---

## What is CoreIdent?

CoreIdent is a **unified authentication solution** for the .NET ecosystem. Whether you need simple embedded auth, integration with external providers, or a full OAuth 2.0/OIDC server—CoreIdent provides a consistent, developer-friendly approach.

### Core Scenarios

| Scenario | Description |
|----------|-------------|
| **Embedded Auth** | Drop-in authentication for ASP.NET Core apps with minimal configuration |
| **External Providers** | Easy integration with Google, Microsoft, GitHub, and other OAuth/OIDC providers |
| **Identity Server** | Full OAuth 2.0 / OIDC server capabilities for apps that need to be identity providers |
| **Client Libraries** | Secure authentication for MAUI, WPF, Console, and Blazor apps |

---

## Current Status

🚧 **Rescoping for 0.4** — Planning complete, implementation starting fresh on .NET 10.

**Prerequisites:** .NET 10 SDK installed (required for all projects and tests)

The previous 0.3.x implementation has been archived. Version 0.4 is a ground-up rebuild focusing on:

- **.NET 10** only (`net10.0`)
- **Passwordless-first** authentication (email magic links, passkeys)
- **Asymmetric keys** (RS256/ES256) for production-ready token signing
- **Improved developer experience** with better test infrastructure and templates
- **F# first-class support**
- **Client libraries** for any .NET application type

> Legacy note: the 0.3.x codebase remains on the `main` branch and is tagged `legacy-0.3.x-main` for reference.

---

## Documentation

All planning and technical documentation for 0.4 is in the [`docs/0.4/`](docs/0.4/) folder:

| Document | Description |
|----------|-------------|
| [**Project Overview**](docs/0.4/Project_Overview.md) | Vision, principles, architecture, and phased roadmap |
| [**Technical Plan**](docs/0.4/Technical_Plan.md) | Detailed specifications, interfaces, and implementation guidance |
| [**DEVPLAN**](docs/0.4/DEVPLAN.md) | Task-level checklist with components, test cases, and documentation requirements |

These documents include:
- .NET 10 feature reference links for implementers
- Code snippets and interface definitions
- Test infrastructure patterns
- OAuth/OIDC RFC references

---

## Asymmetric Key Configuration (0.4)

CoreIdent 0.4 signs JWTs using **asymmetric keys by default**:

- **RS256** (RSA) — default
- **ES256** (ECDSA P-256)

### RSA (PEM string)

```csharp
builder.Services.AddSigningKey(o => o.UseRsaPem(rsaPrivateKeyPem));
```

### RSA (PEM file)

```csharp
builder.Services.AddSigningKey(o => o.UseRsa("/path/to/private-key.pem"));
```

### ECDSA (PEM file)

```csharp
builder.Services.AddSigningKey(o => o.UseEcdsa("/path/to/ec-private-key.pem"));
```

### Development-only HS256 (Deprecated)

```csharp
builder.Services.AddSigningKey(o => o.UseSymmetric("your-32+byte-dev-secret"));
```

### Security Guidance

- **Do not use HS256 in production.** It requires distributing a shared secret to all token validators.
- **Do not publish symmetric keys in JWKS.** CoreIdent does not emit symmetric keys from `/.well-known/jwks.json`.
- Prefer loading keys from **files or certificates** and managing them using your platform’s secret management.
- Treat private keys as secrets: do not log them and do not commit them to source control.

---

## Scope Configuration (0.4)

CoreIdent defines OAuth/OIDC scopes via `CoreIdentScope` and resolves them using `IScopeStore`.

### Standard OIDC scopes

The library includes standard scope name constants in `StandardScopes`:

- `openid`
- `profile`
- `email`
- `address`
- `phone`
- `offline_access`

### In-memory scope store

For development and tests, you can use the in-memory scope store.

```csharp
builder.Services.AddInMemoryStandardScopes();
```

Or, to seed custom scopes:

```csharp
builder.Services.AddInMemoryScopes(new[]
{
    new CoreIdentScope { Name = "api", DisplayName = "API", UserClaims = ["role"] }
});
```

### EF Core scope store

If you're using `CoreIdent.Storage.EntityFrameworkCore`, register the EF scope store:

```csharp
builder.Services.AddEntityFrameworkCoreScopeStore();
```

You are responsible for applying EF Core migrations / ensuring the schema is created.

---

## Key Principles

| Principle | Description |
|-----------|-------------|
| **Open Source** | MIT license. No vendor lock-in. |
| **Developer Experience** | 5-minute setup for common cases. Convention over configuration. |
| **Leverage .NET 10** | Build on ASP.NET Core Identity, not around it. |
| **Modular** | Core is minimal; features are NuGet packages. |
| **Secure by Default** | Asymmetric keys, PKCE enforcement, secure token handling. |
| **Testable** | First-class test infrastructure with reusable fixtures. |

---

## Planned Packages

```
CoreIdent.Core                    # Core services, interfaces, endpoints
CoreIdent.Storage.EntityFrameworkCore  # EF Core persistence
CoreIdent.Client                  # OAuth client for any .NET app
CoreIdent.Client.Maui             # MAUI-specific (SecureStorage, WebAuthenticator)
CoreIdent.Client.Wpf              # WPF/WinForms (DPAPI, WebView2)
CoreIdent.Client.Blazor           # Blazor WASM integration
CoreIdent.Providers.Google        # Google OAuth provider
CoreIdent.Providers.Microsoft     # Microsoft/Entra ID provider
CoreIdent.Providers.GitHub        # GitHub OAuth provider
CoreIdent.UI.Web                  # Razor/Blazor UI components
CoreIdent.Testing                 # Test fixtures and utilities
```

---

## Roadmap

| Phase | Focus | Status |
|-------|-------|--------|
| **0A** | Foundation (crypto + token lifecycle: keys, JWKS, revocation, introspection) | 🔜 Next |
| **0B** | Quality & DevEx (test infra, metrics, CLI, devcontainer) | Planned |
| **1** | Passwordless (email magic link, passkeys, SMS OTP) | Planned |
| **1.5** | Client libraries (MAUI, WPF, Console, Blazor) | Planned |
| **2** | External providers (Google, Microsoft, GitHub) | Planned |
| **3** | OAuth/OIDC hardening (key rotation, DPoP, RAR, device flow, revocable access for controlled distributed systems) | Planned |
| **4** | UI & Administration | Planned |
| **5** | Advanced (MFA, SCIM, SPIFFE/SPIRE) | Future |

See [DEVPLAN.md](docs/0.4/DEVPLAN.md) for detailed task breakdowns.

---

## Contributing

This project is in early development. Contributions welcome once the foundation is established.

Key areas for future contribution:
- Additional OAuth providers
- Storage adapters (MongoDB, Redis)
- UI themes and components
- Documentation and examples
- F# examples and templates

---

## License

[MIT License](LICENSE) — Use freely, contribute back if you can.

---

## Links

- [Project Overview](docs/0.4/Project_Overview.md)
- [Technical Plan](docs/0.4/Technical_Plan.md)
- [Development Plan](docs/0.4/DEVPLAN.md)
- [.NET 10 What's New](https://learn.microsoft.com/en-us/dotnet/core/whats-new/dotnet-10/overview)
- [.NET 10: What’s New for Authentication and Authorization (Auth0)](https://auth0.com/blog/authentication-authorization-enhancements-dotnet-10/)
