# CoreIdent (Detailed Reference)

This document is the **detailed reference** for CoreIdent.

The root `README.md` is intended to be a concise, friendly entry point; use this file when you want the deeper configuration and endpoint reference.

## Quick links

- **Integrate CoreIdent into an app**
  - [Developer Guide](Developer_Guide.md)
- **Aspire integration (service defaults)**
  - [Aspire Integration](Aspire_Integration.md)
- **Scaffold a host with templates**
  - `dotnet new install CoreIdent.Templates`
  - Templates: `coreident-api`, `coreident-server`, `coreident-api-fsharp`
- **Add passkeys (WebAuthn)**
  - [Passkeys Guide](Passkeys.md)
- **Use the CLI**
  - [CLI Reference](CLI_Reference.md)
- **Understand the roadmap / implementation status**
  - [DEVPLAN](DEVPLAN.md)

---

# CoreIdent

**Holistic, open-source authentication and identity for .NET 10+**

[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![.NET 10](https://img.shields.io/badge/.NET-10-512BD4)](https://dotnet.microsoft.com/)

---

## What is CoreIdent?

CoreIdent is a **unified authentication solution** for the .NET ecosystem. It is designed to cover the spectrum from simple embedded auth to running a full OAuth 2.0 / OpenID Connect server, with additional capabilities delivered incrementally across phases.

## Embedded Auth vs Membership (Guidance Placeholder)

This section is a placeholder for DEVPLAN 1.13.6.

- **Embedded auth**: Use CoreIdent endpoints directly in your host app for minimal “auth for my app” workflows.
- **Membership/admin**: Build on CoreIdent by implementing store interfaces and enriching tokens/profile responses with membership data owned by your app.

### Core Scenarios

| Scenario | Description |
|----------|-------------|
| **Embedded Auth** | Minimal “auth for my app” workflows via resource-owner convenience endpoints (`/auth/register`, `/auth/login`, `/auth/profile`) |
| **External Providers** | Planned (Phase 2) |
| **Identity Server** | OAuth/OIDC foundation implemented; additional hardening and advanced features planned (Phase 3+) |
| **Client Libraries** | Planned (Phase 1.5) |

---

## Current Status

CoreIdent is in active development on .NET 10.

**Prerequisites:** .NET 10 SDK installed (required for all projects and tests)

Current focus areas include:

- **.NET 10** only (`net10.0`)
- **Asymmetric keys** (RS256/ES256) for production-ready token signing
- **OAuth/OIDC foundation** (discovery, JWKS, token endpoint, revocation, introspection)
- **Authorization Code + PKCE** with a minimal consent UI
- **Resource-owner convenience endpoints** (`/auth/register`, `/auth/login`, `/auth/profile`)
- **Pluggable persistence** (in-memory defaults, EF Core implementations)
- **Developer experience**: test infrastructure, CLI tool, devcontainer/Codespaces support
- **Observability**: optional `System.Diagnostics.Metrics` instrumentation

> Note: CoreIdent focuses on a clean, modular core with secure defaults and a strong developer experience.

---

## Passwordless authentication

CoreIdent includes passwordless flows:

- Email magic links
- Passkeys/WebAuthn
- SMS one-time passcodes (OTP)

For the SMS OTP endpoint and configuration reference, see the Developer Guide section [4.8 Passwordless SMS OTP](Developer_Guide.md#48-passwordless-sms-otp-feature-13).

## Documentation

All planning and technical documentation is in the [`docs/`](./) folder:

| Document | Description |
|----------|-------------|
| [**Project Overview**](Project_Overview.md) | Vision, principles, architecture, and phased roadmap |
| [**Technical Plan**](Technical_Plan.md) | Detailed specifications, interfaces, and implementation guidance |
| [**DEVPLAN**](DEVPLAN.md) | Task-level checklist with components, test cases, and documentation requirements |
| [**Developer Guide**](Developer_Guide.md) | Practical guide to the current codebase, endpoints, configuration, and testing |
| [**Aspire Integration**](Aspire_Integration.md) | Integrating CoreIdent with .NET Aspire service defaults |
| [**Passkeys Guide**](Passkeys.md) | Passkeys (WebAuthn) setup guide |
| [**CLI Reference**](CLI_Reference.md) | Command reference for the `dotnet coreident` CLI tool |

These documents include:
- .NET 10 feature reference links for implementers
- Code snippets and interface definitions
- Test infrastructure patterns
- OAuth/OIDC RFC references

---

## Asymmetric Key Configuration

CoreIdent signs JWTs using **asymmetric keys by default**:

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

### EF Core store registration order

When using EF Core-backed stores, register CoreIdent first, then your EF `DbContext`, then CoreIdent’s EF Core stores:

```csharp
builder.Services.AddCoreIdent();

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddEntityFrameworkCoreStores();
```

You are responsible for applying EF Core migrations / ensuring the schema is created.

---

## Token Endpoint (0.4)

CoreIdent exposes an OAuth 2.0 token endpoint at `POST /auth/token` (configurable via `CoreIdentRouteOptions.TokenPath`).

### Supported Grant Types

| Grant Type | Description |
|------------|-------------|
| `client_credentials` | Machine-to-machine authentication using client ID and secret |
| `refresh_token` | Exchange a refresh token for new access and refresh tokens |
| `authorization_code` | Authorization Code flow (PKCE required) |
| `password` | **Deprecated** resource owner password credentials (ROPC). Supported for legacy/mobile scenarios; logs a warning on use. |

> **Note:** Authorization Code flow requires the `/auth/authorize` endpoint and an authenticated user (your host app must configure authentication).

### Password Grant (ROPC) (Deprecated)

CoreIdent supports `grant_type=password` for **legacy** scenarios.

- **Deprecation:** This grant is deprecated in OAuth 2.1. CoreIdent will log a warning: `Password grant is deprecated in OAuth 2.1. Consider using authorization code flow with PKCE.`
- **Recommendation:** Migrate to **authorization code + PKCE**.

```http
POST /auth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=password&username=user%40example.com&password=Test123!&scope=openid%20offline_access
```

Notes:

- A client must include `"password"` in `AllowedGrantTypes`.
- A refresh token is only issued when:
  - the client has `AllowOfflineAccess = true`, and
  - the granted scopes include `offline_access`.

### Client Credentials Grant

```http
POST /auth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=client_credentials&scope=api
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "api"
}
```

### Refresh Token Grant

```http
POST /auth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=refresh_token&refresh_token=<refresh_token>
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "<new_refresh_token>",
  "scope": "openid profile"
}
```

### Refresh Token Rotation

CoreIdent implements **refresh token rotation** for enhanced security:

1. **Single use:** Each refresh token can only be used once. After use, it is marked as consumed.
2. **Token families:** All refresh tokens derived from the same initial grant share a `FamilyId`.
3. **Theft detection:** If a consumed refresh token is reused (indicating potential theft), the **entire token family is revoked**, invalidating all tokens in that lineage.

This approach ensures that if an attacker steals a refresh token, legitimate use by the real user will trigger revocation, limiting the attack window.

### Custom Claims

Register a custom `ICustomClaimsProvider` to add claims to tokens:

```csharp
public class MyClaimsProvider : ICustomClaimsProvider
{
    public Task<IEnumerable<Claim>> GetAccessTokenClaimsAsync(ClaimsContext context, CancellationToken ct)
    {
        var claims = new List<Claim>();
        if (context.Scopes.Contains("roles"))
        {
            claims.Add(new Claim("role", "admin"));
        }
        return Task.FromResult<IEnumerable<Claim>>(claims);
    }

    public Task<IEnumerable<Claim>> GetIdTokenClaimsAsync(ClaimsContext context, CancellationToken ct)
        => Task.FromResult(Enumerable.Empty<Claim>());
}

// Register before AddCoreIdent() to override the default
builder.Services.AddSingleton<ICustomClaimsProvider, MyClaimsProvider>();
```

---

## Token Revocation (RFC 7009) (0.4)

CoreIdent exposes a token revocation endpoint at `POST /auth/revoke` (configurable via `CoreIdentRouteOptions.RevocationPath`).

### Client Authentication

- **Confidential clients:** must authenticate (recommended: HTTP Basic auth).
- **Public clients:** client authentication requirements may vary by deployment; CoreIdent enforces the same endpoint contract but confidential clients must still authenticate.

### Revoke an Access Token

```http
POST /auth/revoke
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

token=<access_token>&token_type_hint=access_token
```

CoreIdent will validate the JWT signature, extract the `jti`, and record the token as revoked in `ITokenRevocationStore`.

> **Important (JWT reality):** revoking a JWT only takes effect for resource servers that perform an online check (e.g., via introspection or shared revocation middleware). CoreIdent provides `UseCoreIdentTokenRevocation()` middleware for this purpose.

### Revoke a Refresh Token

```http
POST /auth/revoke
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

token=<refresh_token>&token_type_hint=refresh_token
```

CoreIdent will revoke the refresh token using `IRefreshTokenStore`.

### Privacy / Response Semantics

Per RFC 7009, the revocation endpoint is designed to avoid leaking token validity. CoreIdent returns `200 OK` for well-formed requests even if the token is unknown.

### Client Ownership

CoreIdent validates that the authenticated client is the same client that the token was issued to. If a client attempts to revoke a token it does not own, CoreIdent returns `200 OK` but does not revoke the token.

---

## Token Introspection (RFC 7662) (0.4)

CoreIdent exposes an introspection endpoint at `POST /auth/introspect` (configurable via `CoreIdentRouteOptions.IntrospectionPath`).

This endpoint is intended for **resource servers** (APIs) that need an online check for:

- Token validity / expiry
- Access token revocation status
- Refresh token activity status

### Client Authentication

Introspection requests must authenticate using **resource server credentials** (recommended: HTTP Basic auth).

```http
POST /auth/introspect
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(resource_server_client_id:resource_server_client_secret)

token=<token>&token_type_hint=access_token
```

### Response

The response follows RFC 7662. Example:

```json
{
  "active": true,
  "scope": "openid profile",
  "client_id": "client123",
  "token_type": "Bearer",
  "exp": 1234567890,
  "iat": 1234567800,
  "sub": "user-id",
  "aud": "https://api.example",
  "iss": "https://issuer.example"
}
```

If the token is unknown, invalid, expired, revoked, or otherwise inactive, CoreIdent returns:

```json
{ "active": false }
```

---

## Client Configuration (0.4)

---

## Resource Owner Endpoints (Register/Login/Profile) (0.4)

CoreIdent provides minimal **resource owner** endpoints under the base path (default `/auth`):

- `GET/POST /auth/register`
- `GET/POST /auth/login`
- `GET /auth/profile`

`/auth/profile` is a **CoreIdent convenience endpoint** intended for first-party apps using the resource owner (register/login) workflow.
It is distinct from the OIDC-standard **UserInfo** endpoint (`/auth/userinfo` via `CoreIdentRouteOptions.UserInfoPath`), which is specified by OpenID Connect and is tracked separately in Feature 1.10.

### Content Negotiation (JSON vs HTML)

CoreIdent returns **JSON** when the request indicates a JSON client:

- `Accept: application/json`, or
- `Content-Type: application/json`

Otherwise, CoreIdent returns **minimal HTML** suitable for basic browser workflows.

### Default Responses

- `POST /auth/register`
  - JSON: `{ "userId": "...", "message": "Registered successfully" }`
  - HTML: basic success page
- `POST /auth/login`
  - JSON: OAuth-style token response (`access_token`, `refresh_token`, `expires_in`, `token_type`)
  - HTML: basic success page
  - Optional: if `redirect_uri` is provided as a query string parameter, CoreIdent redirects after successful login
- `GET /auth/profile`
  - Requires a valid **Bearer** access token
  - JSON: `{ "id": "...", "email": "...", "claims": { ... } }`
  - HTML: basic profile page

### Customizing Responses with Delegates

You can override the default behavior by registering handlers via `ConfigureResourceOwnerEndpoints(...)`.
Each handler can return a custom `IResult`, or return `null` to fall back to CoreIdent's default response.

```csharp
builder.Services.ConfigureResourceOwnerEndpoints(options =>
{
    options.RegisterHandler = (http, user, ct) =>
        Task.FromResult<IResult?>(Results.Redirect("/welcome"));

    options.LoginHandler = (http, user, tokens, ct) =>
        Task.FromResult<IResult?>(Results.Json(new { tokens.AccessToken }));

    options.ProfileHandler = (http, user, claims, ct) =>
        Task.FromResult<IResult?>(Results.Json(new { user.Id, user.UserName }));
});
```

### Disabling Individual Endpoints

`MapCoreIdentEndpoints()` maps *all* CoreIdent endpoints, including the resource owner endpoints.

To omit one or more endpoints:

- Do not call `MapCoreIdentEndpoints()`.
- Instead, map only the endpoints you want using the granular extension methods (e.g., `MapCoreIdentTokenEndpoint(...)`, `MapCoreIdentTokenManagementEndpoints(...)`, `MapCoreIdentResourceOwnerEndpoints(...)`, etc.).

Clients are OAuth 2.0 applications that can request tokens. Configure clients using `IClientStore`.

### Client Model

```csharp
var client = new CoreIdentClient
{
    ClientId = "my-api-client",
    ClientSecretHash = secretHasher.HashSecret("my-secret"),
    ClientName = "My API Client",
    ClientType = ClientType.Confidential,
    AllowedGrantTypes = ["client_credentials", "refresh_token"],
    AllowedScopes = ["openid", "profile", "api"],
    AllowOfflineAccess = true,
    AccessTokenLifetimeSeconds = 900,      // 15 minutes
    RefreshTokenLifetimeSeconds = 604800,  // 7 days
    RequirePkce = true,
    Enabled = true
};
```

### Client Types

| Type | Description |
|------|-------------|
| `Confidential` | Server-side apps that can securely store secrets. Must provide `client_secret`. |
| `Public` | SPAs, mobile apps that cannot securely store secrets. Must use PKCE. |

### In-Memory Client Store

```csharp
var hasher = new DefaultClientSecretHasher();
builder.Services.AddInMemoryClients(new[]
{
    new CoreIdentClient
    {
        ClientId = "my-client",
        ClientSecretHash = hasher.HashSecret("my-secret"),
        ClientType = ClientType.Confidential,
        AllowedGrantTypes = ["client_credentials"],
        AllowedScopes = ["api"]
    }
});
```

### EF Core Client Store

```csharp
builder.Services.AddEntityFrameworkCoreClientStore();
```

### Token Lifetimes

Each client can have custom token lifetimes:

- `AccessTokenLifetimeSeconds` — How long access tokens are valid (default: 3600 = 1 hour)
- `RefreshTokenLifetimeSeconds` — How long refresh tokens are valid (default: 86400 = 1 day)

The global defaults in `CoreIdentOptions` are used when creating tokens for flows that don't have a specific client (if applicable).

---

## OIDC Discovery Metadata (0.4)

CoreIdent exposes an OpenID Connect discovery document endpoint at:

- `/.well-known/openid-configuration`

**Issuer requirement:** the `issuer` value in the discovery document **exactly matches** your configured `CoreIdentOptions.Issuer`.

CoreIdent advertises its endpoints (JWKS, token, revocation, introspection) based on the configured route options and issuer.

---

## Metrics and Observability (0.4)

CoreIdent emits metrics using `System.Diagnostics.Metrics`, compatible with OpenTelemetry and .NET Aspire.

### Enable Metrics

```csharp
builder.Services.AddCoreIdent(...);
builder.Services.AddCoreIdentMetrics();
```

### Available Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `coreident.client.authenticated` | Counter | Client authentication attempts |
| `coreident.token.issued` | Counter | Tokens issued |
| `coreident.token.revoked` | Counter | Tokens revoked |
| `coreident.client.authentication.duration` | Histogram | Client auth duration (ms) |
| `coreident.token.issuance.duration` | Histogram | Token issuance duration (ms) |

### Metric Tags

- `coreident.client.authenticated`: `client_type`, `success`
- `coreident.token.issued`: `token_type`, `grant_type`
- `coreident.token.revoked`: `token_type`

### Filtering and Sampling

```csharp
builder.Services.AddCoreIdentMetrics(o =>
{
    o.SampleRate = 0.1;  // 10% sampling
    o.Filter = ctx => ctx.MetricName != "coreident.token.issued";
});
```

### Integration with OpenTelemetry

```csharp
builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics => metrics.AddMeter("CoreIdent"));
```

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

Not all packages listed here exist yet; this section is a roadmap view.

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
| **0A** | Foundation (crypto + token lifecycle: keys, JWKS, revocation, introspection) | Completed |
| **0B** | Quality & DevEx (test infra, metrics, CLI, devcontainer) | Completed |
| **1** | Passwordless (email magic link, passkeys, SMS OTP) | In progress |
| **1.5** | Client libraries (MAUI, WPF, Console, Blazor) | Planned |
| **2** | External providers (Google, Microsoft, GitHub) | Planned |
| **3** | OAuth/OIDC hardening (key rotation, DPoP, RAR, device flow, revocable access for controlled distributed systems) | Planned |
| **4** | UI & Administration | Planned |
| **5** | Advanced (MFA, SCIM, SPIFFE/SPIRE) | Future |

See [DEVPLAN.md](DEVPLAN.md) for detailed task breakdowns.

---

## Contributing

CoreIdent is still early in its roadmap, but the foundation is established and contributions are welcome.

Key areas for future contribution:
- Additional OAuth providers
- Storage adapters (MongoDB, Redis)
- UI themes and components
- Documentation and examples
- F# examples and templates

---

## License

[MIT License](../../LICENSE) — Use freely, contribute back if you can.

---

## Links

- [Project Overview](Project_Overview.md)
- [Technical Plan](Technical_Plan.md)
- [Development Plan](DEVPLAN.md)
- [Developer Guide](Developer_Guide.md)
- [Passkeys Guide](Passkeys.md)
- [.NET 10 What's New](https://learn.microsoft.com/en-us/dotnet/core/whats-new/dotnet-10/overview)
- [.NET 10: What’s New for Authentication and Authorization (Auth0)](https://auth0.com/blog/authentication-authorization-enhancements-dotnet-10/)
