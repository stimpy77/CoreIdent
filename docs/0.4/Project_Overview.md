# CoreIdent 0.4: Project Overview & Vision

## Executive Summary

CoreIdent is a **holistic, open-source authentication and identity solution for .NET 10+**. It provides a unified approach to security across multiple scenarios:

1. **Embedded Authentication** — Drop-in auth for ASP.NET Core apps with minimal configuration
2. **External Provider Integration** — Easy connection to third-party OAuth/OIDC providers (Google, Microsoft, etc.)
3. **Identity Server Capabilities** — Full OAuth 2.0 / OIDC server for apps that need to be identity providers
4. **Passwordless-First** — Modern authentication (email magic links, passkeys) as primary, passwords as fallback

CoreIdent wraps and extends .NET 10's built-in identity primitives, dramatically simplifying developer experience while remaining fully extensible for complex scenarios.

---

## Core Principles

| Principle | Description |
|-----------|-------------|
| **Open Source** | MIT license. No vendor lock-in. |
| **Developer Experience First** | 5-minute setup for common cases. Convention over configuration. |
| **Leverage .NET 10** | Build on ASP.NET Core Identity, not around it. Use native passkey support, metrics, etc. |
| **Modular Architecture** | Core is minimal; features are NuGet packages. Use only what you need. |
| **Secure by Default** | Asymmetric keys (RS256/ES256), PKCE enforcement, secure token handling. |
| **Testable** | First-class test infrastructure with reusable fixtures and minimal boilerplate. |

---

## Modular Design Philosophy

CoreIdent is built as a **composable ecosystem of packages**, not a monolithic framework:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CORE (Required)                                 │
│  CoreIdent.Core — Interfaces, base services, minimal API endpoints      │
│  (C# & F# compatible)                                                   │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼─────────────────────────────────────────┐
        ▼                           ▼                           ▼           ▼
┌───────────────┐         ┌─────────────────┐         ┌─────────────────┐  ┌─────────────────┐
│   STORAGE     │         │   PROVIDERS     │         │   FEATURES      │  │   CLIENTS       │
├───────────────┤         ├─────────────────┤         ├─────────────────┤  ├─────────────────┤
│ .EFCore       │         │ .Google         │         │ .Passwordless   │  │ .Client         │
│ .Sqlite       │         │ .Microsoft      │         │ .Passkeys       │  │ .Client.Maui    │
│ .MongoDB*     │         │ .GitHub         │         │ .MFA            │  │ .Client.Wpf     │
│ .Redis*       │         │ .Apple*         │         │ .UI.Web         │  │ .Client.Console │
│ .Adapters     │         │ .SAML*          │         │ .AdminApi       │  │ .Client.Blazor  │
└───────────────┘         └─────────────────┘         └─────────────────┘  └─────────────────┘
                                                      * = community/future
```

**Key modularity principles:**

1. **Pay for what you use** — Don't need external providers? Don't install them.
2. **Swap implementations** — All core services are interface-based (`IUserStore`, `ITokenService`, etc.)
3. **Extend without forking** — Register custom implementations via DI
4. **External library integration** — Hooks for integrating third-party security libraries

**Extension points:**

| Extension Point | Interface | Purpose |
|-----------------|-----------|--------|
| User Storage | `IUserStore` | Custom user persistence |
| Token Generation | `ITokenService` | Custom token formats |
| Key Management | `ISigningKeyProvider` | External key vaults |
| Custom Claims | `ICustomClaimsProvider` | Add claims to tokens |
| Email Delivery | `IEmailSender` | Custom email providers |
| SMS Delivery | `ISmsProvider` | Custom SMS providers |
| Rate Limiting | `IRateLimiter` | Custom rate limit logic |
| Audit Logging | `IAuditLogger` | Custom audit destinations |

---

## What CoreIdent Is NOT

- **Not a Keycloak replacement** — We're not building a full IAM platform with admin UIs for enterprise policy management
- **Not competing on obscure protocols** — No SAML, WS-Fed, or legacy enterprise federation (use specialized tools)
- **Not blockchain/Web3 focused** — Removed from core roadmap (community can add later)

---

## Target Scenarios

### Scenario 1: "I just need auth for my app"
```csharp
// Program.cs - That's it. Passwordless email auth ready.
builder.Services.AddCoreIdent(options => {
    options.UsePasswordlessEmail(smtp => smtp.Configure(Configuration));
});
app.MapCoreIdentEndpoints();
```

### Scenario 2: "I want to use Google/Microsoft login"
```csharp
builder.Services.AddCoreIdent()
    .AddExternalProvider<GoogleProvider>(Configuration)
    .AddExternalProvider<MicrosoftProvider>(Configuration);
```

### Scenario 3: "I need to be an OAuth/OIDC server"
```csharp
builder.Services.AddCoreIdent()
    .AddOAuthServer(options => {
        options.UseAsymmetricKeys(Configuration);
    })
    .AddEntityFrameworkStores<AppDbContext>();
```

### Scenario 4: "I have an existing user database"
```csharp
builder.Services.AddCoreIdent()
    .AddDelegatedUserStore(options => {
        options.FindUserById = id => myUserService.GetUserAsync(id);
        options.ValidateCredentials = (user, pwd) => myUserService.CheckPasswordAsync(user, pwd);
    });
```

---

## .NET 10 Features We Leverage

| Feature | How CoreIdent Uses It |
|---------|----------------------|
| **Built-in Passkey Support** | Wrap `IdentityPasskeyOptions` with simplified configuration; extend for server-side scenarios |
| **C# 14 Extension Members** | Provide `ClaimsPrincipal` extensions for clean claim access (`User.Email`, `User.GetUserId()`) |
| **Authentication Metrics** | Integrate with `Microsoft.AspNetCore.Authentication` metrics (sign_ins, sign_outs, duration) |
| **ASP.NET Core Identity Metrics** | Expose `aspnetcore.identity.*` metrics for user ops, password checks, 2FA tracking |
| **Cookie Auth API Improvements** | Leverage `IApiEndpointMetadata` for proper 401/403 on API endpoints |
| **ASP.NET Core Identity** | Build on top of `UserManager<T>`, `SignInManager<T>` where appropriate |
| **Post-Quantum Cryptography** | Future-ready with .NET 10's ML-DSA support (watch list) |
| **`*.localhost` Dev Certificates** | Better local dev experience with unique subdomains |

### .NET 10 Reference Documentation

For implementers unfamiliar with .NET 10's auth features, start here:

- **Overview:** [What's new in .NET 10](https://learn.microsoft.com/en-us/dotnet/core/whats-new/dotnet-10/overview)
- **ASP.NET Core 10:** [What's new in ASP.NET Core 10](https://learn.microsoft.com/en-us/aspnet/core/release-notes/aspnetcore-10.0)
- **Passkeys:** [Passkey authentication in ASP.NET Core Identity](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/passkeys)
- **Identity Introduction:** [Introduction to Identity on ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity)
- **Auth Metrics:** [ASP.NET Core built-in metrics](https://learn.microsoft.com/en-us/aspnet/core/log-mon/metrics/built-in)
- **C# 14:** [What's new in C# 14](https://learn.microsoft.com/en-us/dotnet/csharp/whats-new/csharp-14)
- **F# 10:** [F# release notes](https://fsharp.github.io/fsharp-compiler-docs/release-notes/About.html)
- **MAUI:** [What's new in .NET MAUI in .NET 10](https://learn.microsoft.com/en-us/dotnet/maui/whats-new/dotnet-10)

**Third-party analysis:**
- [Auth0: .NET 10 Authentication & Authorization Enhancements](https://auth0.com/blog/authentication-authorization-enhancements-dotnet-10/)
- [InfoQ: ASP.NET Core 10 Release](https://www.infoq.com/news/2025/12/asp-net-core-10-release/)
- [Leading EDJE: What's New in .NET 10](https://blog.leadingedje.com/post/whatsnewindotnet/10.html)
- [Duende: Most Anticipated .NET 10 Auth Features](https://duendesoftware.com/blog/20250916-duende-most-anticipated-dotnet-10-auth-features)

---

## Language & Platform Support

### F# First-Class Support

CoreIdent is designed to work seamlessly with F#:

```fsharp
// F# example - Giraffe/Saturn integration
let webApp =
    choose [
        route "/api/protected" >=> authorize >=> text "Hello from F#!"
    ]

let configureServices (services: IServiceCollection) =
    services.AddCoreIdent(fun options ->
        options.Issuer <- "https://myapp.com"
        options.Audience <- "my-api"
    ) |> ignore
```

**F# considerations:**
- All public APIs use F#-friendly types (no `out` parameters, `Result<T>` where appropriate)
- Async methods return `Task<T>` (compatible with F# `task { }` CE)
- Configuration uses mutable options pattern (standard .NET) but also supports F# record-style
- Examples and templates provided in both C# and F#

### Client Libraries for Any .NET App

**`CoreIdent.Client`** — Core client library for authenticating against CoreIdent (or any OAuth/OIDC server):

```csharp
// Works in any .NET 10 app: MAUI, WPF, WinForms, Console, Blazor WASM
var authClient = new CoreIdentClient(new CoreIdentClientOptions
{
    Authority = "https://auth.myapp.com",
    ClientId = "my-desktop-app",
    RedirectUri = "myapp://callback",
    Scopes = ["openid", "profile", "api"]
});

// Trigger login (opens browser/webview)
var result = await authClient.LoginAsync();

// Tokens are securely stored and auto-refreshed
var accessToken = await authClient.GetAccessTokenAsync();
```

**Platform-specific packages:**

| Package | Platform | Secure Storage | Browser Integration |
|---------|----------|----------------|--------------------|
| `CoreIdent.Client` | .NET 10 (`net10.0`) | Pluggable | Pluggable |
| `CoreIdent.Client.Maui` | .NET MAUI | SecureStorage | WebAuthenticator |
| `CoreIdent.Client.Wpf` | WPF | DPAPI | WebView2 / System Browser |
| `CoreIdent.Client.WinForms` | WinForms | DPAPI | WebView2 / System Browser |
| `CoreIdent.Client.Console` | Console Apps | File (encrypted) | System Browser |
| `CoreIdent.Client.Blazor` | Blazor WASM | Browser Storage | Native |

**Key features:**
- **Secure token storage** — Platform-appropriate secure storage (Keychain, DPAPI, SecureStorage)
- **Automatic token refresh** — Background refresh before expiry
- **PKCE by default** — All public client flows use PKCE
- **Offline support** — Cached tokens work offline until expiry
- **DPoP support** — Proof-of-possession tokens (Phase 3)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           CLIENT APPLICATIONS                              │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  │
│  │ MAUI App      │  │ WPF/WinForms  │  │ Console App   │  │ Blazor WASM   │  │
│  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘  │
│          └────────────┴──────────────┴──────────────┴────────────┘           │
│                                    │                                       │
│                     ┌───────────────┴────────────────┐                      │
│                     │   CoreIdent.Client (C#/F#)   │                      │
│                     │   - Secure token storage     │                      │
│                     │   - Auto token refresh       │                      │
│                     │   - PKCE flow handling       │                      │
│                     │   - Platform abstractions    │                      │
│                     └───────────────┬────────────────┘                      │
└───────────────────────────────────────┴───────────────────────────────────────┘
                                        │
                              HTTPS / OAuth 2.0
                                        │
┌───────────────────────────────────────┴───────────────────────────────────────┐
│                        SERVER / EMBEDDED AUTH                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                     CoreIdent.Core (0.4) — C# & F#                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  ┌─────────────┐  │
│  │ Auth APIs   │  │ Token Svc   │  │ Passwordless Engine     │  │ Metrics     │  │
│  │ /login      │  │ JWT/Refresh │  │ Email Magic Links       │  │ OpenTelemetry│  │
│  │ /register   │  │ RS256/ES256 │  │ Passkey (ASP.NET 10)    │  │ .NET 10     │  │
│  │ /authorize  │  │ Key Rotate  │  │ SMS (pluggable)         │  │ native      │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  └─────────────┘  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                      Extension Packages                                     │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────┐  ┌───────────────┐  │
│  │ Storage.EFCore   │  │ Providers.*      │  │ UI.Web        │  │ Client.*      │  │
│  │ Storage.Sqlite   │  │ (Google, MS,     │  │ (Razor/Blazor │  │ Client.Maui   │  │
│  │ Adapters.*       │  │  GitHub, etc.)   │  │  components)  │  │ Client.Wpf    │  │
│  └──────────────────┘  └──────────────────┘  └───────────────┘  └───────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Phased Development Plan

### Phase 0A: Foundation Reset — Crypto + Core Token Lifecycle (0.4)
**Goal:** Establish production-ready cryptographic foundation and essential OAuth/OIDC token lifecycle endpoints on **.NET 10**.

**Deliverables:**
- [ ] Migrate to .NET 10 (`net10.0` only)
- [ ] **Asymmetric key support (RS256, ES256)** — Non-negotiable for production
- [ ] Key management infrastructure (loading, rotation preparation)
- [ ] Update JWKS endpoint for asymmetric keys
- [ ] Token Revocation endpoint (RFC 7009)
- [ ] Token Introspection endpoint (RFC 7662)
- [ ] Remove/deprecate HS256-only code paths (keep as opt-in for dev/testing)

> **Note on JWT revocation:** Revoking a JWT access token only works for resource servers that perform an online check (e.g., introspection or a shared revocation store). Default guidance is short-lived access tokens + refresh token rotation/revocation. See Phase 3 for “revocable access” in controlled distributed systems.

---

### Phase 0B: Quality & DevEx — Testing, Observability, Tooling (0.4)
**Goal:** Make CoreIdent easy to test, ship, and contribute to.

**Deliverables:**
- [ ] **Unified test infrastructure** — Reusable `WebApplicationFactory` base, fixtures, seeders
- [ ] **CLI Tool (`dotnet coreident`)** — `init`, `keys generate`, `client add` commands
- [ ] **.devcontainer configuration** — One-click dev environment for contributors
- [ ] OpenTelemetry metrics integration (leverage .NET 10 built-in authentication/identity metrics)

**Why This First:** Nothing else matters if tokens can't be validated securely in production.

---

### Phase 1: Passwordless & Developer Experience
**Goal:** Make passwordless authentication trivially easy; establish the "5-minute auth" story.

**Deliverables:**
- [ ] **Email Magic Link Authentication**
  - `IEmailSender` abstraction with SMTP default implementation
  - Token generation, storage, validation flow
  - Configurable expiry, rate limiting
- [ ] **Passkey Integration** (wrapping .NET 10's built-in support)
  - Simplified configuration over `IdentityPasskeyOptions`
  - Registration and authentication ceremonies
  - Storage abstraction for credentials
- [ ] **SMS OTP** (pluggable provider interface)
  - `ISmsProvider` abstraction
  - Twilio reference implementation (separate package)
- [ ] **ClaimsPrincipal Extensions** (C# 14 extension members)
  - `User.Email`, `User.UserId`, `User.GetClaim<T>("custom")`
- [ ] **`dotnet new` Templates**
  - `coreident-api` — Minimal API with CoreIdent auth
  - `coreident-server` — Full OAuth/OIDC server setup
- [ ] **Aspire Integration** (`CoreIdent.Aspire`)
  - Pre-configured dashboard integration
  - Health checks, metrics, traces out of the box
- [ ] Comprehensive getting-started documentation

---

### Phase 2: External Provider Integration
**Goal:** Seamless integration with third-party OAuth/OIDC providers.

**Deliverables:**
- [ ] **Provider Abstraction Layer** (`CoreIdent.Providers.Abstractions`)
  - Standardized callback handling
  - User profile mapping
  - Account linking support
- [ ] **Built-in Providers**
  - Google (`CoreIdent.Providers.Google`)
  - Microsoft/Entra ID (`CoreIdent.Providers.Microsoft`)
  - GitHub (`CoreIdent.Providers.GitHub`)
- [ ] Provider configuration via `appsettings.json`
- [ ] Integration tests for each provider (using test accounts/mocks)

---

### Phase 3: OAuth/OIDC Server Hardening
**Goal:** Production-grade OAuth 2.0 / OIDC server capabilities.

**Deliverables:**
- [ ] **Key Rotation** — Automated rotation with grace period for old keys
- [ ] **Session Management** — OIDC logout, back-channel logout, session tracking
- [ ] **Dynamic Client Registration** (RFC 7591)
- [ ] **Device Authorization Flow** (RFC 8628) — For IoT/TV apps
- [ ] **Pushed Authorization Requests** (RFC 9126) — Enhanced security
- [ ] **DPoP - Demonstrating Proof of Possession** (RFC 9449) — Sender-constrained tokens
- [ ] **Rich Authorization Requests** (RFC 9396) — Fine-grained authorization
- [ ] **Token Exchange** (RFC 8693) — Impersonation, delegation, cross-service auth
- [ ] **JWT-Secured Authorization Request (JAR)** — Signed/encrypted auth requests
- [ ] **Revocable access for controlled distributed systems** — Introspection-first validation middleware + optional opaque/reference access tokens (for resource servers you control)
- [ ] **Webhook System** — Events for user.created, login, token.issued, consent.granted
- [ ] OIDC Conformance test suite integration
- [ ] Rate limiting and abuse prevention

---

### Phase 4: UI & Administration
**Goal:** Optional UI components for common flows.

**Deliverables:**
- [ ] **`CoreIdent.UI.Web`** — Razor/Blazor components
  - Login page (with passwordless options)
  - Registration page
  - Consent page
  - Account management (change email, manage passkeys)
- [ ] **Self-Service User Portal**
  - Account settings (email, password, MFA)
  - Session management (view/revoke active sessions)
  - Linked accounts management
  - Audit log viewer (user's own activity)
- [ ] **Admin API** — Programmatic user/client management
- [ ] Basic admin dashboard (optional package)
- [ ] **Multi-tenancy Support**
  - Multiple issuers in one instance
  - Per-tenant configuration (keys, providers, branding)
  - Tenant isolation and data separation

---

### Phase 5: Advanced & Community
**Goal:** Extended capabilities for specialized use cases.

**Deliverables:**
- [ ] MFA framework (TOTP, backup codes)
- [ ] Fine-grained authorization (FGA/RBAC) integration points
- [ ] Audit logging infrastructure
- [ ] Anomaly detection hooks
- [ ] Community provider packages (Apple, Twitter, LinkedIn, etc.)
- [ ] **SCIM support** (RFC 7643/7644) — User provisioning for enterprise
- [ ] **Verifiable Credentials** — W3C VC integration points
- [ ] **SPIFFE/SPIRE integration** — Workload identity for service mesh / zero-trust
- [ ] **Risk-Based Authentication**
  - Device fingerprinting
  - Geo-location checks
  - Step-up auth for sensitive operations
- [ ] **Credential Breach Detection**
  - HaveIBeenPwned API integration
  - Compromised credential alerts
- [ ] **API Gateway Integration Patterns**
  - YARP integration examples
  - Token exchange for downstream services
- [ ] **Blazor Server Integration** (`CoreIdent.Client.BlazorServer`)
  - Circuit-aware token management
  - Server-side session handling

---

## Future Protocol Watch List

These protocols are emerging or specialized; tracked for potential inclusion:

| Protocol | Status | Notes |
|----------|--------|-------|
| **GNAP** (Grant Negotiation and Authorization Protocol) | IETF Draft | Potential OAuth successor; watching for standardization |
| **OpenID Federation** | Draft | Trust chain management for large ecosystems |
| **Selective Disclosure JWT (SD-JWT)** | Draft | Privacy-preserving credentials |
| **SPIFFE/SPIRE** | CNCF Graduated | Workload identity; consider `CoreIdent.Identity.Spiffe` package |

---

## Removed from Roadmap

The following were in the original roadmap but are **removed** or **deferred indefinitely**:

| Feature | Reason |
|---------|--------|
| **Web3 Wallet Login** | Niche adoption; community can add if needed |
| **LNURL-auth** | Very niche (Bitcoin Lightning); not mainstream |
| **AI Framework SDK Integrations** | Premature; unclear requirements |
| **CIBA for AI Actions** | Specialized; defer until clear demand |
| **Token Vault / Secrets Management** | Out of scope; use dedicated tools (Azure Key Vault, etc.) |

---

## Test Infrastructure Vision

### Problems with Current Test Harness
1. **Duplicated `WebApplicationFactory` setup** across test classes
2. **Inconsistent seeding** — Each test class seeds differently
3. **Cookie/auth handling complexity** — Multiple auth schemes, manual cookie management
4. **SQLite connection lifecycle issues** — Connection management scattered

### New Test Architecture

```
CoreIdent.Testing/
├── Fixtures/
│   ├── CoreIdentTestFixture.cs      # Base fixture with DI, DB, seeding
│   ├── AuthenticatedTestFixture.cs  # Pre-authenticated user context
│   └── OAuthServerTestFixture.cs    # Full OAuth flow testing
├── Builders/
│   ├── TestUserBuilder.cs           # Fluent user creation
│   ├── TestClientBuilder.cs         # Fluent OAuth client creation
│   └── TestScopeBuilder.cs          # Fluent scope creation
├── Extensions/
│   ├── HttpClientExtensions.cs      # .WithTestUser(), .WithBearerToken()
│   └── AssertionExtensions.cs       # .ShouldBeValidJwt(), .ShouldHaveClaim()
└── Mocks/
    ├── MockEmailSender.cs           # Captures sent emails for verification
    └── MockSmsProvider.cs           # Captures sent SMS for verification
```

**Usage Example:**
```csharp
public class LoginTests : CoreIdentTestFixture
{
    [Fact]
    public async Task Login_WithValidCredentials_ReturnsTokens()
    {
        // Arrange
        var user = await CreateUser(u => u.WithEmail("test@example.com").WithPassword("Test123!"));
        
        // Act
        var response = await Client.PostAsJsonAsync("/auth/login", new { 
            Email = "test@example.com", 
            Password = "Test123!" 
        });
        
        // Assert
        response.ShouldBeSuccessful();
        var tokens = await response.Content.ReadFromJsonAsync<TokenResponse>();
        tokens.AccessToken.ShouldBeValidJwt()
            .ShouldHaveClaim("sub", user.Id);
    }
}
```

---

## Success Metrics

| Metric | Target |
|--------|--------|
| **Time to first auth** | < 5 minutes for basic setup |
| **Test coverage** | > 80% on core packages |
| **NuGet downloads** | Organic growth indicator |
| **GitHub stars** | Community interest indicator |
| **Issues resolved** | Responsiveness indicator |

---

## Migration from 0.3.x

Existing 0.3.x users will need to:

1. **Update target framework** to `net10.0`
2. **Configure asymmetric keys** — HS256 will be deprecated for production
3. **Update token validation** — Resource servers need public key, not shared secret
4. **Review breaking changes** in `MIGRATION.md` (to be created)

---

## Contributing

See `CONTRIBUTING.md` for guidelines. Key areas for contribution:

- Additional external providers
- Storage adapters (MongoDB, Redis, etc.)
- UI themes and components
- Documentation and examples
- Translations

---

## License

MIT License — Use freely, contribute back if you can.
