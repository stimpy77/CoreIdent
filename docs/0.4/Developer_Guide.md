# CoreIdent 0.4 Developer Guide

This guide documents the **CoreIdent 0.4** codebase (a ground-up rewrite from 0.3). It is intended to be the “one stop” developer reference for:

- Getting a host app running quickly
- Understanding how CoreIdent is structured
- Configuring keys, routes, clients, and scopes
- Using the OAuth/OIDC endpoints CoreIdent currently implements
- Persisting CoreIdent state with EF Core
- Writing unit/integration tests using the provided test infrastructure

## You will achieve

- Run a minimal CoreIdent host and exercise key endpoints
- Configure signing keys, routes, clients, and scopes
- Enable persistence with EF Core
- Understand the implemented endpoint surface and how to map it

If you are looking for the high-level roadmap and design intent, start with:

- `docs/0.4/Project_Overview.md`
- `docs/0.4/Technical_Plan.md`
- `docs/0.4/DEVPLAN.md`
- `docs/0.4/Passkeys.md`
- `docs/0.4/Aspire_Integration.md`

---

## What CoreIdent 0.4 is today

CoreIdent 0.4 currently provides a **minimal, modular OAuth/OIDC foundation** on .NET 10:

- **JWT token issuance** (`/auth/token`)
  - `client_credentials`
  - `refresh_token`
  - `authorization_code` (with PKCE)
  - `password` (implemented but **deprecated** and logs a warning)
- **Token revocation** (`/auth/revoke`, RFC 7009)
- **Token introspection** (`/auth/introspect`, RFC 7662)
- **Discovery document** (OIDC metadata)
- **JWKS publishing** (public keys only)
- **Authorization endpoint** (`/auth/authorize`) + **minimal consent UI** (`/auth/consent`) for authorization code flow
- **Resource-owner convenience endpoints** (`/auth/register`, `/auth/login`, `/auth/profile`) for simple “first party app” workflows
- **Pluggable stores** with in-memory defaults + EF Core implementations in `CoreIdent.Storage.EntityFrameworkCore`
- A **testing package** (`tests/CoreIdent.Testing`) with fixtures and builders for integration tests

CoreIdent is not trying to be “everything at once” yet. The focus of 0.4 is **secure defaults** (asymmetric signing by default) and **testable primitives**.

---

## Repository structure

At a high level:

- `src/CoreIdent.Core/`
  - Core models, options, store interfaces, in-memory stores, services, endpoint mapping extensions
- `src/CoreIdent.Storage.EntityFrameworkCore/`
  - EF Core `DbContext`, entity models, and EF Core implementations of stores
- `src/CoreIdent.Adapters.DelegatedUserStore/`
  - Adapter package for plugging in an external user store (if used)
- `tests/CoreIdent.Core.Tests/`
  - Unit + integration tests for the core package
- `tests/CoreIdent.Testing/`
  - Shared test infrastructure: `WebApplicationFactory`, fixture base class, builders, assertion extensions
- `tests/CoreIdent.TestHost/`
  - A minimal runnable host used by some tests and manual validation
- `src/CoreIdent.Cli/`
  - CLI tool package (`dotnet coreident`) for project scaffolding, key generation, and database migrations

---

## CLI Tool

CoreIdent ships a .NET global tool for common development tasks:

```bash
dotnet tool install -g CoreIdent.Cli
```

Commands:

- `dotnet coreident init` — Scaffold `appsettings.json` and add package references
- `dotnet coreident keys generate <rsa|ecdsa>` — Generate signing key pairs
- `dotnet coreident client add` — Interactive client registration helper
- `dotnet coreident migrate` — Apply database schema (SQLite, SQL Server, PostgreSQL)

See [`docs/0.4/CLI_Reference.md`](CLI_Reference.md) for full documentation.

---

## Prerequisites

- **.NET 10 SDK** (required)
- Recommended:
  - SQLite tooling (optional; used by tests/fixtures)
  - OpenSSL (optional; useful for key generation)

---

# 1. Quick start

## 1.1 Minimal “OAuth server” host

This is the smallest “real” CoreIdent host app setup:

- configure issuer/audience
- configure a signing key (RSA or ECDSA for production)
- map CoreIdent endpoints

Key points:

- `AddCoreIdent()` registers all core services and **in-memory stores by default**.
- `AddSigningKey(...)` registers an `ISigningKeyProvider` used by token services and JWKS.
- `MapCoreIdentEndpoints()` maps all CoreIdent endpoints using `CoreIdentRouteOptions`.

### Example (Program.cs)

```csharp
using CoreIdent.Core.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCoreIdent(o =>
{
    o.Issuer = "https://issuer.example";
    o.Audience = "https://resource.example";
});

// Production: prefer RSA/ECDSA.
// Example: load RSA from PEM file
builder.Services.AddSigningKey(o => o.UseRsa("/path/to/private-key.pem"));

var app = builder.Build();

app.MapCoreIdentEndpoints();

app.Run();
```

### What you get

With defaults, CoreIdent maps:

- OpenID Connect discovery document: `GET <issuerPath>/.well-known/openid-configuration`
- JWKS: `GET <issuerPath>/.well-known/jwks.json`
- Authorization endpoint: `GET /auth/authorize`
- Consent UI: `GET/POST /auth/consent`
- Token endpoint: `POST /auth/token`
- Token management:
  - `POST /auth/revoke`
  - `POST /auth/introspect`
- Resource owner endpoints:
  - `GET/POST /auth/register`
  - `GET/POST /auth/login`
  - `GET /auth/profile`
- Passwordless email magic link:
  - `POST /auth/passwordless/email/start`
  - `GET /auth/passwordless/email/verify`
- Passwordless SMS OTP:
  - `POST /auth/passwordless/sms/start`
  - `POST /auth/passwordless/sms/verify`
- Passkeys (WebAuthn): see `docs/0.4/Passkeys.md` (mapped via `app.MapCoreIdentPasskeyEndpoints()`)

> Note: discovery and JWKS are computed based on the `Issuer` URL’s **path** (see “Routing” below). They are not hardcoded to root.

---

## 1.2 Run the test host

A runnable host exists at `tests/CoreIdent.TestHost/Program.cs`. It configures:

- `AddCoreIdent(...)`
- `AddSigningKey(o => o.UseSymmetric(...))` (**development/testing only**)
- EF Core `CoreIdentDbContext` (SQLite)
- `AddEntityFrameworkCoreStores()` to use EF-backed stores
- ASP.NET authentication with a test header auth handler

This is a convenient way to manually poke endpoints.

---

## 1.3 Scaffold a host with `dotnet new`

CoreIdent ships a template pack (`CoreIdent.Templates`) that contains starter host projects.

Install the templates:

```bash
dotnet new install CoreIdent.Templates
```

Available templates:

- **`coreident-api`** (C#)
  - Minimal host for CoreIdent endpoints.
  - Parameters:
    - `--useEfCore <true|false>` (default: `true`)
    - `--usePasswordless <true|false>` (default: `true`)
- **`coreident-server`** (C#)
  - Full OAuth/OIDC server host (EF Core stores) with optional passkey endpoints.
  - Parameters:
    - `--usePasskeys <true|false>` (default: `true`)
    - `--usePasswordless <true|false>` (default: `true`)
- **`coreident-api-fsharp`** (F#)
  - Minimal host for CoreIdent endpoints.
  - Parameters:
    - `--useEfCore <true|false>` (default: `true`)
    - `--usePasswordless <true|false>` (default: `true`)

Examples:

```bash
dotnet new coreident-api -n MyCoreIdentApi
dotnet new coreident-api -n MyCoreIdentApiNoEf --useEfCore false

dotnet new coreident-server -n MyCoreIdentServer
dotnet new coreident-server -n MyCoreIdentServerNoPasskeys --usePasskeys false

dotnet new coreident-api-fsharp -n MyCoreIdentApiFSharp
dotnet new coreident-api-fsharp -n MyCoreIdentApiFSharpNoEf --useEfCore false
```

Each template includes a sample `appsettings.json` with required `CoreIdent` configuration (issuer, audience, dev signing key) and, when applicable, a SQLite connection string.

---

# 2. Configuration and dependency injection

## 2.1 Core options (`CoreIdentOptions`)

`CoreIdentOptions` includes:

- `Issuer` (required)
- `Audience` (required)
- `AccessTokenLifetime` (default: 15 minutes)
- `RefreshTokenLifetime` (default: 7 days)

`AddCoreIdent()` registers a validator (`CoreIdentOptionsValidator`) and calls `ValidateOnStart()`. If required values are missing or invalid, the app will fail fast at startup.

### Important behavior

- Many endpoints and services assume `Issuer` and `Audience` are non-null once validated.
- The `ITokenService` (JWT token creation) requires issuer/audience per call.

---

## 2.2 Route options (`CoreIdentRouteOptions`)

`CoreIdentRouteOptions` controls how endpoint routes are assembled.

Defaults:

- `BasePath = "/auth"`
- Relative paths under base:
  - `AuthorizePath = "authorize"`
  - `TokenPath = "token"`
  - `RevocationPath = "revoke"`
  - `IntrospectionPath = "introspect"`
  - `ConsentPath = "consent"`
  - `UserInfoPath = "userinfo"` (future)
  - `RegisterPath = "register"`
  - `LoginPath = "login"`
  - `ProfilePath = "profile"`
- Root-ish helper:
  - `UserProfilePath = "/me"` (host-friendly convenience route; not currently mapped by `MapCoreIdentEndpoints()`)

### How route composition works

- `CombineWithBase(path)`:
  - If `path` starts with `/`, it is treated as root-relative and returned normalized.
  - Otherwise it returns `BasePath + "/" + path` normalized.

### Discovery and JWKS paths are derived from Issuer

If `DiscoveryPath` and `JwksPath` are not explicitly set:

- `GetDiscoveryPath(CoreIdentOptions)` returns:
  - `"<issuerPath>/.well-known/openid-configuration"`
- `GetJwksPath(CoreIdentOptions)` returns:
  - `"<issuerPath>/.well-known/jwks.json"`

Where `issuerPath` is the **path component** of `Issuer`:

- If `Issuer = "https://example.com"` → issuerPath is empty → discovery is `/.well-known/openid-configuration`
- If `Issuer = "https://example.com/auth"` → issuerPath is `/auth` → discovery is `/auth/.well-known/openid-configuration`

This makes it possible to host CoreIdent under a path while still generating correct issuer-relative discovery URLs.

---

## 2.3 AddCoreIdent and default registrations

`builder.Services.AddCoreIdent(...)` registers:

- Options:
  - `CoreIdentOptions`
  - `CoreIdentRouteOptions`
  - `CoreIdentResourceOwnerOptions`
  - `CoreIdentAuthorizationCodeOptions`
  - `PasswordlessEmailOptions`
  - `PasswordlessSmsOptions`
  - `SmtpOptions`
- Core services:
  - `ITokenService` → `JwtTokenService`
  - `IClientSecretHasher` → `DefaultClientSecretHasher`
  - `IPasswordHasher` → `DefaultPasswordHasher`
  - `ICustomClaimsProvider` → `NullCustomClaimsProvider`
  - `TimeProvider` → `TimeProvider.System`
  - `IEmailSender` → `SmtpEmailSender`
- `ISmsProvider` → `ConsoleSmsProvider`
  - `PasswordlessEmailTemplateRenderer`
- In-memory stores (defaults):
  - `IClientStore` → `InMemoryClientStore`
  - `IScopeStore` → `InMemoryScopeStore` (pre-seeded with standard OIDC scopes)
  - `IRefreshTokenStore` → `InMemoryRefreshTokenStore`
  - `IAuthorizationCodeStore` → `InMemoryAuthorizationCodeStore`
  - `IUserGrantStore` → `InMemoryUserGrantStore`
  - `ITokenRevocationStore` → `InMemoryTokenRevocationStore`
  - `IUserStore` → `InMemoryUserStore`
  - `IPasswordlessTokenStore` → `InMemoryPasswordlessTokenStore`
- Hosted service:
  - `AuthorizationCodeCleanupHostedService`

---

## 2.4 Metrics and observability

CoreIdent emits metrics using `System.Diagnostics.Metrics`.

### Enable CoreIdent-specific metrics

By default, CoreIdent registers a no-op metrics sink.

To enable CoreIdent metrics emission:

```csharp
builder.Services.AddCoreIdent(...);
builder.Services.AddCoreIdentMetrics();
```

### CoreIdent metric names

**Counters:**
- `coreident.client.authenticated` — Number of client authentication attempts
- `coreident.token.issued` — Number of tokens issued
- `coreident.token.revoked` — Number of tokens revoked

**Histograms:**
- `coreident.client.authentication.duration` — Duration of client authentication (ms)
- `coreident.token.issuance.duration` — Duration of token issuance (ms)

### Metric tags

- `coreident.client.authenticated`
  - `client_type` (`public` / `confidential` / `unknown`)
  - `success` (`true` / `false`)
- `coreident.token.issued`
  - `token_type` (`access_token` / `refresh_token` / `id_token`)
  - `grant_type` (e.g. `client_credentials`, `authorization_code`, `refresh_token`, `password`)
- `coreident.token.revoked`
  - `token_type` (`access_token` / `refresh_token`)

### Filtering and sampling

You can configure filtering and sampling when enabling metrics:

```csharp
builder.Services.AddCoreIdentMetrics(o =>
{
    o.SampleRate = 1.0;
    o.Filter = ctx => ctx.MetricName != "coreident.token.issued";
});
```

### Built-in ASP.NET Core metrics

.NET 10 already emits metrics for:

- `aspnetcore.authentication.*`
- `aspnetcore.identity.*`

CoreIdent metrics are intended to complement these with OAuth/OIDC-specific counters.

### Overriding defaults

All store and service registrations use `TryAdd*` patterns so you can override them by registering your own implementations **before** calling `AddCoreIdent()` (or by replacing registrations explicitly).

### Delegated user store adapter (integrate existing user systems)

If you already have an existing user system (database + credential verification) and you want CoreIdent to **delegate user lookup and credential validation**, use `CoreIdent.Adapters.DelegatedUserStore`.

Registration:

```csharp
using CoreIdent.Adapters.DelegatedUserStore.Extensions;

builder.Services.AddCoreIdentDelegatedUserStore(o =>
{
    o.FindUserByIdAsync = (id, ct) => myUsers.FindByIdAsync(id, ct);
    o.FindUserByUsernameAsync = (username, ct) => myUsers.FindByUsernameAsync(username, ct);
    o.ValidateCredentialsAsync = (user, password, ct) => myUsers.ValidatePasswordAsync(user, password, ct);

    // Optional: provide claims that will be emitted into tokens.
    o.GetClaimsAsync = (subjectId, ct) => myUsers.GetClaimsAsync(subjectId, ct);
});
```

Notes:

- The adapter **replaces** `IUserStore` and `IPasswordHasher` registrations.
- CoreIdent will **not** store password hashes when using this adapter (credential validation is delegated).
- You are responsible for:
  - secure credential storage and verification (hashing, rate limiting, lockout, MFA, etc.)
  - preventing credential leakage in logs and telemetry
  - ensuring usernames are normalized consistently with your system

---

# 3. Signing keys and JWKS

CoreIdent uses `ISigningKeyProvider` to:

- provide `SigningCredentials` for token creation
- provide validation keys for token verification / JWKS publishing

## 3.1 Configure signing keys (`AddSigningKey`)

`AddSigningKey(...)` configures `CoreIdentKeyOptions` using `CoreIdentKeyOptionsBuilder`:

- `UseRsa(string keyPath)`
- `UseRsaPem(string pemString)`
- `UseEcdsa(string keyPath)`
- `UseSymmetric(string secret)` (**development/testing only**)

### RSA provider notes

- The RSA provider (`RsaSigningKeyProvider`) supports:
  - PEM string
  - PEM file
  - X509 certificate (PFX)
  - fallback: generate an ephemeral RSA key **with a warning**
- Key IDs (`kid`) are computed from the SHA-256 hash of the public key.

### ECDSA provider notes

- The ECDSA provider supports:
  - PEM string
  - PEM file
  - X509 certificate
  - fallback: generate ephemeral P-256 key (ES256) **with a warning**

### Symmetric (HS256) notes

- `SymmetricSigningKeyProvider` logs a warning at startup.
- Symmetric keys are **not published** via JWKS.
- Secret must be at least **32 bytes**.

---

## 3.2 JWKS endpoint

The JWKS endpoint returns a JSON Web Key Set:

- RSA keys are output with `kty=RSA`, `n`, `e`, `kid`, `alg=RS256`
- EC keys are output with `kty=EC`, `crv`, `x`, `y`, `kid`, `alg=ES256`
- Symmetric keys are **skipped** (not published)

This is intentionally “safe by default” (no shared secrets exposed).

---

# 4. Endpoints and flows

## 4.1 Endpoint mapping overview

### Map everything

`app.MapCoreIdentEndpoints()` maps all current endpoints.

### Map only what you want

If you want a more controlled surface area, map individual endpoints:

- `MapCoreIdentOpenIdConfigurationEndpoint(coreOptions, routeOptions)`
- `MapCoreIdentDiscoveryEndpoints(jwksPath)`
- `MapCoreIdentAuthorizeEndpoint(authorizePath)`
- `MapCoreIdentConsentEndpoints(consentPath)`
- `MapCoreIdentTokenEndpoint(tokenPath)`
- `MapCoreIdentTokenManagementEndpoints(revokePath, introspectPath)`
- `MapCoreIdentResourceOwnerEndpoints(registerPath, loginPath, profilePath)`

---

## 4.2 OIDC discovery document

The discovery endpoint returns an `OpenIdConfigurationDocument` that includes:

- `issuer`
- `jwks_uri`
- `token_endpoint`
- `revocation_endpoint`
- `introspection_endpoint`
- `scopes_supported` (pulled from `IScopeStore.GetAllAsync()`, filtered by `ShowInDiscoveryDocument`)
- `id_token_signing_alg_values_supported` (from `ISigningKeyProvider.Algorithm`)

> `grant_types_supported` is currently returned as an empty list in the implementation (even though token endpoint supports multiple grants). This is an implementation detail worth revisiting, but the guide documents current behavior.

---

## 4.3 Token endpoint (`POST /auth/token`)

The token endpoint expects:

- `Content-Type: application/x-www-form-urlencoded`
- Client authentication:
  - Prefer `Authorization: Basic base64(client_id:client_secret)`
  - Or form params `client_id`, `client_secret`

### Supported grant types

- `client_credentials`
- `refresh_token`
- `authorization_code`
- `password` (**deprecated**; logs warning)

### Token response

The endpoint returns `TokenResponse`:

- `access_token` (JWT)
- `token_type` ("Bearer")
- `expires_in` (seconds)
- `refresh_token` (when applicable)
- `scope` (space-delimited, when applicable)
- `id_token` (only for `authorization_code` when scope includes `openid`)

### Scopes behavior

- If the request does not include `scope`, CoreIdent grants the client’s `AllowedScopes`.
- If the request includes `scope`, CoreIdent intersects requested scopes with client’s `AllowedScopes`.

---

## 4.4 Refresh tokens

Refresh tokens are stored via `IRefreshTokenStore` as `CoreIdentRefreshToken` records.

Important security properties:

- Refresh token **rotation** is implemented:
  - The old token is consumed (`ConsumedAt` set).
  - A new token is issued.
- **Theft detection** is implemented:
  - If a consumed refresh token is reused, CoreIdent revokes the entire token family (`FamilyId`).

### Offline access gating

Refresh tokens are only minted in some flows when:

- client has `AllowOfflineAccess = true`, and
- granted scopes include `offline_access`

---

## 4.5 Authorization code flow (PKCE)

CoreIdent implements:

- Authorization endpoint: `GET /auth/authorize`
- Consent endpoint (when client requires consent): `GET/POST /auth/consent`
- Token exchange: `POST /auth/token` with `grant_type=authorization_code`

### `/auth/authorize` requirements

- `client_id` (required)
- `redirect_uri` (required)
- `response_type=code` (required)
- `state` (required)
- PKCE is required:
  - `code_challenge` (required)
  - `code_challenge_method=S256` (required)
- `scope` (optional)
- `nonce` (optional; used for id_token issuance)

### Authentication requirement

The authorize endpoint uses ASP.NET authentication:

- If `HttpContext.User.Identity.IsAuthenticated` is false, it returns `Results.Challenge()`.

That means **your host app must configure authentication** (cookies, external provider, etc.) for interactive login.

### Consent

If `client.RequireConsent == true`:

- CoreIdent checks `IUserGrantStore.HasUserGrantedConsentAsync(...)`.
- If consent is missing, it redirects to `ConsentPath`.
- Consent UI is a minimal HTML form.

### Authorization code store

Authorization codes are stored via `IAuthorizationCodeStore`.

- Default is `InMemoryAuthorizationCodeStore`.
- Codes are single-use (`ConsumedAt` is set on consume).
- Cleanup runs periodically via `AuthorizationCodeCleanupHostedService`.

---

## 4.6 Resource-owner convenience endpoints

CoreIdent includes **non-OIDC** convenience endpoints for quick “auth for my app” workflows:

- `GET/POST /auth/register`
- `GET/POST /auth/login`
- `GET /auth/profile`

### Content negotiation

These endpoints return JSON when:

- `Accept: application/json`, or
- `Content-Type: application/json`

Otherwise they return minimal HTML.

### `/auth/profile` token validation

`/auth/profile` validates bearer tokens itself using:

- `ISigningKeyProvider.GetValidationKeysAsync()`
- `Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler.ValidateTokenAsync`

It does not rely on ASP.NET `JwtBearer` middleware.

This makes it useful for quick starts, but if you’re building a larger system you’ll typically configure JWT authentication in the host instead.

### Customizing resource-owner responses

You can override result handling using:

```csharp
builder.Services.ConfigureResourceOwnerEndpoints(options =>
{
    options.RegisterHandler = (http, user, ct) => Task.FromResult<IResult?>(Results.Redirect("/welcome"));
    options.LoginHandler = (http, user, tokens, ct) => Task.FromResult<IResult?>(Results.Json(new { tokens.AccessToken }));
    options.ProfileHandler = (http, user, claims, ct) => Task.FromResult<IResult?>(Results.Ok());
});
```

Returning `null` falls back to CoreIdent defaults.

---

## 4.7 Passwordless email magic link (Feature 1.1)

CoreIdent provides a simple passwordless flow using **email magic links**:

- `POST /auth/passwordless/email/start` — request a sign-in link
- `GET /auth/passwordless/email/verify?token=...` — verify the token, create/find the user, and issue tokens

### 4.7.1 Start endpoint (`POST /auth/passwordless/email/start`)

Request body (JSON):

```json
{ "email": "user@example.com" }
```

Behavior:

- Always returns `200 OK` (does not leak whether a user exists)
- Generates a secure random token and stores **only a hash** via `IPasswordlessTokenStore`
- Enforces per-email rate limiting (`PasswordlessEmailOptions.MaxAttemptsPerHour`)
- Sends an email using `IEmailSender` with a link to the verify endpoint

### 4.7.2 Verify endpoint (`GET /auth/passwordless/email/verify`)

Behavior:

- Validates and consumes the token (single-use)
- Creates the user if not found (`IUserStore`)
- Issues an access token + refresh token
- If `PasswordlessEmailOptions.SuccessRedirectUrl` is set, redirects there and appends:
  - `access_token`, `refresh_token`, `token_type=Bearer`, `expires_in`

If the token is invalid, expired, or already consumed, it returns `400 Bad Request`.

### 4.7.3 Configuration (`PasswordlessEmailOptions`)

```csharp
builder.Services.Configure<PasswordlessEmailOptions>(opts =>
{
    opts.TokenLifetime = TimeSpan.FromMinutes(15);
    opts.MaxAttemptsPerHour = 5;
    opts.EmailSubject = "Sign in to {AppName}";

    // Relative by default; combined with CoreIdentRouteOptions.BasePath
    opts.VerifyEndpointUrl = "passwordless/email/verify";

    // Optional redirect that receives tokens in query string
    opts.SuccessRedirectUrl = "https://client.example/signed-in";

    // Optional custom HTML template
    // opts.EmailTemplatePath = "EmailTemplates/passwordless.html";
});
```

### 4.7.4 SMTP configuration (default `SmtpEmailSender`)

CoreIdent defaults `IEmailSender` to an SMTP implementation. Configure it via `SmtpOptions`.

Example `appsettings.json`:

```json
{
  "SmtpOptions": {
    "Host": "smtp.example.com",
    "Port": 587,
    "EnableTls": true,
    "UserName": "smtp-user",
    "Password": "smtp-password",
    "FromAddress": "no-reply@example.com",
    "FromDisplayName": "CoreIdent"
  }
}
```

And bind options:

```csharp
builder.Services.Configure<SmtpOptions>(builder.Configuration.GetSection("SmtpOptions"));
```

### 4.7.5 Email template customization

CoreIdent renders a simple HTML email containing a verify link.

- Default template is built into `PasswordlessEmailTemplateRenderer`.
- To provide your own template, set `PasswordlessEmailOptions.EmailTemplatePath`.
  - If the path is relative, it is resolved relative to `IHostEnvironment.ContentRootPath`.

Available placeholders:

- `{AppName}` — `IHostEnvironment.ApplicationName`
- `{Email}` — recipient email
- `{VerifyUrl}` — absolute verify URL

### 4.7.6 Provider email APIs (recommended for production)

Recommendation:

- SMTP is great for demos and small self-hosted deployments.
- For production, many teams prefer provider email APIs (SendGrid, Postmark, Mailgun, AWS SES, Azure Communication Services) for deliverability and operational convenience.

CoreIdent is designed to be extended without forking:

1. Implement `IEmailSender` in your host app or a separate package.
2. Register it in DI to override the default SMTP sender.

Example:

```csharp
public sealed class MyProviderEmailSender : IEmailSender
{
    public Task SendAsync(EmailMessage message, CancellationToken ct = default)
    {
        // Call your provider API here.
        throw new NotImplementedException();
    }
}

builder.Services.AddSingleton<IEmailSender, MyProviderEmailSender>();
builder.Services.AddCoreIdent(...);
```

Because CoreIdent uses `TryAdd*` for defaults, registering `IEmailSender` before `AddCoreIdent()` will take precedence.

---

## 4.8 Passwordless SMS OTP (Feature 1.3)

CoreIdent provides a simple passwordless flow using **SMS one-time passcodes**:

- `POST /auth/passwordless/sms/start` — request an OTP
- `POST /auth/passwordless/sms/verify` — verify the OTP, create/find the user, and issue tokens

### 4.8.1 Start endpoint (`POST /auth/passwordless/sms/start`)

Request body (JSON):

```json
{ "phone_number": "+15551234567" }
```

Phone numbers must be in E.164 format (for example: `+15551234567`). CoreIdent applies minimal normalization before validation (trims whitespace, removes spaces/hyphens/parentheses, and converts a leading `00` prefix to `+`).

Behavior:

- Always returns `200 OK` (does not leak whether a user exists)
- If the phone number is missing or invalid, CoreIdent still returns `200 OK` with the same response message
- Generates a 6-digit numeric OTP and stores **only a hash** via `IPasswordlessTokenStore`
- Enforces per-phone rate limiting (`PasswordlessSmsOptions.MaxAttemptsPerHour`)
- Sends an SMS using `ISmsProvider`

### 4.8.2 Verify endpoint (`POST /auth/passwordless/sms/verify`)

Request body (JSON):

```json
{ "phone_number": "+15551234567", "otp": "123456" }
```

Behavior:

- Validates and consumes the OTP (single-use)
- Creates the user if not found (`IUserStore`)
- Issues an access token + refresh token

If the phone number is missing or invalid, or if the OTP is invalid, expired, or already consumed, it returns `400 Bad Request`.

### 4.8.3 Configuration (`PasswordlessSmsOptions`)

```csharp
builder.Services.Configure<PasswordlessSmsOptions>(opts =>
{
    opts.OtpLifetime = TimeSpan.FromMinutes(5);
    opts.MaxAttemptsPerHour = 5;
});
```

### 4.8.4 Providing an SMS provider

CoreIdent registers a default `ConsoleSmsProvider` for development.

To use a real provider, register your own `ISmsProvider` implementation:

```csharp
builder.Services.AddSingleton<ISmsProvider, MySmsProvider>();
```
---

# 5. Token revocation and resource server enforcement

## 5.1 Revocation endpoint (`POST /auth/revoke`, RFC 7009)

- Requires form content type
- Requires client authentication for confidential clients
- Returns `200 OK` even for invalid/unknown tokens (privacy semantics)

Revocation behavior:

- If token looks like a JWT (or `token_type_hint=access_token`):
  - CoreIdent validates signature (without issuer/audience checks), extracts `jti`, and stores revocation via `ITokenRevocationStore`.
- Otherwise (or `token_type_hint=refresh_token`):
  - CoreIdent attempts refresh token revocation via `IRefreshTokenStore.RevokeAsync`.

Client ownership checks:

- If token belongs to a different client, CoreIdent returns `200 OK` but does not revoke.

---

## 5.2 Enforcing revocation for JWTs

**JWTs are stateless**; revocation only works if resource servers check revocation status.

CoreIdent provides middleware:

- `app.UseCoreIdentTokenRevocation()`

This middleware checks:

- If the current request is authenticated
- If the principal contains a `jti` claim
- If `ITokenRevocationStore.IsRevokedAsync(jti)` is true → respond `401 Unauthorized`

### Typical resource server pipeline

```csharp
app.UseAuthentication();
app.UseCoreIdentTokenRevocation();
app.UseAuthorization();
```

Notes:

- You still need JWT validation (`AddAuthentication().AddJwtBearer(...)`) in the resource server.
- Revocation middleware adds the “online check” layer.

---

# 6. Token introspection (`POST /auth/introspect`, RFC 7662)

- Requires form content type
- Requires client authentication (resource server credentials)
- Returns:
  - `{ "active": false }` for unknown/invalid/expired/revoked tokens
  - RFC 7662-compatible payload for active tokens

Introspection supports:

- Access tokens (JWT): validates signature, checks expiry, checks revocation store
- Refresh tokens: checks store state (`IsRevoked`, `ConsumedAt`, `ExpiresAt`)

---

# 7. Clients and scopes

## 7.1 Clients (`CoreIdentClient`)

`CoreIdentClient` is the central configuration for OAuth clients.

Notable fields:

- `ClientId`
- `ClientSecretHash` (confidential clients)
- `ClientType` (`Public` or `Confidential`)
- `AllowedGrantTypes`
- `AllowedScopes`
- `RedirectUris`
- `RequirePkce`
- `RequireConsent`
- `AllowOfflineAccess`
- Token lifetimes:
  - `AccessTokenLifetimeSeconds`
  - `RefreshTokenLifetimeSeconds`

### Client authentication

- Confidential clients must authenticate and must have a secret.
- Public clients should use PKCE and typically don’t use a client secret.

---

## 7.2 Scopes (`CoreIdentScope` and `StandardScopes`)

CoreIdent includes standard scope constants:

- `openid`
- `profile`
- `email`
- `address`
- `phone`
- `offline_access`

Default in-memory scope store seeds these standard scopes.

---

# 8. Persistence with EF Core

The EF Core package provides:

- `CoreIdentDbContext`
- Entities:
  - `ClientEntity`, `ScopeEntity`, `RefreshTokenEntity`, `AuthorizationCodeEntity`, `UserGrantEntity`, `UserEntity`, `RevokedToken`
- Store implementations

## 8.1 Registration order

When using EF-backed stores, use this order:

1. `AddCoreIdent(...)`
2. `AddDbContext<CoreIdentDbContext>(...)`
3. `AddEntityFrameworkCoreStores()`

Example:

```csharp
builder.Services.AddCoreIdent(o =>
{
    o.Issuer = "https://issuer.example";
    o.Audience = "https://resource.example";
});

builder.Services.AddSigningKey(o => o.UseRsa("/path/to/private-key.pem"));

builder.Services.AddDbContext<CoreIdentDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddEntityFrameworkCoreStores();
```

## 8.2 Migrations

CoreIdent does not run migrations for you. Your host app owns migrations and schema management.

- Use `EnsureCreated()` for quick dev prototypes
- Use migrations for production

---

# 9. Testing CoreIdent

CoreIdent includes a dedicated testing package:

- `tests/CoreIdent.Testing`

## 9.1 Core fixtures

### `CoreIdentWebApplicationFactory`

- Uses SQLite in-memory
- Registers EF Core stores via `AddEntityFrameworkCoreStores()`
- Seeds standard scopes via `StandardScopes.All`

### `CoreIdentTestFixture`

Provides:

- `Client` (`HttpClient`)
- `Services` (`IServiceProvider`)
- Helpers:
  - `CreateUserAsync(...)`
  - `CreateClientAsync(...)`
  - `AuthenticateAsAsync(user)` (sets test headers for the test auth scheme)

## 9.2 Builders

- `UserBuilder`
  - `.WithEmail(...)`, `.WithPassword(...)`, `.WithClaim(...)`
- `ClientBuilder`
  - `.WithClientId(...)`, `.WithSecret(...)`, `.WithGrantTypes(...)`, `.WithScopes(...)`, `.WithRedirectUris(...)`, `.RequireConsent(...)`, `.AsPublicClient()`, etc.

## 9.3 Assertion helpers

- `HttpResponseAssertionExtensions`
  - `.ShouldBeSuccessful()`
  - `.ShouldBeSuccessfulWithContent<T>()`
  - `.ShouldBeUnauthorized()`
  - `.ShouldBeBadRequest(contains: ...)`

There is also a `JwtAssertionExtensions` helper (see `tests/CoreIdent.Testing/Extensions/JwtAssertionExtensions.cs`).

---

# 10. Tutorials

## 10.1 Tutorial: issue a client_credentials token

1. Register a confidential client in the store with:
   - `AllowedGrantTypes` containing `client_credentials`
   - `AllowedScopes` containing your API scope (e.g. `api`)
2. Call:

```http
POST /auth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=client_credentials&scope=api
```

3. Validate the returned `access_token` using your JWT validation stack + the published JWKS.

## 10.2 Tutorial: refresh a token

1. Ensure client supports `refresh_token` and (when minted from interactive/user flows) has `AllowOfflineAccess=true`.
2. Exchange:

```http
POST /auth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=refresh_token&refresh_token=<handle>
```

CoreIdent will rotate refresh tokens and detect reuse.

## 10.3 Tutorial: authorization code + PKCE (with consent)

1. Configure your host app authentication (cookies, external provider, etc.) so `/auth/authorize` can authenticate a user.
2. Configure client:
   - `AllowedGrantTypes` includes `authorization_code`
   - `RedirectUris` includes your redirect URI
   - `RequirePkce=true`
   - Optionally `RequireConsent=true`
3. Start auth request:

```http
GET /auth/authorize?
  response_type=code&
  client_id=...&
  redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&
  scope=openid%20profile&
  state=...&
  code_challenge=...&
  code_challenge_method=S256
```

4. If consent is required, CoreIdent redirects to `/auth/consent`.
5. After consent + auth, CoreIdent redirects to your redirect URI with `code` and `state`.
6. Exchange the code:

```http
POST /auth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=authorization_code&code=...&redirect_uri=...&code_verifier=...
```

If the granted scopes include `openid`, CoreIdent also returns an `id_token`.

---

# 11. Troubleshooting

## Common startup failures

- **Issuer/Audience not configured**
  - `CoreIdentOptions` validation fails on start.

- **Signing key not configured**
  - RSA/ECDSA providers will generate ephemeral keys with warnings.
  - Symmetric provider requires a 32+ byte secret.

## Common endpoint issues

- **`/auth/token` returns 400**
  - Ensure `Content-Type` is `application/x-www-form-urlencoded`.

- **`/auth/token` returns 401 invalid_client**
  - Ensure the client exists and is enabled.
  - For confidential clients, ensure the secret is correct.

- **`/auth/authorize` returns challenge**
  - Your host app hasn’t configured authentication, or the user is not signed in.

- **JWT revocation appears to “not work”**
  - Ensure the resource server uses `UseCoreIdentTokenRevocation()` (or performs introspection).

---

# 12. Security guidance (practical)

- Use **RSA (RS256)** or **ECDSA (ES256)** in production.
- Keep access tokens **short-lived**.
- Prefer refresh token rotation and revoke on suspicion.
- Never publish symmetric signing secrets in JWKS (CoreIdent does not).
- Do not log secrets, tokens, or private keys.

---

# Appendix A: Where to look in code

- DI registration:
  - `src/CoreIdent.Core/Extensions/ServiceCollectionExtensions.cs`
- Endpoint aggregation:
  - `src/CoreIdent.Core/Extensions/EndpointRouteBuilderExtensions.cs`
- Token endpoint:
  - `src/CoreIdent.Core/Endpoints/TokenEndpointExtensions.cs`
- Revocation / introspection:
  - `src/CoreIdent.Core/Endpoints/TokenManagementEndpointsExtensions.cs`
- Discovery/JWKS:
  - `src/CoreIdent.Core/Endpoints/DiscoveryEndpointsExtensions.cs`
- Authorize/consent:
  - `src/CoreIdent.Core/Endpoints/AuthorizationEndpointExtensions.cs`
  - `src/CoreIdent.Core/Endpoints/ConsentEndpointExtensions.cs`
- Revocation enforcement middleware:
  - `src/CoreIdent.Core/Middleware/TokenRevocationMiddleware.cs`
- EF Core:
  - `src/CoreIdent.Storage.EntityFrameworkCore/CoreIdentDbContext.cs`
  - `src/CoreIdent.Storage.EntityFrameworkCore/Extensions/ServiceCollectionExtensions.cs`
- Test infrastructure:
  - `tests/CoreIdent.Testing/Fixtures/CoreIdentTestFixture.cs`
  - `tests/CoreIdent.Testing/Fixtures/CoreIdentWebApplicationFactory.cs`

