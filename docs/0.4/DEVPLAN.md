# CoreIdent 0.4: Detailed Development Plan (DEVPLAN.md)

This document provides a detailed breakdown of tasks, components, test cases, and technical guidance for CoreIdent 0.4. It aligns with the rescoped vision in `Project_Overview.md` and technical specifications in `Technical_Plan.md`.

**Key Changes from 0.3.x DEVPLAN:**
- **Clean slate build** — All implementation starts fresh (no existing code)
- Phase 0 (Foundation) is now first priority — asymmetric keys, revocation, introspection
- Passwordless authentication moved to Phase 1
- Test infrastructure overhaul is a dedicated effort
- Removed: Web3, LNURL, AI integrations
- Added: DPoP, RAR, SPIFFE/SPIRE (later phases)

> **Note:** This is a ground-up rewrite. References to "creating" components mean building from scratch. The 0.3.x codebase is archived for reference only.

**Checklist Legend:**
- `[x]` — Complete
- `[ ]` — Not started
- `[~]` — Partial / needs revisit after prior feature is implemented

## TL;DR: Protocol & Feature Status Summary

| Protocol / Feature | Phase | Feature | Status |
|-------------------|-------|---------|--------|
| .NET 10 Migration | 0 | 0.1 | ✅ Complete |
| Asymmetric Keys (RS256/ES256) | 0 | 0.2 | ✅ Complete |
| Client Store & Model | 0 | 0.3 | ✅ Complete |
| Scope & Core Models | 0 | 0.4 | ✅ Complete |
| Core Registration & Routing | 0 | 0.4.1 | ✅ Complete |
| OIDC Discovery Metadata | 0 | 0.4.2 | ✅ Complete |
| User Model & Stores | 0 | 0.4.3 | ✅ Complete |
| Token Issuance Endpoint | 0 | 0.5 | ✅ Complete |
| Token Revocation (RFC 7009) | 0 | 0.6 | ✅ Complete |
| Token Introspection (RFC 7662) | 0 | 0.7 | ✅ Complete |
| Test Infrastructure | 0 | 0.8 | ✅ Complete |
| OpenTelemetry Metrics | 0 | 0.9 | ✅ Complete |
| CLI Tool | 0 | 0.10 | ✅ Complete |
| Dev Container | 0 | 0.11 | ✅ Complete |
| Email Magic Link | 1 | 1.1 | ✅ Complete |
| Passkey/WebAuthn | 1 | 1.2 | ✅ Complete |
| SMS OTP | 1 | 1.3 | ✅ Complete |
| F# Compatibility | 1 | 1.4 | ✅ Complete |
| `dotnet new` Templates | 1 | 1.5 | ✅ Complete |
| Aspire Integration | 1 | 1.6 | ✅ Complete |
| Authorization Code + PKCE | 1 | 1.7 | ✅ Complete |
| Consent & Grants | 1 | 1.8 | ✅ Complete |
| Delegated User Store | 1 | 1.9 | ✅ Complete |
| OIDC UserInfo Endpoint | 1 | 1.10 | 🔲 Planned |
| Resource Owner Endpoints (Register/Login/Profile) | 1 | 1.11 | ✅ Complete |
| Password Grant (ROPC) | 1 | 1.12 | ✅ Complete |
| Follow-Up Cleanup | 1 | 1.13 | 🔲 Planned |
| Google Provider | 2 | 2.2 | 🔲 Planned |
| Microsoft Provider | 2 | 2.3 | 🔲 Planned |
| GitHub Provider | 2 | 2.4 | 🔲 Planned |
| Key Rotation | 3 | 3.1 | 🔲 Planned |
| OIDC Logout | 3 | 3.2 | 🔲 Planned |
| Dynamic Client Registration | 3 | 3.3 | 🔲 Planned |
| Device Authorization Flow | 3 | 3.4 | 🔲 Planned |
| PAR (RFC 9126) | 3 | 3.5 | 🔲 Planned |
| DPoP (RFC 9449) | 3 | 3.6 | 🔲 Planned |
| RAR (RFC 9396) | 3 | 3.7 | 🔲 Planned |
| UI Package | 4 | 4.1 | 🔲 Planned |
| Admin API | 4 | 4.3 | 🔲 Planned |
| MFA Framework | 5 | 5.1 | 🔲 Planned |
| SCIM | 5 | 5.4 | 🔲 Planned |
| SPIFFE/SPIRE | 5 | 5.5 | 🔲 Planned |
| Verifiable Credentials | 5 | 5.10 | 🔲 Planned |

---

## Phase 0: Foundation Reset

**Goal:** Establish production-ready cryptographic foundation, essential token lifecycle endpoints, and robust test infrastructure.

**Estimated Duration:** 3-4 weeks

**Prerequisites:** .NET 10 SDK installed

### Phase 0 Milestones (to keep scope executable)

- **Milestone 0A — Foundation & Crypto**: Features **0.1–0.2** (project setup, asymmetric keys)
- **Milestone 0B — Core Models & Stores**: Features **0.3–0.4** (client, scope, user, refresh token infrastructure)
- **Milestone 0C — Token Lifecycle Endpoints**: Features **0.5–0.7** (token issuance, revocation, introspection)
- **Milestone 0D — Quality & DevEx**: Features **0.8–0.11** (testing, metrics, CLI, dev container)

---

### Feature 0.1: .NET 10 Migration

*   **Component:** Solution & Project Setup
    - [x] (L1) Create `CoreIdent.sln` solution file
    - [x] (L1) Create `CoreIdent.Core.csproj` targeting `net10.0`
    - [x] (L1) Create `CoreIdent.Storage.EntityFrameworkCore.csproj` targeting `net10.0`
    - [x] (L1) Create `CoreIdent.Adapters.DelegatedUserStore.csproj` targeting `net10.0`
    - [x] (L1) Create test projects targeting `net10.0`
    - [x] (L2) Configure NuGet package references for .NET 10
        - `Microsoft.AspNetCore.Authentication.JwtBearer` → 10.x
        - `Microsoft.Extensions.Identity.Core` → 10.x
        - `Microsoft.EntityFrameworkCore` → 10.x
        - `Microsoft.IdentityModel.Tokens` → latest stable
*   **Component:** C# 14 Features
    - [x] (L1) Enable C# 14 in all projects (`<LangVersion>14</LangVersion>`)
    - [x] (L2) Add `ClaimsPrincipalExtensions` using extension members syntax
*   **Test Case:**
    - [x] (L1) Solution builds without warnings on .NET 10
*   **Documentation:**
    - [x] (L1) Update README.md with .NET 10 requirement

---

### Feature 0.2: Asymmetric Key Support (RS256/ES256)

*   **Component:** `ISigningKeyProvider` Interface
    - [x] (L1) Create `CoreIdent.Core/Services/ISigningKeyProvider.cs`
        ```csharp
        public interface ISigningKeyProvider
        {
            Task<SigningCredentials> GetSigningCredentialsAsync(CancellationToken ct = default);
            Task<IEnumerable<SecurityKeyInfo>> GetValidationKeysAsync(CancellationToken ct = default);
            string Algorithm { get; }
        }
        
        public record SecurityKeyInfo(string KeyId, SecurityKey Key, DateTime? ExpiresAt);
        ```
*   **Component:** `CoreIdentKeyOptions` Configuration
    - [x] (L1) Create `CoreIdent.Core/Configuration/CoreIdentKeyOptions.cs`
        ```csharp
        public class CoreIdentKeyOptions
        {
            public KeyType Type { get; set; } = KeyType.RSA;
            public int RsaKeySize { get; set; } = 2048;
            public string? PrivateKeyPem { get; set; }
            public string? PrivateKeyPath { get; set; }
            public string? CertificatePath { get; set; }
            public string? CertificatePassword { get; set; }
        }
        
        public enum KeyType { RSA, ECDSA, Symmetric }
        ```
*   **Component:** `RsaSigningKeyProvider` Implementation
    - [x] (L3) Create `CoreIdent.Core/Services/RsaSigningKeyProvider.cs`
        *   *Guidance:* Load RSA key from PEM string, PEM file, or X509 certificate
        *   *Guidance:* Generate key on startup if none configured (dev mode only, log warning)
        *   *Guidance:* Support `kid` (key ID) generation based on key thumbprint
*   **Component:** `EcdsaSigningKeyProvider` Implementation
    - [x] (L3) Create `CoreIdent.Core/Services/EcdsaSigningKeyProvider.cs`
        *   *Guidance:* Support ES256 (P-256 curve)
        *   *Guidance:* Similar loading patterns as RSA
*   **Component:** `SymmetricSigningKeyProvider` Implementation (Legacy/Dev)
    - [x] (L2) Create `CoreIdent.Core/Services/SymmetricSigningKeyProvider.cs`
        *   *Guidance:* Implement HS256 logic (for dev/testing only)
        *   *Guidance:* Log deprecation warning when used
*   **Component:** `JwtTokenService`
    - [x] (L2) Create `JwtTokenService` using `ISigningKeyProvider`
    - [x] (L2) Use `SigningCredentials` from provider for all token generation
    - [x] (L2) Include `kid` claim in JWT header
*   **Component:** JWKS Endpoint
    - [x] (L2) Create `DiscoveryEndpointsExtensions.cs` with JWKS endpoint using `ISigningKeyProvider.GetValidationKeysAsync()`
    - [x] (L3) Return proper RSA key format (`kty: "RSA"`, `n`, `e`, `kid`, `use: "sig"`, `alg`)
    - [x] (L2) Support multiple keys in JWKS (for rotation)
*   **Component:** DI Registration
    - [x] (L2) Add `AddSigningKey()` extension method with overloads:
        ```csharp
        .AddSigningKey(options => options.UseRsa(keyPath))
        .AddSigningKey(options => options.UseRsaPem(pemString))
        .AddSigningKey(options => options.UseEcdsa(keyPath))
        .AddSigningKey(options => options.UseSymmetric(secret)) // Dev only
        ```
*   **Test Case (Unit):**
    - [x] (L2) `RsaSigningKeyProvider` loads key from PEM file correctly
    - [x] (L2) `RsaSigningKeyProvider` loads key from PEM string correctly
    - [x] (L2) `RsaSigningKeyProvider` generates key when none configured
    - [x] (L2) `EcdsaSigningKeyProvider` loads ES256 key correctly
    - [x] (L1) Generated tokens include `kid` in header
    - [x] (L2) JWKS endpoint returns valid RSA public key structure
*   **Test Case (Integration):**
    - [x] (L3) Token signed with RSA can be validated using JWKS public key
    - [x] (L3) Token signed with ECDSA can be validated using JWKS public key
    - [x] (L2) External JWT library can validate tokens using published JWKS
*   **Documentation:**
    - [x] (L1) Update README.md with asymmetric key configuration examples
    - [x] (L2) Add security guidance for key management

---

### Feature 0.3: Client Store & Model

*   **Component:** `CoreIdentClient` Model
    - [x] (L1) Create `CoreIdent.Core/Models/CoreIdentClient.cs`
        ```csharp
        public class CoreIdentClient
        {
            public string ClientId { get; set; } = string.Empty;
            public string? ClientSecret { get; set; } // Hashed for confidential clients
            public string ClientName { get; set; } = string.Empty;
            public ClientType ClientType { get; set; } = ClientType.Confidential;
            public ICollection<string> RedirectUris { get; set; } = [];
            public ICollection<string> PostLogoutRedirectUris { get; set; } = [];
            public ICollection<string> AllowedScopes { get; set; } = [];
            public ICollection<string> AllowedGrantTypes { get; set; } = [];
            public int AccessTokenLifetimeSeconds { get; set; } = 3600;
            public int RefreshTokenLifetimeSeconds { get; set; } = 86400;
            public bool RequirePkce { get; set; } = true;
            public bool AllowOfflineAccess { get; set; } = false;
            public bool Enabled { get; set; } = true;
            public DateTime CreatedAt { get; set; }
            public DateTime? UpdatedAt { get; set; }
        }
        
        public enum ClientType { Public, Confidential }
        ```
*   **Component:** `IClientStore` Interface
    - [x] (L1) Create `CoreIdent.Core/Stores/IClientStore.cs`
        ```csharp
        public interface IClientStore
        {
            Task<CoreIdentClient?> FindByClientIdAsync(string clientId, CancellationToken ct = default);
            Task<bool> ValidateClientSecretAsync(string clientId, string clientSecret, CancellationToken ct = default);
            Task CreateAsync(CoreIdentClient client, CancellationToken ct = default);
            Task UpdateAsync(CoreIdentClient client, CancellationToken ct = default);
            Task DeleteAsync(string clientId, CancellationToken ct = default);
        }
        ```
*   **Component:** `InMemoryClientStore`
    - [x] (L2) Create in-memory implementation using `ConcurrentDictionary`
    - [x] (L2) Support seeding clients at startup
*   **Component:** `EfClientStore`
    - [x] (L2) Create EF Core implementation in `CoreIdent.Storage.EntityFrameworkCore`
    - [x] (L1) Add `ClientEntity` entity configuration to `CoreIdentDbContext`
*   **Component:** Client Secret Hashing
    - [x] (L2) Create `IClientSecretHasher` interface and `DefaultClientSecretHasher` implementation
    - [x] (L2) Use secure hashing (PBKDF2 with SHA256) for client secrets
*   **Component:** DI Registration
    - [x] (L1) Add `AddInMemoryClientStore()` extension method
    - [x] (L1) Add `AddInMemoryClients(IEnumerable<CoreIdentClient>)` extension
    - [x] (L1) Add `AddEntityFrameworkCoreClientStore()` extension method
*   **Test Case (Unit):**
    - [x] (L1) `InMemoryClientStore` CRUD operations work correctly
    - [x] (L1) Client secret validation works correctly
    - [x] (L1) `EfClientStore` CRUD operations work correctly
---

### Feature 0.4: Scope & Core Models

*   **Component:** `CoreIdentScope` Model
    - [x] (L1) Create `CoreIdent.Core/Models/CoreIdentScope.cs`
        ```csharp
        public class CoreIdentScope
        {
            public string Name { get; set; } = string.Empty;
            public string? DisplayName { get; set; }
            public string? Description { get; set; }
            public bool Required { get; set; } = false;
            public bool Emphasize { get; set; } = false;
            public bool ShowInDiscoveryDocument { get; set; } = true;
            public ICollection<string> UserClaims { get; set; } = [];
        }
        ```
*   **Component:** `IScopeStore` Interface
    - [x] (L1) Create `CoreIdent.Core/Stores/IScopeStore.cs`
        ```csharp
        public interface IScopeStore
        {
            Task<CoreIdentScope?> FindByNameAsync(string name, CancellationToken ct = default);
            Task<IEnumerable<CoreIdentScope>> FindByScopesAsync(IEnumerable<string> scopeNames, CancellationToken ct = default);
            Task<IEnumerable<CoreIdentScope>> GetAllAsync(CancellationToken ct = default);
        }
        ```
*   **Component:** `InMemoryScopeStore`
    - [x] (L2) Create in-memory implementation
    - [x] (L2) Pre-seed standard OIDC scopes (openid, profile, email, address, phone, offline_access)
*   **Component:** `EfScopeStore`
    - [x] (L2) Create EF Core implementation
    - [x] (L1) Add entity + DbContext schema configuration *(migrations are app-owned)*
*   **Component:** `CoreIdentRefreshToken` Model
    - [x] (L1) Create `CoreIdent.Core/Models/CoreIdentRefreshToken.cs`
        ```csharp
        public class CoreIdentRefreshToken
        {
            public string Handle { get; set; } = string.Empty;
            public string SubjectId { get; set; } = string.Empty;
            public string ClientId { get; set; } = string.Empty;
            public string? FamilyId { get; set; } // For rotation tracking
            public ICollection<string> Scopes { get; set; } = [];
            public DateTime CreatedAt { get; set; }
            public DateTime ExpiresAt { get; set; }
            public DateTime? ConsumedAt { get; set; }
            public bool IsRevoked { get; set; } = false;
        }
        ```
*   **Component:** `IRefreshTokenStore` Interface (Full)
    - [x] (L1) Expand `CoreIdent.Core/Stores/IRefreshTokenStore.cs`
        ```csharp
        public interface IRefreshTokenStore
        {
            Task<string> StoreAsync(CoreIdentRefreshToken token, CancellationToken ct = default);
            Task<CoreIdentRefreshToken?> GetAsync(string handle, CancellationToken ct = default);
            Task<bool> RevokeAsync(string handle, CancellationToken ct = default);
            Task RevokeFamilyAsync(string familyId, CancellationToken ct = default);
            Task<bool> ConsumeAsync(string handle, CancellationToken ct = default);
            Task CleanupExpiredAsync(CancellationToken ct = default);
        }
        ```
*   **Component:** `InMemoryRefreshTokenStore`
    - [x] (L2) Create in-memory implementation with `ConcurrentDictionary`
*   **Component:** `EfRefreshTokenStore`
    - [x] (L2) Create EF Core implementation
    - [x] (L1) Add entity + DbContext schema configuration *(migrations are app-owned)*
    - [x] (L2) Inject `TimeProvider` for testability (consistent with in-memory store)
*   **Component:** Standard Scope Helpers
    - [x] (L1) Create `StandardScopes` static class with predefined OIDC scopes
*   **Component:** DI Registration
    - [x] (L1) Add `AddScopeStore()` and `AddRefreshTokenStore()` extension methods
    - [x] (L1) Add `AddInMemoryScopes(IEnumerable<CoreIdentScope>)` extension
*   **Test Case (Unit):**
    - [x] (L1) Scope store operations work correctly
    - [x] (L1) Refresh token store CRUD and family revocation work correctly
*   **Documentation:**
    - [x] (L1) Document scope configuration

---

### Feature 0.4.1: Core Registration & Routing (Unambiguous Host Integration)

*   **Component:** `CoreIdentOptions` Configuration
    - [x] (L1) Create `CoreIdentOptions` with required issuer/audience settings and safe defaults
        *   *Guidance:* Include at minimum: `Issuer`, `Audience`, `AccessTokenLifetime`, `RefreshTokenLifetime`
        *   *Guidance:* Options should provide **sane defaults** where possible, but still allow **fail-fast validation** for required values (e.g., issuer/audience).
        *   *Guidance:* Keep `ITokenService` as a low-level primitive (caller provides issuer/audience/expires). Higher-level endpoints/features should read from `IOptions<CoreIdentOptions>` and pass values into `ITokenService`.
    - [x] (L1) Add startup validation (fail fast)
        *   *Guidance:* Validate required fields (issuer/audience), validate lifetimes are positive
*   **Component:** `CoreIdentRouteOptions`
    - [x] (L1) Create route options to remove all ambiguity around endpoint mapping
        *   *Guidance:* Include `BasePath` (default `/auth`), `TokenPath` (default `token`)
        *   *Guidance:* Include root-relative `DiscoveryPath` (default `/.well-known/openid-configuration`)
        *   *Guidance:* Include root-relative `JwksPath` (default `/.well-known/jwks.json`)
        *   *Guidance:* Include `ConsentPath` (default `consent`, relative to `BasePath`) for future consent UI
        *   *Guidance:* Include `UserInfoPath` (default `userinfo`, relative to `BasePath`) for OIDC userinfo
        *   *Guidance:* Include `UserProfilePath` (default `/me`, root-relative) for host-friendly "who am I" endpoint
        *   *Guidance:* Routes must have **hardcoded defaults** that can be overridden via configuration/DI (convention over configuration).
        *   *Guidance:* Root-relative OIDC endpoints **must remain root-relative** even when `BasePath` changes.
        *   *Guidance:* Any non-root-relative route should be composed as `BasePath + "/" + <RelativePath>` (normalized for leading/trailing slashes).
        *   *Guidance:* Route option values may be stored either with or without leading/trailing slashes, but endpoint mapping must normalize to valid ASP.NET route templates (single leading slash, no double slashes).
*   **Component:** DI Registration (`AddCoreIdent`)
    - [x] (L2) Create `AddCoreIdent()` extension method that registers:
        *   `CoreIdentOptions` + validation
        *   `CoreIdentRouteOptions`
        *   `ITokenService` and related core services
        *   Default stores when not overridden (in-memory)
        *   *Guidance:* Provide parameterless and parameterized overloads (e.g. `AddCoreIdent()` and `AddCoreIdent(Action<CoreIdentOptions> configure, Action<CoreIdentRouteOptions>? configureRoutes = null)`), where the parameterless version uses defaults.
        *   *Guidance:* Parameterless `AddCoreIdent()` still requires issuer/audience to be configured (e.g., via `appsettings.json` binding to `CoreIdentOptions`). Validation will fail at startup if required values are missing.
    - [x] (L1) Document registration order for EF Core
        *   *Guidance:* `AddCoreIdent()` -> `AddDbContext(...)` -> `AddEntityFrameworkCore*Store()`
*   **Component:** Endpoint Mapping (`MapCoreIdentEndpoints`)
    - [x] (L2) Create `MapCoreIdentEndpoints()` extension method that maps all CoreIdent endpoints
        *   *Guidance:* Map endpoints under `BasePath` unless explicitly root-relative
        *   *Guidance:* Ensure discovery and JWKS endpoints are always root-relative (per OIDC spec)
        *   *Guidance:* Provide parameterless and parameterized overloads. Parameterless should use configured options from DI; parameterized overload(s) should accept an options instance or configuration delegate and then cascade those settings down to the granular mappers.
        *   *Guidance:* Granular endpoint mappers remain public and convention-based; `MapCoreIdentEndpoints()` is the authoritative aggregation.
*   **Test Case (Integration):**
    - [x] (L2) App can boot with `AddCoreIdent()` + `MapCoreIdentEndpoints()` and responds on required routes
        *   *Guidance:* Test should only rely on defaults + minimal required configuration (issuer/audience, signing key) and validate that:
            *   Root-relative `/.well-known/*` endpoints respond (ignoring `BasePath`)
            *   Base-path endpoints respond under the configured default `BasePath`

---

### Feature 0.4.2: OIDC Discovery Metadata (Unambiguous `/.well-known/openid-configuration`)

*   **Component:** Discovery Document Endpoint
    - [x] (L2) Add `/.well-known/openid-configuration` endpoint
        *   *Guidance:* Always root-relative, ignore `BasePath`
        *   *Guidance:* `issuer` must exactly match configured `CoreIdentOptions.Issuer`
        *   *Guidance:* Advertise endpoints using `CoreIdentRouteOptions` (token, revocation, introspection, JWKS)
        *   *Guidance:* Include supported `grant_types_supported` based on implemented features
        *   *Guidance:* Include `scopes_supported` based on `IScopeStore.GetAllAsync()` (filter `ShowInDiscoveryDocument`)
        *   *Guidance:* Include signing algs from `ISigningKeyProvider.Algorithm`
*   **Component:** Discovery Document Model
    - [x] (L1) Create a response model (record/class) for discovery document serialization
*   **Test Case (Integration):**
    - [x] (L2) Discovery endpoint returns valid JSON with correct issuer and endpoint URLs

---

### Feature 0.4.3: User Model & Store Foundation (Required for All User-Based Flows)
*   **Component:** `CoreIdentUser` Model
    - [x] (L1) Create `CoreIdent.Core/Models/CoreIdentUser.cs`
        *   *Guidance:* Include at minimum: `Id`, `UserName`, `NormalizedUserName`, `CreatedAt`, `UpdatedAt`
*   **Component:** `IUserStore` Interface
    - [x] (L1) Create `CoreIdent.Core/Stores/IUserStore.cs`
        *   *Guidance:* Include at minimum: `FindByIdAsync`, `FindByUsernameAsync`, `CreateAsync`, `UpdateAsync`, `DeleteAsync`
        *   *Guidance:* Include claims support to power token issuance: `GetClaimsAsync(subjectId)`
*   **Component:** In-Memory User Store
    - [x] (L2) Create `InMemoryUserStore` using `ConcurrentDictionary`
        *   *Guidance:* Normalize usernames consistently
*   **Component:** EF Core User Store
    - [x] (L2) Create `EfUserStore` in `CoreIdent.Storage.EntityFrameworkCore`
    - [x] (L1) Add `UserEntity` + DbContext configuration
*   **Component:** Password Hashing
    - [x] (L1) Create `IPasswordHasher` interface and default implementation using ASP.NET Core Identity hasher
        *   *Guidance:* Password support is optional in Phase 1 flows, but needed for password-based auth where enabled
*   **Component:** DI Registration
    - [x] (L1) Add `AddInMemoryUserStore()` extension method
    - [x] (L1) Add `AddEntityFrameworkCoreUserStore()` extension method
*   **Test Case (Unit):**
    - [x] (L1) `InMemoryUserStore` CRUD operations work correctly
    - [x] (L1) `EfUserStore` CRUD operations work correctly

---

### Feature 0.5: Token Issuance Endpoint

*   **Component:** Token Endpoint
    - [x] (L3) Create `POST /auth/token` endpoint in `TokenEndpointExtensions.cs`
        *   *Guidance:* Support `grant_type=client_credentials`
        *   *Guidance:* Support `grant_type=refresh_token`
        *   *Guidance:* `grant_type=authorization_code` is implemented in Feature 1.7 (requires `/auth/authorize`)
        *   *Guidance:* Validate client authentication
        *   *Guidance:* Validate requested scopes against client's allowed scopes
        *   *Guidance:* Issue JWT access tokens using `ITokenService`
        *   *Guidance:* Issue refresh tokens using `IRefreshTokenStore`
        *   *Guidance:* Implement refresh token rotation (new token on each use)
*   **Component:** Token Response Models
    - [x] (L1) Create `TokenRequest` record
    - [x] (L1) Create `TokenResponse` record
        ```csharp
        public record TokenResponse(
            string AccessToken,
            string TokenType,
            int ExpiresIn,
            string? RefreshToken = null,
            string? Scope = null,
            string? IdToken = null
        );
        ```
*   **Component:** Token Service Enhancement
    - [x] (L2) Extend `ITokenService` to support scope claims
    - [x] (L2) Add `jti` claim generation for all tokens
    - [x] (L2) Add configurable token lifetimes per client
*   **Component:** Custom Claims Provider
    - [x] (L1) Create `ICustomClaimsProvider` interface
        *   *Guidance:* Provide a hook to add/transform claims based on subject, client, and granted scopes
    - [x] (L2) Integrate `ICustomClaimsProvider` into token issuance
*   **Component:** Refresh Token Rotation
    - [x] (L3) Implement rotation: consume old token, issue new token with same family
    - [x] (L3) Implement theft detection: if consumed token is reused, revoke entire family
*   **Test Case (Unit):**
    - [x] (L1) Token response includes all required fields
    - [x] (L2) Refresh token rotation creates new token in same family
*   **Test Case (Integration):**
    - [x] (L2) `POST /auth/token` with `client_credentials` returns access token
    - [x] (L2) `POST /auth/token` with `refresh_token` returns new tokens
    - [x] (L3) Refresh token rotation works correctly
    - [x] (L3) Reusing consumed refresh token revokes family (theft detection)
    - [x] (L1) Invalid client credentials return 401
    - [x] (L1) Invalid grant returns 400
    - [x] (L2) Client authentication works in token endpoints *(from Feature 0.3)*
*   **Documentation:**
    - [x] (L1) Document token endpoint usage
    - [x] (L2) Document refresh token rotation behavior
    - [x] (L1) Document client configuration options *(from Feature 0.3)*

---

### Feature 0.6: Token Revocation Endpoint (RFC 7009)

> **Status:** Access token revocation complete. Refresh token revocation to be completed after Feature 0.5 (Token Issuance).

*   **Component:** `ITokenRevocationStore` Interface
    - [x] (L1) Create `CoreIdent.Core/Stores/ITokenRevocationStore.cs`
        ```csharp
        public interface ITokenRevocationStore
        {
            Task RevokeTokenAsync(string jti, string tokenType, DateTime expiry, CancellationToken ct = default);
            Task<bool> IsRevokedAsync(string jti, CancellationToken ct = default);
            Task CleanupExpiredAsync(CancellationToken ct = default);
        }
        ```
*   **Component:** `InMemoryTokenRevocationStore`
    - [x] (L2) Create in-memory implementation using `ConcurrentDictionary`
    - [x] (L2) Implement automatic cleanup of expired entries
*   **Component:** `EfTokenRevocationStore`
    - [x] (L2) Create EF Core implementation in `CoreIdent.Storage.EntityFrameworkCore`
    - [x] (L1) Add `RevokedToken` entity to `CoreIdentDbContext`
    - [x] (L2) Inject `TimeProvider` for testability (consistent with in-memory store)
*   **Component:** Revocation Endpoint
    - [x] (L3) Create `POST /auth/revoke` endpoint in `TokenManagementEndpointsExtensions.cs`
        *   *Guidance:* Accept `token` and optional `token_type_hint` parameters
        *   *Guidance:* Support both access tokens and refresh tokens
        *   *Guidance:* For refresh tokens: mark as consumed in `IRefreshTokenStore`
        *   *Guidance:* For access tokens: add JTI to revocation store
        *   *Guidance:* Require client authentication for confidential clients
        *   *Guidance:* Always return 200 OK (per RFC 7009 - don't leak token validity)
        *   *Guidance:* **JWT revocation reality:** revoked JWT access tokens are only rejected by resource servers that perform an online check (introspection and/or shared revocation store). Default posture is short-lived access tokens + refresh token revocation/rotation.
*   **Component:** Token Validation Integration
    - [x] (L3) Create token validation middleware that checks revocation store
    - [x] (L3) Integrate `ITokenRevocationStore` check in protected endpoint middleware
*   **Component:** Revocation Endpoint Enhancement (Post-0.5)
    - [x] (L2) Update revocation endpoint to use full `IRefreshTokenStore` for refresh token revocation
    - [x] (L2) Validate client owns the token being revoked
*   **Test Case (Unit):**
    - [x] (L1) `InMemoryTokenRevocationStore` stores and retrieves revocations correctly
    - [x] (L1) Cleanup removes only expired entries
*   **Test Case (Integration):**
    - [x] (L2) `POST /auth/revoke` with valid refresh token invalidates it *(requires Feature 0.5)*
    - [x] (L2) `POST /auth/revoke` with valid access token adds to revocation list
    - [x] (L3) Revoked access token is rejected by protected endpoints
    - [x] (L2) Revoked refresh token cannot be used for token refresh *(requires Feature 0.5)*
    - [x] (L1) Invalid token revocation returns 200 OK (no information leakage)
    - [x] (L2) Confidential client must authenticate to revoke tokens
*   **Documentation:**
    - [x] (L1) Add revocation endpoint to README.md
    - [x] (L1) Document revocation behavior and client requirements

---

### Feature 0.7: Token Introspection Endpoint (RFC 7662)

> **Note:** Introspection of refresh tokens requires Feature 0.5 (Token Issuance) to be complete.

*   **Component:** Introspection Endpoint
    - [x] (L3) Create `POST /auth/introspect` endpoint in `TokenManagementEndpointsExtensions.cs`
        *   *Guidance:* Accept `token` and optional `token_type_hint` parameters
        *   *Guidance:* Require client authentication (resource server credentials)
        *   *Guidance:* Validate token signature, expiry, revocation status
        *   *Guidance:* Check `IRefreshTokenStore` for refresh token introspection
        *   *Guidance:* Return standardized response:
            ```json
            {
              "active": true,
              "scope": "openid profile",
              "client_id": "client123",
              "username": "user@example.com",
              "token_type": "Bearer",
              "exp": 1234567890,
              "iat": 1234567800,
              "sub": "user-id",
              "aud": "resource-server",
              "iss": "https://issuer.example.com"
            }
            ```
*   **Component:** Introspection Response Models
    - [x] (L1) Create `TokenIntrospectionRequest` record
    - [x] (L1) Create `TokenIntrospectionResponse` record
*   **Test Case (Integration):**
    - [x] (L2) Valid access token returns `active: true` with claims
    - [x] (L1) Expired token returns `active: false`
    - [x] (L2) Revoked token returns `active: false`
    - [x] (L1) Invalid token returns `active: false`
    - [x] (L1) Unauthenticated request returns 401
    - [x] (L2) Response includes all standard claims
    - [x] (L2) Valid refresh token returns `active: true` *(requires Feature 0.5)*
    - [x] (L2) Revoked/consumed refresh token returns `active: false` *(requires Feature 0.5)*
*   **Documentation:**
    - [x] (L1) Add introspection endpoint to README.md
    - [x] (L2) Document resource server integration pattern

---

### Feature 0.8: Test Infrastructure Overhaul

> **Note:** Entity builders (UserBuilder, ClientBuilder, ScopeBuilder) require Features 0.3-0.4 to be complete.

*   **Component:** `CoreIdent.Testing` Package
    - [x] (L1) Create new project `tests/CoreIdent.Testing/CoreIdent.Testing.csproj`
    - [x] (L1) Add package references: xUnit, Shouldly, Microsoft.AspNetCore.Mvc.Testing
*   **Component:** `CoreIdentWebApplicationFactory`
    - [x] (L3) Create `CoreIdent.Testing/Fixtures/CoreIdentWebApplicationFactory.cs`
        *   *Guidance:* Encapsulate SQLite in-memory setup
        *   *Guidance:* Provide `ConfigureTestServices` hook
        *   *Guidance:* Provide `SeedDatabase` hook
        *   *Guidance:* Auto-seed standard OIDC scopes
        *   *Guidance:* Handle connection lifecycle properly
*   **Component:** `CoreIdentTestFixture` Base Class
    - [x] (L2) Create `CoreIdent.Testing/Fixtures/CoreIdentTestFixture.cs`
        *   *Guidance:* Implement `IAsyncLifetime`
        *   *Guidance:* Provide `Client` (HttpClient) property
        *   *Guidance:* Provide `Services` (IServiceProvider) property
        *   *Guidance:* Provide helper methods: `CreateUserAsync()`, `CreateClientAsync()`, `AuthenticateAsAsync()`
*   **Component:** Fluent Builders
    - [x] (L2) Create `CoreIdent.Testing/Builders/UserBuilder.cs`
        *   *Guidance:* Fluent API: `.WithEmail()`, `.WithPassword()`, `.WithClaim()`
    - [x] (L2) Create `CoreIdent.Testing/Builders/ClientBuilder.cs`
        *   *Guidance:* Fluent API: `.WithClientId()`, `.WithSecret()`, `.AsPublicClient()`, `.AsConfidentialClient()`
    - [x] (L1) Create `CoreIdent.Testing/Builders/ScopeBuilder.cs`
*   **Component:** Assertion Extensions
    - [x] (L2) Create `CoreIdent.Testing/Extensions/JwtAssertionExtensions.cs`
        *   *Guidance:* `.ShouldBeValidJwt()`, `.ShouldHaveClaim()`, `.ShouldExpireAfter()`
    - [x] (L1) Create `CoreIdent.Testing/Extensions/HttpResponseAssertionExtensions.cs`
        *   *Guidance:* `.ShouldBeSuccessful()`, `.ShouldBeUnauthorized()`, `.ShouldBeBadRequest()`
*   **Component:** Standard Seeders
    - [x] (L1) Create `CoreIdent.Testing/Seeders/StandardScopes.cs`
        *   *Guidance:* Pre-defined openid, profile, email, offline_access scopes
    - [x] (L1) Create `CoreIdent.Testing/Seeders/StandardClients.cs`
        *   *Guidance:* Pre-defined test clients (public, confidential)
*   **Component:** Integration Test Setup
    - [x] (L2) Create `CoreIdent.Integration.Tests` project using new fixtures
    - [x] (L2) Write initial integration tests using builders
*   **Test Case:**
    - [x] (L1) Fixture-based tests are simple and readable
    - [x] (L1) Test execution time is reasonable
    - [x] (L1) Integration smoke test implemented and passing (app boots with test fixture, health/check endpoint returns 200)

---

### Feature 0.9: OpenTelemetry Metrics Integration

> **Note:** .NET 10 provides built-in metrics (`aspnetcore.authentication.*`, `aspnetcore.identity.*`). CoreIdent adds supplementary metrics for OAuth/OIDC-specific operations. Requires Feature 0.5 (Token Issuance) for `coreident.token.issued` metric.

*   **Component:** Metrics Instrumentation
    - [x] (L2) Integrate with .NET 10's built-in `Microsoft.AspNetCore.Authentication` metrics
    - [x] (L2) Integrate with `Microsoft.AspNetCore.Identity` metrics (user ops, sign-ins, 2FA)
    - [x] (L2) Add CoreIdent-specific metrics:
        - `coreident.token.issued` — Tokens issued (by type)
        - `coreident.token.revoked` — Tokens revoked
        - `coreident.client.authenticated` — Client authentications
*   **Component:** Metrics Configuration
    - [x] (L1) Add `AddCoreIdentMetrics()` extension method
    - [x] (L2) Support filtering/sampling
*   **Test Case:**
    - [x] (L2) Metrics are emitted for key operations
    - [x] (L2) Metrics integrate with Aspire dashboard
*   **Documentation:**
    - [x] (L1) Metrics and observability guide

---

### Feature 0.10: CLI Tool (`dotnet coreident`)

> **Note:** `client add` command requires Feature 0.3 (Client Store) to be complete.

*   **Component:** CLI Package (`CoreIdent.Cli`)
    - [x] (L2) Create .NET tool package
    - [x] (L1) Register as `dotnet tool install -g CoreIdent.Cli`
*   **Component:** `init` Command
    - [x] (L2) Scaffold `appsettings.json` with CoreIdent section
    - [x] (L2) Generate secure random signing key (for dev)
    - [x] (L1) Add package references to `.csproj`
*   **Component:** `keys generate` Command
    - [x] (L2) Generate RSA key pair (PEM format)
    - [x] (L2) Generate ECDSA key pair (PEM format)
    - [x] (L1) Output to file or stdout
*   **Component:** `client add` Command
    - [x] (L2) Interactive client registration
    - [x] (L1) Generate client ID and secret
    - [x] (L1) Output configuration snippet
*   **Component:** `migrate` Command
    - [x] (L2) Wrapper around EF Core migrations for CoreIdent schema
*   **Test Case:**
    - [x] (L1) Each command works in isolation
    - [x] (L2) Generated keys are valid and usable
*   **Documentation:**
    - [x] (L1) CLI reference guide

---

### Feature 0.11: Dev Container Configuration

*   **Component:** `.devcontainer/` Setup
    - [x] (L1) Create `devcontainer.json`
    - [x] (L1) Configure .NET 10 SDK
    - [x] (L1) Include recommended VS Code extensions
    - [x] (L1) Pre-configure database (SQLite for simplicity)
*   **Component:** Codespaces Support
    - [x] (L1) Test in GitHub Codespaces
    - [x] (L1) Add "Open in Codespaces" badge to README
*   **Documentation:**
    - [x] (L1) Contributing guide with dev container instructions

---

## Phase 1: Passwordless & Developer Experience

**Goal:** Make passwordless authentication trivially easy; establish the "5-minute auth" story.

**Estimated Duration:** 3-4 weeks

**Prerequisites:** Phase 0 complete

---

### Feature 1.1: Email Magic Link Authentication

*   **Component:** `IEmailSender` Interface
    - [x] (L1) Create `CoreIdent.Core/Services/IEmailSender.cs`
        ```csharp
        public interface IEmailSender
        {
            Task SendAsync(EmailMessage message, CancellationToken ct = default);
        }
        
        public record EmailMessage(string To, string Subject, string HtmlBody, string? TextBody = null);
        ```
*   **Component:** `SmtpEmailSender` Implementation
    - [x] (L2) Create default SMTP implementation
    - [x] (L1) Support configuration via `SmtpOptions` (host, port, credentials, TLS)
*   **Component:** `IPasswordlessTokenStore` Interface
    - [x] (L1) Create `CoreIdent.Core/Stores/IPasswordlessTokenStore.cs`
        ```csharp
        public interface IPasswordlessTokenStore
        {
            Task<string> CreateTokenAsync(PasswordlessToken token, CancellationToken ct = default);
            Task<PasswordlessToken?> ValidateAndConsumeAsync(string token, CancellationToken ct = default);
            Task CleanupExpiredAsync(CancellationToken ct = default);
        }
        ```
*   **Component:** `PasswordlessToken` Model
    - [x] (L1) Create model with: Id, Email, TokenHash, CreatedAt, ExpiresAt, Consumed, UserId
*   **Component:** `InMemoryPasswordlessTokenStore`
    - [x] (L2) Create in-memory implementation
*   **Component:** `EfPasswordlessTokenStore`
    - [x] (L2) Create EF Core implementation
    - [x] (L1) Add entity mapping (migrations owned by consuming host app)
*   **Component:** Passwordless Endpoints
    - [x] (L3) Create `POST /auth/passwordless/email/start`
        *   *Guidance:* Accept email, generate secure token, store hashed, send email
        *   *Guidance:* Rate limit per email address
        *   *Guidance:* Always return success (don't leak email existence)
    - [x] (L3) Create `GET /auth/passwordless/email/verify`
        *   *Guidance:* Accept token, validate, consume, create/find user, issue tokens
        *   *Guidance:* Redirect to configured success URL with tokens
*   **Component:** `PasswordlessEmailOptions`
    - [x] (L1) Create configuration class
        ```csharp
        public class PasswordlessEmailOptions
        {
            public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromMinutes(15);
            public int MaxAttemptsPerHour { get; set; } = 5;
            public string EmailSubject { get; set; } = "Sign in to {AppName}";
            public string? EmailTemplatePath { get; set; }
            public string VerifyEndpointUrl { get; set; } = "passwordless/email/verify";
            public string? SuccessRedirectUrl { get; set; }
        }
        ```
*   **Component:** Email Templates
    - [x] (L1) Create default HTML email template
    - [x] (L2) Support custom template loading
*   **Test Case (Unit):**
    - [x] (L2) Token generation creates unique, secure tokens
    - [x] (L2) Token hashing is one-way and consistent
    - [x] (L2) Rate limiting blocks excessive requests
*   **Test Case (Integration):**
    - [x] (L2) `POST /auth/passwordless/email/start` sends email (mock sender)
    - [x] (L3) `GET /auth/passwordless/email/verify` with valid token issues tokens
    - [x] (L1) Expired token returns error
    - [x] (L1) Already-consumed token returns error
    - [x] (L2) New user is created if email not found
    - [x] (L2) Existing user is authenticated if email found
*   **Documentation:**
    - [x] (L1) Add passwordless email setup guide
    - [x] (L1) Document SMTP configuration
    - [x] (L1) Recommend SMTP for demos/self-hosted; provider email APIs for production; document how to extend CoreIdent with custom `IEmailSender` (separate package/DI swap)
    - [x] (L1) Provide email template customization examples

---

### Feature 1.2: Passkey Integration (WebAuthn/FIDO2)

> **Note:** .NET 10 provides built-in passkey support via `IdentityPasskeyOptions` and ASP.NET Core Identity. CoreIdent wraps this for minimal-API scenarios and adds convenience configuration.

*   **Component:** `CoreIdentPasskeyOptions`
    - [x] (L2) Create wrapper around .NET 10's `IdentityPasskeyOptions`
        ```csharp
        public class CoreIdentPasskeyOptions
        {
            public string ClientId { get; set; } = "passkey";
            public string? RelyingPartyId { get; set; }
            public string RelyingPartyName { get; set; } = "CoreIdent";
            public TimeSpan ChallengeTimeout { get; set; } = TimeSpan.FromMinutes(5);
            public int ChallengeSize { get; set; } = 32;
            // ~~UserVerificationRequirement UserVerification~~ — not exposed by .NET 10's IdentityPasskeyOptions
        }
        ```
*   **Component:** Passkey Service
    - [x] (L1) Create `IPasskeyService` interface
    - [x] (L2) Implement using .NET 10's built-in passkey support
    - [x] (L2) Handle registration ceremony
    - [x] (L2) Handle authentication ceremony
*   **Component:** Passkey Credential Storage
    - [x] (L1) Create `IPasskeyCredentialStore` interface
    - [x] (L1) Create `PasskeyCredential` model
    - [x] (L2) Implement in-memory store
    - [x] (L2) Implement EF Core store
*   **Component:** Passkey Endpoints
    - [x] (L2) `POST /auth/passkey/register/options` - Get registration options
    - [x] (L2) `POST /auth/passkey/register/complete` - Complete registration
    - [x] (L2) `POST /auth/passkey/authenticate/options` - Get authentication options
    - [x] (L2) `POST /auth/passkey/authenticate/complete` - Complete authentication
*   **Component:** DI Registration
    - [x] (L1) Add `AddPasskeys()` extension method
*   **Test Case (Integration):**
    - [x] (L2) Registration flow returns valid options
    - [x] (L2) Authentication flow returns valid options
    - [ ] (Note: Full WebAuthn testing requires browser automation or mocks)
*   **Documentation:**
    - [x] (L1) Add passkey setup guide
    - [x] (L1) Document browser requirements
    - [x] (L2) Provide JavaScript integration examples

---

### Feature 1.3: SMS OTP (Pluggable Provider)

*   **Component:** `ISmsProvider` Interface
    - [x] (L1) Create `CoreIdent.Core/Services/ISmsProvider.cs`
        ```csharp
        public interface ISmsProvider
        {
            Task SendAsync(string phoneNumber, string message, CancellationToken ct = default);
        }
        ```
*   **Component:** `ConsoleSmsProvider` (Dev/Testing)
    - [x] (L1) Create implementation that logs to console
*   **Component:** SMS OTP Endpoints
    - [x] (L2) `POST /auth/passwordless/sms/start` - Send OTP
    - [x] (L2) `POST /auth/passwordless/sms/verify` - Verify OTP
*   **Component:** OTP Generation and Storage
    - [x] (L1) Reuse `IPasswordlessTokenStore` with SMS-specific token type
    - [x] (L1) Generate 6-digit numeric OTP
*   **Test Case (Integration):**
    - [x] (L1) OTP is sent via provider (mock)
    - [x] (L2) Valid OTP authenticates user
    - [x] (L1) Expired OTP fails
    - [x] (L2) Rate limiting works
*   **Documentation:**
    - [x] (L1) Document SMS provider interface
    - [x] (L2) Provide Twilio implementation example (separate package)

---

### Feature 1.4: F# Compatibility

> **Note:** Moved from Feature 0.1 — verification is more meaningful once core APIs exist.

*   **Component:** F# Compatibility Verification
    - [x] (L2) Verify all public APIs are F#-friendly (no `out` parameters in critical paths)
    - [x] (L2) Create F# sample project using Giraffe/Saturn
    - [x] (L2) Add F# template (`coreident-api-fsharp`)
    - [x] (L1) Document F# usage patterns
*   **Test Case:**
    - [x] (L1) F# sample project compiles and runs
    - [x] (L2) All core interfaces are usable from F#
*   **Documentation:**
    - [x] (L1) F# usage guide

---

### Feature 1.5: `dotnet new` Templates
> **Note:** We should support both C# and F# templates

*   **Component:** Template Package Structure
    - [x] (L1) Create `templates/` directory structure
    - [x] (L1) Create `CoreIdent.Templates.csproj` for packaging
*   **Component:** `coreident-api` Template
    - [x] (L2) Create minimal API template with CoreIdent auth
    - [x] (L2) Include `template.json` with parameters (usePasswordless, useEfCore)
    - [x] (L1) Include sample `appsettings.json`
*   **Component:** `coreident-server` Template
    - [x] (L2) Create full OAuth/OIDC server template
    - [x] (L2) Include EF Core setup
    - [x] (L1) Include sample clients and scopes
*   **Component:** Template Testing
    - [x] (L2) Create test that instantiates templates and builds them
*   **Documentation:**
    - [x] (L1) Add template usage to getting started guide
    - [x] (L1) Document template parameters

---

### Feature 1.6: Aspire Integration

*   **Component:** `CoreIdent.Aspire` Package
    - [x] (L2) Create package targeting Aspire v13 (net10.0)
    - [x] (L3) Provide AppHost integration via `IDistributedApplicationBuilder` extension methods (Aspire.Hosting)
*   **Component:** Dashboard Integration
    - [x] (L2) OpenTelemetry metrics integration that includes CoreIdent `System.Diagnostics.Metrics` meter(s)
    - [x] (L2) Structured logging integration guidance (OpenTelemetry logging)
    - [x] (L2) Distributed tracing for auth flows (CoreIdent ActivitySource spans)
*   **Component:** Health Checks
    - [x] (L1) Database connectivity check (when EF Core DbContext is configured)
    - [x] (L1) Key availability check (ISigningKeyProvider)
    - [x] (L2) External provider connectivity (if configured)
*   **Component:** Service Defaults
    - [x] (L2) `AddCoreIdentDefaults()` extension for Aspire-style service defaults
    - [x] (L2) `MapCoreIdentDefaultEndpoints()` helper for mapping `/health` + `/alive`
*   **Test Case:**
    - [x] (L2) OpenTelemetry configuration includes CoreIdent meter(s)
    - [x] (L2) OpenTelemetry configuration includes CoreIdent tracing spans
    - [x] (L1) Health checks report correctly
*   **Documentation:**
    - [x] (L1) Aspire integration guide

---

### Feature 1.7: OAuth 2.0 Authorization Code Flow (PKCE Required)

*   **Component:** Authorization Code Model
    - [x] (L1) Create `CoreIdentAuthorizationCode` model
        *   *Guidance:* Include code handle, client_id, subject_id, redirect_uri, scopes, created/expires, consumed, nonce, code_challenge, code_challenge_method
*   **Component:** `IAuthorizationCodeStore` Interface
    - [x] (L1) Create store interface
        *   *Guidance:* `CreateAsync`, `GetAsync`, `ConsumeAsync`, `CleanupExpiredAsync`
*   **Component:** In-Memory Store
    - [x] (L2) Implement `InMemoryAuthorizationCodeStore` using `ConcurrentDictionary`
*   **Component:** EF Core Store
    - [x] (L2) Implement `EfAuthorizationCodeStore` in `CoreIdent.Storage.EntityFrameworkCore`
    - [x] (L1) Add `AuthorizationCodeEntity` + DbContext configuration
*   **Component:** Authorization Code Cleanup
    - [x] (L2) Add hosted service that periodically calls `CleanupExpiredAsync`
        *   *Guidance:* Must be opt-out via options
*   **Component:** Authorize Endpoint
    - [x] (L3) Implement `GET /auth/authorize`
        *   *Guidance:* Validate `client_id`, `redirect_uri`, `response_type=code`, and requested scopes
        *   *Guidance:* Enforce PKCE: require `code_challenge` + `code_challenge_method=S256`
        *   *Guidance:* Require `state` round-trip
        *   *Guidance:* Require authenticated user (`HttpContext.User.Identity.IsAuthenticated`); otherwise challenge
        *   *Guidance:* Persist authorization code via `IAuthorizationCodeStore`
        *   *Guidance:* Redirect back to client with `code` and `state` or `error` and `error_description`
*   **Component:** Token Endpoint (`authorization_code` grant)
    - [x] (L3) Extend `POST /auth/token` to support `grant_type=authorization_code`
        *   *Guidance:* Validate code exists and not expired/consumed
        *   *Guidance:* Validate `redirect_uri` matches the one stored in the code
        *   *Guidance:* Validate PKCE `code_verifier` against stored challenge
        *   *Guidance:* Consume code atomically (single-use)
        *   *Guidance:* Issue access token and (optionally) refresh token
*   **Component:** OpenID Connect ID Token (when `openid` scope is granted)
    - [x] (L2) Issue `id_token` in token response for `authorization_code` when `openid` scope is granted
        *   *Guidance:* Include `nonce` (if provided), set `aud` to `client_id`, and include scope-derived claims
        *   *Guidance:* Use signing key provider / `ITokenService` consistently
*   **Component:** DI Registration
    - [x] (L1) Add store registration extensions for authorization code store (in-memory + EF)
*   **Test Case (Integration):**
    - [x] (L3) Authorization code flow works end-to-end (authorize -> token)
    - [x] (L2) PKCE failure returns `invalid_grant`
    - [x] (L2) Redirect URI mismatch returns `invalid_request`
    - [x] (L2) Consumed code cannot be reused
*   **Documentation:**
    - [x] (L1) Document Authorization Code + PKCE flow and required parameters

---

### Feature 1.8: User Consent & Grants

*   **Component:** User Grant Model
    - [x] (L1) Create `CoreIdentUserGrant` model
        *   *Guidance:* Include subject_id, client_id, granted scopes, created/expires
*   **Component:** `IUserGrantStore` Interface
    - [x] (L1) Create interface for consent persistence
        *   *Guidance:* Include `FindAsync(subjectId, clientId)`, `SaveAsync(grant)`, `RevokeAsync(...)`, `HasUserGrantedConsentAsync(...)`
*   **Component:** In-Memory Store
    - [x] (L2) Implement `InMemoryUserGrantStore`
*   **Component:** EF Core Store
    - [x] (L2) Implement `EfUserGrantStore`
    - [x] (L1) Add `UserGrantEntity` + DbContext configuration
*   **Component:** Consent UX Endpoints
    - [x] (L3) Implement `GET /auth/consent` (default minimal HTML)
        *   *Guidance:* Must be replaceable by host app; driven by `CoreIdentRouteOptions.ConsentPath`
    - [x] (L3) Implement `POST /auth/consent` to persist grant or deny
        *   *Guidance:* Deny returns `access_denied` back to client redirect_uri
*   **Component:** Authorize Endpoint Consent Integration
    - [x] (L3) Integrate consent checks into `/auth/authorize`
        *   *Guidance:* If client requires consent and no existing grant satisfies requested scopes, redirect to consent UI
*   **Test Case (Integration):**
    - [x] (L3) Consent required redirects to consent UI
    - [x] (L3) Allow persists grant and completes code flow
    - [x] (L2) Deny returns `access_denied`
*   **Documentation:**
    - [x] (L1) Document consent behavior and how to replace the default consent UI

---

### Feature 1.9: Delegated User Store Adapter (Integrate Existing User Systems)

*   **Component:** Delegated User Store Options
    - [x] (L1) Create `DelegatedUserStoreOptions` with required delegates:
        *   `FindUserByIdAsync`
        *   `FindUserByUsernameAsync`
        *   `ValidateCredentialsAsync`
        *   optional: `GetClaimsAsync`
*   **Component:** `DelegatedUserStore` Implementation
    - [x] (L2) Implement `IUserStore` via configured delegates
        *   *Guidance:* Must never store password hashes; credential validation is delegated
*   **Component:** Validation
    - [x] (L1) Add startup validation to ensure required delegates are provided
*   **Component:** DI Registration
    - [x] (L1) Add `AddCoreIdentDelegatedUserStore(...)` extension method
        *   *Guidance:* Should replace any previously-registered `IUserStore`
*   **Test Case (Unit):**
    - [x] (L2) Missing required delegates fails validation on startup
    - [x] (L2) Delegates are invoked correctly for find + credential validation
*   **Documentation:**
    - [x] (L1) Document integration pattern and security responsibilities

---

### Feature 1.10: OIDC UserInfo Endpoint

*   **Component:** UserInfo Endpoint
    - [x] (L3) Implement `GET /auth/userinfo`
        *   *Guidance:* Path must be configurable via `CoreIdentRouteOptions.UserInfoPath`
        *   *Guidance:* Require a valid access token (bearer auth)
        *   *Guidance:* Use scopes to determine returned claims (e.g., `profile`, `email`, `address`, `phone`)
        *   *Guidance:* Source claims from `IUserStore` and/or `ICustomClaimsProvider`
        *   *Guidance:* Return standard OIDC claims when present; omit claims not granted by scope
*   **Component:** UserInfo Response Model
    - [x] (L1) Define a response model (record/dictionary) suitable for OIDC userinfo
*   **Test Case (Integration):**
    - [x] (L2) Unauthenticated request returns 401
    - [x] (L3) With `openid profile` scope, userinfo returns `sub` and profile claims
    - [x] (L2) With `openid email` scope, userinfo returns `email`
*   **Documentation:**
    - [x] (L1) Document userinfo endpoint behavior and scope-to-claims mapping

---

### Feature 1.11: Resource Owner Endpoints (Register/Login/Profile)

**Goal:** Provide minimal, working endpoints for user registration, login, and profile retrieval. Full customization via delegate replacement. Supports both JSON API and HTML form workflows.

**Philosophy:**
- Convention over configuration — works out of the box with minimal HTML
- Developer can replace response handling entirely via delegate
- We do the security-critical work (hashing, token issuance), they control the response
- Content negotiation: JSON for API clients, HTML for browsers

*   **Component:** `CoreIdentResourceOwnerOptions`
    - [x] (L1) Create options class with delegate properties:
        ```csharp
        public class CoreIdentResourceOwnerOptions
        {
            // Delegate receives the created user; returns custom response or null for default
            public Func<HttpContext, CoreIdentUser, CancellationToken, Task<IResult?>>? RegisterHandler { get; set; }
            
            // Delegate receives authenticated user + issued tokens; returns custom response or null for default
            public Func<HttpContext, CoreIdentUser, TokenResponse, CancellationToken, Task<IResult?>>? LoginHandler { get; set; }
            
            // Delegate receives current user + claims; returns custom response or null for default
            public Func<HttpContext, CoreIdentUser, IReadOnlyList<Claim>, CancellationToken, Task<IResult?>>? ProfileHandler { get; set; }
        }
        
        public record TokenResponse(string AccessToken, string RefreshToken, int ExpiresIn, string TokenType = "Bearer");
        ```

*   **Component:** Route Configuration
    - [x] (L1) Add paths to `CoreIdentRouteOptions`:
        ```csharp
        public string RegisterPath { get; set; } = "/register";
        public string LoginPath { get; set; } = "/login";
        public string ProfilePath { get; set; } = "/profile";
        ```

*   **Component:** Content Negotiation Helper
    - [x] (L1) Create shared helper for detecting JSON vs HTML preference:
        ```csharp
        // Returns true if client prefers JSON (explicit Accept header or JSON Content-Type)
        // Returns false for form posts without JSON Accept, query string GETs, etc.
        private static bool WantsJson(HttpRequest request);
        ```

*   **Component:** `ResourceOwnerEndpointsExtensions`
    - [x] (L2) `POST /auth/register`:
        *   Accept JSON body OR form-urlencoded
        *   Validate email + password
        *   Create user via `IUserStore.CreateAsync()`
        *   Hash password via `IPasswordHasher`
        *   Call delegate if provided; if delegate returns null or not provided, return default response
        *   Default JSON: `{ "userId": "...", "message": "Registered successfully" }`
        *   Default HTML: Minimal success page with user ID
    - [x] (L2) `GET /auth/register` (optional form UI):
        *   Return minimal HTML registration form
        *   Form posts to same endpoint
    - [x] (L2) `POST /auth/login`:
        *   Accept JSON body OR form-urlencoded
        *   Validate credentials via `IUserStore.FindByUsernameAsync()` + `IPasswordHasher.VerifyHashedPassword()`
        *   Issue tokens via `ITokenService` + `IRefreshTokenStore`
        *   Call delegate if provided
        *   Default JSON: `{ "access_token": "...", "refresh_token": "...", "expires_in": 3600, "token_type": "Bearer" }`
        *   Default HTML: Minimal success page (or redirect if `redirect_uri` provided)
    - [x] (L2) `GET /auth/login` (optional form UI):
        *   Return minimal HTML login form
        *   Form posts to same endpoint
    - [x] (L2) `GET /auth/profile`:
        *   Require bearer token authentication
        *   Get user via `IUserStore.FindByIdAsync()` using `sub` claim
        *   Get claims via `IUserStore.GetClaimsAsync()`
        *   Call delegate if provided
        *   Default JSON: `{ "id": "...", "email": "...", "claims": {...} }`
        *   Default HTML: Minimal profile display

*   **Component:** DI Registration
    - [x] (L1) Add `ConfigureResourceOwnerEndpoints(Action<CoreIdentResourceOwnerOptions>)` extension
    - [x] (L1) Integrate into `MapCoreIdentEndpoints()` pipeline

*   **Test Case (Unit):**
    - [x] (L2) Register creates user with hashed password
    - [x] (L2) Register rejects duplicate email
    - [x] (L2) Login returns tokens for valid credentials
    - [x] (L2) Login rejects invalid credentials
    - [x] (L2) Profile returns user data for authenticated request
    - [x] (L2) Profile rejects unauthenticated request

*   **Test Case (Integration):**
    - [x] (L2) Full register → login → profile flow (JSON)
    - [x] (L2) Full register → login → profile flow (HTML form)
    - [x] (L2) Custom delegate is invoked and can override response
    - [x] (L2) Custom delegate returning null falls back to default

*   **Documentation:**
    - [x] (L1) Document default behavior and content negotiation
    - [x] (L1) Document delegate customization pattern with examples
    - [x] (L1) Document how to disable individual endpoints

---

### Feature 1.12: Password Grant (Resource Owner Password Credentials)

**Goal:** Support `grant_type=password` in token endpoint for legacy/mobile scenarios.

**Note:** This grant type is deprecated in OAuth 2.1. A warning is logged when used.

*   **Component:** Password Grant Handler
    - [x] (L2) Add `GrantTypes.Password` case to `TokenEndpointExtensions.HandleTokenRequest()`
    - [x] (L2) Validate `username` and `password` parameters
    - [x] (L2) Authenticate via `IUserStore.FindByUsernameAsync()` + `IPasswordHasher.VerifyHashedPassword()`
    - [x] (L2) Issue tokens same as login endpoint
    - [x] (L1) Log deprecation warning: "Password grant is deprecated in OAuth 2.1. Consider using authorization code flow with PKCE."

*   **Component:** Client Configuration
    - [x] (L1) Add "password" as valid grant type in `CoreIdentClient.AllowedGrantTypes`

*   **Test Case (Integration):**
    - [x] (L2) Password grant returns tokens for valid credentials
    - [x] (L2) Password grant rejects invalid credentials
    - [x] (L2) Password grant rejected if client doesn't allow it
    - [x] (L1) Deprecation warning is logged

*   **Documentation:**
    - [x] (L1) Document password grant with deprecation notice
    - [x] (L1) Recommend migration to authorization code flow

### Feature 1.13: Follow-Up Cleanup

**Goal:** Clean up inconsistencies, address technical debt, and ensure codebase quality before Phase 1.5.

**Estimated Duration:** 1-2 weeks

---

#### 1.13.1: TimeProvider Consistency

*   **Component:** Replace `DateTime.UtcNow` with `TimeProvider`
    - [x] (L2) `InMemoryUserStore.cs` — Replace `DateTime.UtcNow` with injected `TimeProvider.GetUtcNow()`
    - [x] (L2) `EfUserStore.cs` — Replace `DateTime.UtcNow` with injected `TimeProvider.GetUtcNow()`
    - [x] (L2) `CliApp.cs` — Replace `DateTime.UtcNow` in client creation (or accept as CLI-only exception)
    - [x] (L2) `PasswordlessEmailEndpointsExtensions.cs` — Replace 2 instances with `TimeProvider`
    - [x] (L2) `PasswordlessSmsEndpointsExtensions.cs` — Replace 2 instances with `TimeProvider`
    - [x] (L2) `ResourceOwnerEndpointsExtensions.cs` — Replace instance with `TimeProvider`
    - [x] (L1) Ensure `TimeProvider` is registered in DI (already done in `ServiceCollectionExtensions.cs`)
*   **Test Case:**
    - [x] (L2) Unit tests can control time via `FakeTimeProvider` for user creation timestamps

---

#### 1.13.2: Route Options Consistency

> **Decision:** Parameterless endpoint overloads should read from `IOptions<CoreIdentRouteOptions>` via DI. Hardcoded defaults are not acceptable for production-quality code.

*   **Component:** Refactor parameterless overloads to use `IOptions<CoreIdentRouteOptions>`
    - [x] (L2) `TokenEndpointExtensions.cs` — Refactor to resolve `TokenPath` from `IOptions<CoreIdentRouteOptions>`
    - [x] (L2) `TokenManagementEndpointsExtensions.cs` — Refactor to resolve `RevocationPath`, `IntrospectionPath` from options
    - [x] (L2) `ResourceOwnerEndpointsExtensions.cs` — Refactor to resolve `RegisterPath`, `LoginPath`, `ProfilePath` from options
    - [x] (L2) `PasswordlessEmailEndpointsExtensions.cs` — Refactor to resolve passwordless email paths from options (may need to add paths to `CoreIdentRouteOptions`)
    - [x] (L2) `PasswordlessSmsEndpointsExtensions.cs` — Refactor to resolve passwordless SMS paths from options (may need to add paths to `CoreIdentRouteOptions`)
    - [x] (L2) `UserInfoEndpointExtensions.cs` — Refactor to resolve `UserInfoPath` from options
    - [x] (L2) `ConsentEndpointExtensions.cs` — Refactor to resolve `ConsentPath` from options
    - [x] (L2) `AuthorizationEndpointExtensions.cs` — Refactor to resolve `AuthorizePath` from options
    - [x] (L2) `PasskeyEndpointsExtensions.cs` — Refactor to resolve passkey paths from options (may need to add paths to `CoreIdentRouteOptions`)
*   **Component:** Extend `CoreIdentRouteOptions` if needed
    - [x] (L2) Add `PasswordlessEmailStartPath`, `PasswordlessEmailVerifyPath` if not present
    - [x] (L2) Add `PasswordlessSmsStartPath`, `PasswordlessSmsVerifyPath` if not present
    - [x] (L2) Add passkey paths (`PasskeyRegisterOptionsPath`, `PasskeyRegisterCompletePath`, `PasskeyAuthenticateOptionsPath`, `PasskeyAuthenticateCompletePath`) if not present
*   **Documentation:**
    - [x] (L1) Document route customization patterns in Developer_Guide.md if not already covered

---

#### 1.13.3: Technical Debt from Technical_Plan.md

*   **Component:** RFC 7807 Problem Details
    - [ ] (L3) Audit error responses across all endpoints for consistency
    - [ ] (L3) Consider adopting `Results.Problem()` / `ProblemDetails` for error responses
    - [ ] (L2) Create `CoreIdentProblemDetails` helper or extension for standardized error formatting
    - [ ] (L2) Document error response format in Developer_Guide.md
*   **Component:** Structured Logging
    - [ ] (L2) Audit logging statements for structured logging best practices
    - [ ] (L2) Add correlation ID support (e.g., `Activity.Current?.Id` or custom header)
    - [ ] (L2) Ensure sensitive data (tokens, passwords, PII) is never logged
    - [ ] (L1) Document logging configuration in Developer_Guide.md
*   **Test Case:**
    - [ ] (L2) Error responses include consistent structure (error code, message, optional details)

---

#### 1.13.4: Browser Automation Testing Infrastructure

> **Decision:** Deferred to Phase 1.5. This is a significant infrastructure investment that is not blocking for 1.0 GA.

*   **Status:** 🔜 **Deferred to Phase 1.5**
*   **Rationale:** Browser automation testing (Playwright/Puppeteer) requires substantial setup and is better suited for the client library phase where E2E testing becomes critical.
*   **Placeholder items (to be expanded in Phase 1.5):**
    - [ ] (L3) Evaluate Playwright vs Puppeteer for .NET integration testing
    - [ ] (L3) Create `CoreIdent.Testing.Browser` package with browser automation utilities
    - [ ] (L3) Implement WebAuthn/Passkey E2E tests with virtual authenticator
    - [ ] (L3) Implement OAuth flow E2E tests (authorization code, passwordless)

---

#### 1.13.5: Version String and Documentation Path Cleanup (1.0 GA Preparation)

> **Decision:** Move to **1.0 GA** before starting Phase 1.5. This feature is the gate for GA release.

*   **Component:** Version String Updates
    - [ ] (L1) `CliApp.cs` — Update `PackageVersion` from `"0.4.0"` to `"1.0.0"` (or make dynamic via assembly version)
    - [ ] (L2) Search for other hardcoded `0.4` version strings in codebase and update to `1.0`
    - [ ] (L1) Update all `.csproj` files with `<Version>1.0.0</Version>` (or appropriate pre-release tag)
    - [ ] (L1) Update NuGet package metadata for 1.0 release
*   **Component:** Documentation Path Restructure
    - [ ] (L2) Move contents of `docs/0.4/` to `docs/` root
    - [ ] (L2) Update all internal doc links in:
        - README.md
        - CLAUDE.md
        - Developer_Guide.md
        - All other docs that reference `docs/0.4/` paths
    - [ ] (L2) Update template references that point to `docs/0.4/`
    - [ ] (L2) Update CLI output that references `docs/0.4/`
    - [ ] (L1) Remove or archive the empty `docs/0.4/` folder
*   **Component:** Release Preparation
    - [ ] (L1) Create CHANGELOG.md or RELEASE_NOTES.md for 1.0
    - [ ] (L1) Review and finalize MIGRATION.md (from legacy 0.3.x if applicable)
    - [ ] (L1) Tag release in git as `v1.0.0`
*   **Documentation:**
    - [ ] (L1) Update CLAUDE.md with new doc paths
    - [ ] (L1) Update README.md badges and version references

---

#### 1.13.6: Documentation Audit and Refresh

*   **Component:** CLAUDE.md Review
    - [ ] (L1) Verify project structure section matches current layout
    - [ ] (L1) Verify code style guidance matches C# 14 / .NET 10 patterns in use
    - [ ] (L1) Add any missing guidance discovered during Phase 1 implementation
*   **Component:** README.md Review
    - [ ] (L1) Verify quickstart examples work with current codebase
    - [ ] (L1) Verify feature list matches implemented features
    - [ ] (L1) Update status badges if needed
*   **Component:** Developer_Guide.md Review
    - [ ] (L2) Verify all endpoint documentation matches implementation
    - [ ] (L2) Verify configuration examples are accurate
    - [ ] (L2) Add any missing sections for Phase 1 features
*   **Component:** README_Detailed.md Review
    - [ ] (L1) Verify roadmap status table is accurate
    - [ ] (L1) Verify metrics documentation matches implementation
*   **Component:** Technical_Plan.md Review
    - [ ] (L2) Mark completed items or remove outdated sections
    - [ ] (L2) Update "Open Questions" section with decisions made
*   **Component:** Project_Overview.md Review
    - [ ] (L1) Verify architecture diagrams match current structure
    - [ ] (L1) Verify phase descriptions match DEVPLAN.md
*   **Component:** Other Docs
    - [ ] (L1) Passkeys.md — Verify setup guide is accurate
    - [ ] (L1) CLI_Reference.md — Verify command documentation is complete
    - [ ] (L1) Aspire_Integration.md — Verify integration guide is accurate

---

#### 1.13.7: Code Quality and Consistency

*   **Component:** Nullable Reference Type Audit
    - [ ] (L2) Ensure all projects have `<Nullable>enable</Nullable>`
    - [ ] (L2) Address any nullable warnings in CI build output
*   **Component:** XML Documentation
    - [ ] (L2) Ensure all public APIs have XML doc comments
    - [ ] (L2) Consider enabling `<GenerateDocumentationFile>true</GenerateDocumentationFile>` for NuGet packages
*   **Component:** Code Style Consistency
    - [ ] (L1) Run `dotnet format` across solution
    - [ ] (L1) Address any formatting inconsistencies
*   **Component:** Unused Code Removal
    - [ ] (L2) Audit for unused `using` statements
    - [ ] (L2) Audit for dead code paths or commented-out code
*   **Test Case:**
    - [ ] (L1) CI build passes with zero warnings (or document accepted warnings)

---

#### 1.13.8: Test Coverage Review

*   **Component:** Coverage Analysis
    - [ ] (L2) Run coverage report (e.g., `dotnet test --collect:"XPlat Code Coverage"`)
    - [ ] (L2) Identify gaps in critical paths (token issuance, revocation, auth flows)
    - [ ] (L2) Add tests for any uncovered critical paths
*   **Component:** Test Quality
    - [ ] (L1) Ensure all tests have descriptive assertion messages (per CLAUDE.md Shouldly guidance)
    - [ ] (L2) Review flaky tests and stabilize
*   **Documentation:**
    - [ ] (L1) Document test coverage expectations in CONTRIBUTING.md

---

#### 1.13.9: Additional Codebase Scan Follow-Ups

*   **Component:** OIDC Discovery Metadata Completeness
    - [ ] (L2) `DiscoveryEndpointsExtensions.cs` — Populate `grant_types_supported` instead of returning an empty list
        - *Guidance:* Include currently supported grants (`client_credentials`, `refresh_token`, `authorization_code`, `password` (deprecated))
        - *Guidance:* Ensure the discovery document remains accurate if features are disabled via endpoint mapping
        - *Note:* This addresses an incomplete implementation from Feature 0.4.2 which specified including `grant_types_supported`
    - [ ] (L2) Consider adding other commonly expected discovery fields (only if compatible with current scope):
        - `response_types_supported` (e.g., `code`)
        - `token_endpoint_auth_methods_supported` (e.g., `client_secret_basic`, `client_secret_post`)
*   **Test Case (Integration):**
    - [ ] (L2) `/.well-known/openid-configuration` returns a non-empty `grant_types_supported` list matching implemented features

*   **Component:** Sync-over-Async Hotspots
    - [ ] (L2) `DelegatedPasswordHasher.cs` — Remove sync-over-async (`GetAwaiter().GetResult()`) when validating delegated credentials
        - *Guidance:* If `IPasswordHasher` must remain synchronous, introduce a dedicated synchronous delegate in `DelegatedUserStoreOptions` for password verification
        - *Guidance:* Alternatively, introduce an `IAsyncPasswordVerifier` abstraction and adapt the token endpoint to use it
    - [ ] (L2) Remove `CancellationToken.None` usage in the delegated password verification path where feasible
*   **Test Case (Unit):**
    - [ ] (L2) Delegated credential validation can be tested without blocking threads or requiring sync-over-async

*   **Component:** PII / Sensitive Data Logging Audit
    - [ ] (L2) Audit logs for PII disclosure in passwordless flows (email, phone)
        - `PasswordlessEmailEndpointsExtensions.cs` (logs email)
        - `PasswordlessSmsEndpointsExtensions.cs` (logs phone)
        - `ConsoleSmsProvider.cs` (writes full SMS message including OTP)
    - [ ] (L2) Define a standard redaction strategy:
        - Mask email/phone values in logs (e.g., `j***@example.com`, `+1******4567`)
        - Never log OTP values or magic link tokens
    - [ ] (L2) Replace `Console.WriteLine` in default providers with `ILogger` (or ensure these providers are *explicitly* dev-only and opt-in)
*   **Test Case:**
    - [ ] (L2) Tests assert logs do not contain OTP/token material for passwordless flows

*   **Component:** Remove Silent Exception Swallowing
    - [ ] (L2) Remove `catch { }` blocks in Basic auth parsing helpers:
        - `TokenEndpointExtensions.cs` (`ExtractClientCredentials`)
        - `TokenManagementEndpointsExtensions.cs` (`ExtractClientCredentials`)
        - *Guidance:* Prefer `Try*` parsing patterns and consider logging at Debug/Trace level for malformed Authorization headers
*   **Test Case:**
    - [ ] (L2) Malformed Basic auth headers reliably return `invalid_client` without throwing and without leaking secrets

---

## Phase 1.5: Client Libraries

**Goal:** Enable any .NET application to authenticate against CoreIdent (or any OAuth/OIDC server) with minimal code.

**Estimated Duration:** 3-4 weeks

**Prerequisites:** Phase 1 complete (server-side passwordless)

---

### Feature 1.5.1: Core Client Library

*   **Component:** `CoreIdent.Client` Package
    - [ ] (L1) Create new project targeting `net10.0`
    - [ ] (L1) Define `ICoreIdentClient` interface
        ```csharp
        public interface ICoreIdentClient
        {
            Task<AuthResult> LoginAsync(CancellationToken ct = default);
            Task<AuthResult> LoginSilentAsync(CancellationToken ct = default);
            Task LogoutAsync(CancellationToken ct = default);
            Task<string?> GetAccessTokenAsync(CancellationToken ct = default);
            Task<ClaimsPrincipal?> GetUserAsync(CancellationToken ct = default);
            bool IsAuthenticated { get; }
            event EventHandler<AuthStateChangedEventArgs>? AuthStateChanged;
        }
        ```
    - [ ] (L1) Define `CoreIdentClientOptions`
        ```csharp
        public class CoreIdentClientOptions
        {
            public string Authority { get; set; } = string.Empty;
            public string ClientId { get; set; } = string.Empty;
            public string? ClientSecret { get; set; }
            public string RedirectUri { get; set; } = string.Empty;
            public string PostLogoutRedirectUri { get; set; } = string.Empty;
            public IEnumerable<string> Scopes { get; set; } = ["openid", "profile"];
            public bool UsePkce { get; set; } = true;
            public bool UseDPoP { get; set; } = false;
            public TimeSpan TokenRefreshThreshold { get; set; } = TimeSpan.FromMinutes(5);
        }
        ```
*   **Component:** Token Storage Abstraction
    - [ ] (L1) Define `ISecureTokenStorage` interface
        ```csharp
        public interface ISecureTokenStorage
        {
            Task StoreTokensAsync(TokenSet tokens, CancellationToken ct = default);
            Task<TokenSet?> GetTokensAsync(CancellationToken ct = default);
            Task ClearTokensAsync(CancellationToken ct = default);
        }
        ```
    - [ ] (L1) Implement `InMemoryTokenStorage` (default, non-persistent)
    - [ ] (L2) Implement `FileTokenStorage` (encrypted file, for console apps)
*   **Component:** Browser Abstraction
    - [ ] (L1) Define `IBrowserLauncher` interface
        ```csharp
        public interface IBrowserLauncher
        {
            Task<BrowserResult> LaunchAsync(string url, string redirectUri, CancellationToken ct = default);
        }
        ```
    - [ ] (L3) Implement `SystemBrowserLauncher` (opens default browser, listens on localhost)
*   **Component:** OAuth/OIDC Flow Implementation
    - [ ] (L3) Implement Authorization Code + PKCE flow
    - [ ] (L2) Implement token refresh logic
    - [ ] (L2) Implement logout (end session)
    - [ ] (L2) Handle discovery document fetching and caching
*   **Test Case (Unit):**
    - [ ] (L2) PKCE code verifier/challenge generation is correct
    - [ ] (L2) Token refresh triggers before expiry
    - [ ] (L2) State parameter prevents CSRF
*   **Test Case (Integration):**
    - [ ] (L3) Full login flow against CoreIdent test server
    - [ ] (L2) Token refresh works correctly
    - [ ] (L1) Logout clears tokens

---

### Feature 1.5.2: MAUI Client

*   **Component:** `CoreIdent.Client.Maui` Package
    - [ ] (L1) Create project targeting `net10.0-android;net10.0-ios;net10.0-maccatalyst`
    - [ ] (L2) Implement `MauiSecureTokenStorage` using `SecureStorage`
    - [ ] (L3) Implement `MauiBrowserLauncher` using `WebAuthenticator`
    - [ ] (L1) Add `UseCoreIdentClient()` extension for `MauiAppBuilder`
*   **Test Case:**
    - [ ] (L2) Tokens persist across app restarts
    - [ ] (L3) WebAuthenticator flow completes successfully
*   **Documentation:**
    - [ ] (L1) MAUI integration guide with sample app

---

### Feature 1.5.3: WPF/WinForms Client

*   **Component:** `CoreIdent.Client.Wpf` Package
    - [ ] (L1) Create project targeting `net10.0-windows`
    - [ ] (L2) Implement `DpapiTokenStorage` using Windows DPAPI
    - [ ] (L3) Implement `WebView2BrowserLauncher` (embedded browser)
    - [ ] (L2) Implement `SystemBrowserLauncher` (external browser with localhost callback)
*   **Test Case:**
    - [ ] (L2) DPAPI storage encrypts/decrypts correctly
    - [ ] (L3) WebView2 flow works
*   **Documentation:**
    - [ ] (L1) WPF/WinForms integration guide

---

### Feature 1.5.4: Console Client

*   **Component:** `CoreIdent.Client.Console` Package
    - [ ] (L1) Create project targeting `net10.0`
    - [ ] (L2) Implement `EncryptedFileTokenStorage`
    - [ ] (L2) Implement device code flow support (for headless scenarios)
*   **Test Case:**
    - [ ] (L2) Device code flow works
    - [ ] (L2) File storage is encrypted
*   **Documentation:**
    - [ ] (L1) Console/CLI app integration guide

---

### Feature 1.5.5: Blazor WASM Client

*   **Component:** `CoreIdent.Client.Blazor` Package
    - [ ] (L1) Create project targeting `net10.0`
    - [ ] (L2) Implement `BrowserStorageTokenStorage` using `localStorage`/`sessionStorage`
    - [ ] (L3) Integrate with Blazor's `AuthenticationStateProvider`
*   **Test Case:**
    - [ ] (L2) Auth state propagates to Blazor components
    - [ ] (L2) Token refresh works in browser
*   **Documentation:**
    - [ ] (L1) Blazor WASM integration guide

---

## Phase 2: External Provider Integration

**Goal:** Seamless integration with third-party OAuth/OIDC providers.

**Estimated Duration:** 2-3 weeks

**Prerequisites:** Phase 1.5 complete

---

### Feature 2.1: Provider Abstraction Layer

*   **Component:** `CoreIdent.Providers.Abstractions` Package
    - [ ] (L1) Create new project
    - [ ] (L1) Define `IExternalAuthProvider` interface
    - [ ] (L1) Define `ExternalAuthResult` model
    - [ ] (L1) Define `ExternalUserProfile` model
*   **Component:** Account Linking
    - [ ] (L1) Add `ExternalLogin` entity to user model
    - [ ] (L2) Support linking multiple providers to one user
    - [ ] (L2) Handle provider-to-user mapping
*   **Documentation:**
    - [ ] (L1) Document provider implementation guide

---

### Feature 2.2: Google Provider

*   **Component:** `CoreIdent.Providers.Google` Package
    - [ ] (L1) Create new project
    - [ ] (L2) Implement `IExternalAuthProvider` for Google
    - [ ] (L2) Handle OAuth flow with Google
    - [ ] (L1) Map Google profile to `ExternalUserProfile`
*   **Component:** Configuration
    - [ ] (L1) Create `GoogleProviderOptions` (ClientId, ClientSecret, Scopes)
    - [ ] (L1) Add `AddGoogleProvider()` extension method
*   **Test Case (Integration):**
    - [ ] (L1) Configuration validation works
    - [ ] (Full flow requires manual testing or mock)
*   **Documentation:**
    - [ ] (L1) Add Google setup guide with screenshots

---

### Feature 2.3: Microsoft Provider

*   **Component:** `CoreIdent.Providers.Microsoft` Package
    - [ ] (L1) Create new project
    - [ ] (L2) Implement for Microsoft/Entra ID
    - [ ] (L2) Support both personal and work/school accounts
*   **Documentation:**
    - [ ] (L1) Add Microsoft/Entra setup guide

---

### Feature 2.4: GitHub Provider

*   **Component:** `CoreIdent.Providers.GitHub` Package
    - [ ] (L1) Create new project
    - [ ] (L2) Implement for GitHub OAuth
*   **Documentation:**
    - [ ] (L1) Add GitHub setup guide

---

## Phase 3: OAuth/OIDC Server Hardening

**Goal:** Production-grade OAuth 2.0 / OIDC server capabilities.

**Estimated Duration:** 4-5 weeks

**Prerequisites:** Phase 2 complete

---

### Feature 3.1: Key Rotation

*   **Component:** `IKeyRotationService`
    - [ ] (L1) Define interface for key rotation operations
    - [ ] (L3) Implement automatic rotation based on schedule
    - [ ] (L2) Support overlap period for old keys
*   **Component:** Multiple Keys in JWKS
    - [ ] (L2) Extend JWKS endpoint to return all active keys
    - [ ] (L1) Include key expiry metadata
*   **Test Case:**
    - [ ] (L3) Old tokens remain valid during overlap period
    - [ ] (L2) New tokens use new key
    - [ ] (L2) JWKS contains both keys during rotation

---

### Feature 3.2: Session Management & OIDC Logout

*   **Component:** Session Tracking
    - [ ] (L1) Create `ISessionStore` interface
    - [ ] (L2) Track active sessions per user
*   **Component:** OIDC Logout Endpoint
    - [ ] (L2) Implement `GET /auth/logout` (end_session_endpoint)
    - [ ] (L2) Support `id_token_hint`, `post_logout_redirect_uri`, `state`
    - [ ] (L2) Revoke associated tokens
*   **Test Case:**
    - [ ] (L2) Logout invalidates session
    - [ ] (L1) Logout redirects correctly

---

### Feature 3.3: Dynamic Client Registration (RFC 7591)

*   **Component:** Registration Endpoint
    - [ ] (L2) Implement `POST /auth/register` for clients
    - [ ] (L2) Support initial access tokens for authorization
    - [ ] (L1) Return client credentials
*   **Test Case:**
    - [ ] (L2) Client can register and receive credentials
    - [ ] (L1) Invalid registration is rejected

---

### Feature 3.4: Device Authorization Flow (RFC 8628)

*   **Component:** Device Authorization Endpoint
    - [ ] (L2) Implement `POST /auth/device_authorization`
    - [ ] (L1) Return device_code, user_code, verification_uri
*   **Component:** Device Token Endpoint
    - [ ] (L3) Extend token endpoint for `urn:ietf:params:oauth:grant-type:device_code`
*   **Test Case:**
    - [ ] (L3) Device flow completes successfully
    - [ ] (L2) Polling returns appropriate responses

---

### Feature 3.5: Pushed Authorization Requests (RFC 9126)

*   **Component:** PAR Endpoint
    - [ ] (L2) Implement `POST /auth/par`
    - [ ] (L1) Return request_uri
*   **Component:** Authorize Endpoint Extension
    - [ ] (L2) Add `request_uri` parameter support to authorize endpoint
*   **Test Case:**
    - [ ] (L3) PAR flow works end-to-end

---

### Feature 3.6: DPoP - Demonstrating Proof of Possession (RFC 9449)

*   **Component:** DPoP Proof Validation
    - [ ] (L3) Implement DPoP proof parsing and validation
    - [ ] (L3) Validate `htm`, `htu`, `iat`, `jti`, signature
*   **Component:** Token Endpoint DPoP Support
    - [ ] (L2) Add DPoP header acceptance to token endpoint
    - [ ] (L3) Bind tokens to DPoP key
*   **Component:** Token Validation DPoP Support
    - [ ] (L3) Add DPoP proof validation to protected endpoints
*   **Test Case:**
    - [ ] (L3) DPoP-bound token requires valid proof
    - [ ] (L3) Token without DPoP is rejected if DPoP was used at issuance

---

### Feature 3.7: Rich Authorization Requests (RFC 9396)

*   **Component:** Authorization Details Support
    - [ ] (L2) Parse `authorization_details` parameter
    - [ ] (L2) Store with authorization code
    - [ ] (L2) Include in token claims
*   **Test Case:**
    - [ ] (L2) Authorization details flow through to token

---

### Feature 3.8: Token Exchange (RFC 8693)

*   **Component:** Token Exchange Endpoint
    - [ ] (L3) Implement `POST /auth/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
    - [ ] (L2) Support `subject_token` and `actor_token`
    - [ ] (L2) Support token type indicators
*   **Component:** Exchange Policies
    - [ ] (L1) Define `ITokenExchangePolicy` interface
    - [ ] (L2) Implement delegation policy
    - [ ] (L3) Implement impersonation policy
*   **Test Case:**
    - [ ] (L2) Delegation exchange produces valid token
    - [ ] (L3) Impersonation exchange includes `act` claim
    - [ ] (L2) Unauthorized exchanges are rejected
*   **Documentation:**
    - [ ] (L1) Token exchange guide with use cases

---

### Feature 3.9: JWT-Secured Authorization Request (JAR)

*   **Component:** Request Object Support
    - [ ] (L2) Parse `request` parameter (JWT)
    - [ ] (L3) Validate signature against registered client keys
    - [ ] (L2) Support `request_uri` for remote request objects
*   **Component:** Encryption Support (Optional)
    - [ ] (L3) Decrypt JWE request objects
*   **Test Case:**
    - [ ] (L2) Signed request object is validated
    - [ ] (L2) Invalid signature is rejected
*   **Documentation:**
    - [ ] (L1) JAR implementation guide

---

### Feature 3.10: Webhook System

*   **Component:** `IWebhookService` Interface
    - [ ] (L1) Define webhook event types
    - [ ] (L2) Define delivery mechanism
*   **Component:** Webhook Configuration
    - [ ] (L1) Per-event endpoint configuration
    - [ ] (L2) Secret for signature verification
    - [ ] (L2) Retry policy configuration
*   **Component:** Event Types
    - [ ] (L1) `user.created`, `user.updated`, `user.deleted`
    - [ ] (L1) `user.login.success`, `user.login.failed`
    - [ ] (L1) `token.issued`, `token.revoked`
    - [ ] (L1) `consent.granted`, `consent.revoked`
    - [ ] (L1) `client.created`, `client.updated`
*   **Component:** Delivery
    - [ ] (L2) HTTP POST with JSON payload
    - [ ] (L2) HMAC signature header
    - [ ] (L3) Exponential backoff retry
*   **Test Case:**
    - [ ] (L2) Webhooks fire on events
    - [ ] (L3) Retry logic works correctly
    - [ ] (L2) Signature verification works
*   **Documentation:**
    - [ ] (L1) Webhook integration guide

---

### Feature 3.11: OIDC Conformance Testing

*   **Component:** Conformance Test Integration
    - [ ] (L2) Set up OIDC conformance test suite
    - [ ] (L1) Document test results
    - [ ] (L3) Fix any conformance issues
*   **Documentation:**
    - [ ] (L1) Publish conformance status

---

### Feature 3.12: Revocable Access in Controlled Distributed Systems

> **Goal:** Provide a first-class “revocable access token” story for distributed resource servers that you control.
> This complements Phase 0’s revocation + introspection endpoints.

*   **Component:** Resource Server Validation Package
    - [ ] (L2) Create `CoreIdent.ResourceServer` package
    - [ ] (L3) Implement introspection-based authentication handler/middleware (RFC 7662) for APIs
    - [ ] (L2) Add caching strategy and guidance (fail-closed by default; configurable TTL; protect introspection endpoint)
*   **Component:** Optional Opaque/Reference Access Tokens
    - [ ] (L3) Add configuration to issue opaque/reference access tokens (instead of JWT) for APIs that require immediate revocation
    - [ ] (L2) Ensure introspection becomes the validation path for opaque tokens
*   **Test Case (Integration):**
    - [ ] (L3) Revoked access token becomes inactive via introspection across services
    - [ ] (L2) Cache behaves correctly (revocation latency bounded by cache TTL)
*   **Documentation:**
    - [ ] (L2) Document validation modes: offline JWT vs introspection vs opaque/reference tokens
    - [ ] (L2) Document when to choose which mode (embedded vs distributed)

## Phase 4: UI & Administration

**Goal:** Optional UI components for common flows.

**Estimated Duration:** 3-4 weeks

**Prerequisites:** Phase 3 complete

---

### Feature 4.1: `CoreIdent.UI.Web` Package

*   **Component:** Package Setup
    - [ ] (L1) Create Razor Class Library project
    - [ ] (L2) Define themeable components
*   **Component:** Login Page
    - [ ] (L2) Username/password form
    - [ ] (L2) Passwordless options (email, passkey)
    - [ ] (L2) External provider buttons
*   **Component:** Registration Page
    - [ ] (L2) Registration form
    - [ ] (L2) Email verification flow
*   **Component:** Consent Page
    - [ ] (L2) Scope display
    - [ ] (L1) Allow/Deny buttons
*   **Component:** Account Management
    - [ ] (L2) Change email
    - [ ] (L2) Manage passkeys
    - [ ] (L2) View active sessions
*   **Documentation:**
    - [ ] (L1) UI customization guide

---

### Feature 4.2: Self-Service User Portal

*   **Component:** Account Settings
    - [ ] (L2) Change email (with verification)
    - [ ] (L2) Change password
    - [ ] (L2) Enable/disable MFA
*   **Component:** Session Management
    - [ ] (L2) List active sessions (device, location, time)
    - [ ] (L2) Revoke individual sessions
    - [ ] (L2) "Sign out everywhere" option
*   **Component:** Linked Accounts
    - [ ] (L2) View linked external providers
    - [ ] (L2) Link new provider
    - [ ] (L3) Unlink provider (if other auth method exists)
*   **Component:** Activity Log
    - [ ] (L2) View own login history
    - [ ] (L1) View consent grants
    - [ ] (L2) View security events
*   **Test Case:**
    - [ ] (L2) User can manage own account
    - [ ] (L2) Session revocation works
*   **Documentation:**
    - [ ] (L1) User portal customization guide

---

### Feature 4.3: Admin API

*   **Component:** User Management Endpoints
    - [ ] (L2) CRUD operations for users
    - [ ] (L2) Search and pagination
*   **Component:** Client Management Endpoints
    - [ ] (L2) CRUD operations for clients
*   **Component:** Authorization
    - [ ] (L2) Admin role/scope requirements
*   **Documentation:**
    - [ ] (L1) Admin API reference

---

### Feature 4.4: Multi-tenancy Support

*   **Component:** Tenant Model
    - [ ] (L1) `CoreIdentTenant` entity
    - [ ] (L2) Tenant-scoped configuration
*   **Component:** Tenant Resolution
    - [ ] (L1) `ITenantResolver` interface
    - [ ] (L2) Host-based resolution (subdomain)
    - [ ] (L2) Path-based resolution
    - [ ] (L1) Header-based resolution
*   **Component:** Tenant Isolation
    - [ ] (L3) Per-tenant signing keys
    - [ ] (L3) Per-tenant user stores
    - [ ] (L2) Per-tenant client registrations
*   **Component:** Tenant Configuration
    - [ ] (L2) Per-tenant branding (logo, colors)
    - [ ] (L2) Per-tenant enabled providers
    - [ ] (L2) Per-tenant policies
*   **Test Case:**
    - [ ] (L3) Tenants are isolated
    - [ ] (L3) Cross-tenant access is prevented
*   **Documentation:**
    - [ ] (L1) Multi-tenancy setup guide

---

## Phase 5: Advanced & Community

**Goal:** Extended capabilities for specialized use cases.

**Estimated Duration:** Ongoing

---

### Feature 5.1: MFA Framework

*   **Component:** TOTP Support (L2)
*   **Component:** Backup Codes (L2)
*   **Component:** MFA Enforcement Policies (L2)

---

### Feature 5.2: Fine-Grained Authorization Integration

*   **Component:** FGA/RBAC Hooks (L3)
*   **Component:** Policy evaluation interface (L2)

---

### Feature 5.3: Audit Logging

*   **Component:** `IAuditLogger` Interface (L1)
*   **Component:** Structured event logging (L2)
*   **Component:** Default console/file implementation (L1)

---

### Feature 5.4: SCIM Support (RFC 7643/7644)

*   **Component:** SCIM User endpoints (L3)
*   **Component:** SCIM Group endpoints (L3)

---

### Feature 5.5: SPIFFE/SPIRE Integration

*   **Component:** `CoreIdent.Identity.Spiffe` package (L2)
*   **Component:** Workload identity validation (L3)
*   **Component:** SVID integration (L3)

---

### Feature 5.6: Risk-Based Authentication

*   **Component:** Device Fingerprinting
    - [ ] (L2) Collect device characteristics
    - [ ] (L2) Store known devices per user
    - [ ] (L1) Flag unknown devices
*   **Component:** Geo-location Checks
    - [ ] (L2) IP-based location lookup
    - [ ] (L3) Impossible travel detection
    - [ ] (L2) Location-based policies
*   **Component:** Step-up Authentication
    - [ ] (L2) Define step-up triggers
    - [ ] (L2) Force MFA for sensitive operations
    - [ ] (L2) Re-authentication prompts
*   **Component:** Risk Scoring
    - [ ] (L1) `IRiskScorer` interface
    - [ ] (L2) Configurable risk thresholds
*   **Test Case:**
    - [ ] (L2) Unknown device triggers step-up
    - [ ] (L3) Impossible travel is detected
*   **Documentation:**
    - [ ] (L1) Risk-based auth configuration guide

---

### Feature 5.7: Credential Breach Detection

*   **Component:** HaveIBeenPwned Integration
    - [ ] (L2) k-Anonymity API integration
    - [ ] (L1) Check on registration
    - [ ] (L1) Check on password change
    - [ ] (L2) Optional check on login
*   **Component:** Policy Configuration
    - [ ] (L1) Block compromised passwords
    - [ ] (L1) Warn but allow
    - [ ] (L2) Force password change
*   **Component:** Alerts
    - [ ] (L2) Notify user of compromised credential
    - [ ] (L1) Admin notification option
*   **Test Case:**
    - [ ] (L2) Known compromised password is detected
    - [ ] (L2) Policy enforcement works
*   **Documentation:**
    - [ ] (L1) Breach detection setup guide

---

### Feature 5.8: API Gateway Integration

*   **Component:** YARP Integration Examples
    - [ ] (L2) Token validation middleware
    - [ ] (L2) Token transformation
    - [ ] (L2) Rate limiting integration
*   **Component:** Token Exchange for Downstream
    - [ ] (L3) Exchange external token for internal
    - [ ] (L2) Scope downgrade for microservices
*   **Documentation:**
    - [ ] (L1) API gateway patterns guide

---

### Feature 5.9: Blazor Server Integration

*   **Component:** `CoreIdent.Client.BlazorServer` Package
    - [ ] (L3) Circuit-aware token storage
    - [ ] (L3) Automatic token refresh in circuit
    - [ ] (L3) Handle circuit disconnection gracefully
*   **Component:** Server-side Session
    - [ ] (L2) Session state management
    - [ ] (L2) Distributed cache support
*   **Component:** AuthenticationStateProvider
    - [ ] (L2) Custom provider for server-side Blazor
    - [ ] (L2) Cascading auth state
*   **Test Case:**
    - [ ] (L3) Auth persists across circuit reconnection
    - [ ] (L2) Token refresh works in background
*   **Documentation:**
    - [ ] (L1) Blazor Server integration guide

---

### Feature 5.10: Verifiable Credentials

*   **Component:** W3C VC issuance (L3)
*   **Component:** VC verification (L3)

---

## Protocol & Feature Status Summary

This summary is shown near the top of the document.

---

## Features to Re-implement from 0.3.x

The following features were implemented in 0.3.x and will be re-implemented in 0.4 with improvements:

- [x] (L2) JWKS Endpoint (now with asymmetric keys) — *Covered in Feature 0.2*
- [x] (L2) JWT Access Tokens — *Covered in Feature 0.2 (JwtTokenService)*
- [x] (L2) Refresh Tokens — *Covered in Features 0.4-0.5*
- [x] (L3) Refresh Token Rotation & Family Tracking — *Covered in Feature 0.5*
- [x] (L3) Token Theft Detection — *Covered in Feature 0.5*
- [x] (L2) Client Credentials Flow — *Covered in Feature 0.5*
- [x] (L3) OAuth2 Authorization Code Flow with PKCE — *Covered in Feature 1.7*
- [x] (L2) ID Token Issuance — *Covered in Feature 1.7 (OIDC ID token)*
- [x] (L2) OIDC Discovery Endpoint — *Covered in Feature 0.4.2*
- [ ] (L2) OIDC UserInfo Endpoint — *Covered in Feature 1.10*
- [x] (L2) User Consent Mechanism — *Covered in Feature 1.8*
- [x] (L2) EF Core Storage Provider — *Covered in Features 0.3-0.4 (EfClientStore, EfScopeStore, etc.)*
- [ ] (L2) Delegated User Store Adapter — *Covered in Feature 1.9*
- [x] (L2) User Registration Endpoint — *Covered in Feature 1.11*
- [x] (L2) User Login Endpoint — *Covered in Feature 1.11*
- [x] (L2) User Profile Endpoint — *Covered in Feature 1.11*
- [x] (L2) Password Grant (ROPC) — *Covered in Feature 1.12*
- [x] (L1) Custom Claims Provider — *Covered in Feature 0.5*

> **Note:** The 0.3.x implementation is archived on the `main` branch for reference. These features will be rebuilt from scratch using the new architecture. Many items are now explicitly covered in Phase 0 features.

---

## Removed from Roadmap

| Feature | Reason |
|---------|--------|
| Web3 Wallet Login | Niche adoption |
| LNURL-auth | Very niche |
| AI Framework SDK Integrations | Premature |
| CIBA for AI Actions | Specialized |
| Token Vault / Secrets Management | Out of scope |
