# CoreIdent 0.4: Detailed Development Plan (DEVPLAN.md)

This document provides a detailed breakdown of tasks, components, test cases, and technical guidance for CoreIdent 0.4. It aligns with the rescoped vision in `Project_Overview.md` and technical specifications in `Technical_Plan.md`.

**Key Changes from 0.3.x DEVPLAN:**
- Phase 0 (Foundation) is now first priority — asymmetric keys, revocation, introspection
- Passwordless authentication moved to Phase 1
- Test infrastructure overhaul is a dedicated effort
- Removed: Web3, LNURL, AI integrations
- Added: DPoP, RAR, SPIFFE/SPIRE (later phases)

---

## Phase 0: Foundation Reset

**Goal:** Establish production-ready cryptographic foundation, essential token lifecycle endpoints, and robust test infrastructure.

**Estimated Duration:** 3-4 weeks

**Prerequisites:** .NET 10 SDK installed

---

### Feature 0.1: .NET 10 Migration

*   **Component:** Project File Updates
    - [ ] Update `CoreIdent.Core.csproj` to target `net10.0` (or multi-target `net8.0;net10.0`)
    - [ ] Update `CoreIdent.Storage.EntityFrameworkCore.csproj` target framework
    - [ ] Update `CoreIdent.Adapters.DelegatedUserStore.csproj` target framework
    - [ ] Update all test project target frameworks
    - [ ] Update NuGet package references to .NET 10 compatible versions
        - `Microsoft.AspNetCore.Authentication.JwtBearer` → 10.x
        - `Microsoft.Extensions.Identity.Core` → 10.x
        - `Microsoft.EntityFrameworkCore` → 10.x
        - `Microsoft.IdentityModel.Tokens` → latest stable
*   **Component:** C# 14 Features
    - [ ] Enable C# 14 in all projects (`<LangVersion>14</LangVersion>`)
    - [ ] Add `ClaimsPrincipalExtensions` using extension members syntax
*   **Component:** F# Compatibility
    - [ ] Verify all public APIs are F#-friendly (no `out` parameters in critical paths)
    - [ ] Create F# sample project using Giraffe/Saturn
    - [ ] Add F# template (`coreident-api-fsharp`)
    - [ ] Document F# usage patterns
*   **Test Case:**
    - [ ] All existing tests pass after migration
    - [ ] Solution builds without warnings on .NET 10
*   **Documentation:**
    - [ ] Update README.md with .NET 10 requirement
    - [ ] Create MIGRATION.md for 0.3.x → 0.4 upgrade path

---

### Feature 0.2: Asymmetric Key Support (RS256/ES256)

*   **Component:** `ISigningKeyProvider` Interface
    - [ ] Create `CoreIdent.Core/Services/ISigningKeyProvider.cs`
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
    - [ ] Create `CoreIdent.Core/Configuration/CoreIdentKeyOptions.cs`
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
    - [ ] Create `CoreIdent.Core/Services/RsaSigningKeyProvider.cs`
        *   *Guidance:* Load RSA key from PEM string, PEM file, or X509 certificate
        *   *Guidance:* Generate key on startup if none configured (dev mode only, log warning)
        *   *Guidance:* Support `kid` (key ID) generation based on key thumbprint
*   **Component:** `EcdsaSigningKeyProvider` Implementation
    - [ ] Create `CoreIdent.Core/Services/EcdsaSigningKeyProvider.cs`
        *   *Guidance:* Support ES256 (P-256 curve)
        *   *Guidance:* Similar loading patterns as RSA
*   **Component:** `SymmetricSigningKeyProvider` Implementation (Legacy/Dev)
    - [ ] Create `CoreIdent.Core/Services/SymmetricSigningKeyProvider.cs`
        *   *Guidance:* Wrap existing HS256 logic
        *   *Guidance:* Log deprecation warning when used
*   **Component:** Update `JwtTokenService`
    - [ ] Inject `ISigningKeyProvider` instead of reading key from options directly
    - [ ] Use `SigningCredentials` from provider for all token generation
    - [ ] Include `kid` claim in JWT header
*   **Component:** Update JWKS Endpoint
    - [ ] Modify `DiscoveryEndpointsExtensions.cs` to use `ISigningKeyProvider.GetValidationKeysAsync()`
    - [ ] Return proper RSA key format (`kty: "RSA"`, `n`, `e`, `kid`, `use: "sig"`, `alg`)
    - [ ] Support multiple keys in JWKS (for rotation)
*   **Component:** DI Registration
    - [ ] Add `AddSigningKey()` extension method with overloads:
        ```csharp
        .AddSigningKey(options => options.UseRsa(keyPath))
        .AddSigningKey(options => options.UseRsaPem(pemString))
        .AddSigningKey(options => options.UseEcdsa(keyPath))
        .AddSigningKey(options => options.UseSymmetric(secret)) // Dev only
        ```
*   **Test Case (Unit):**
    - [ ] `RsaSigningKeyProvider` loads key from PEM file correctly
    - [ ] `RsaSigningKeyProvider` loads key from PEM string correctly
    - [ ] `RsaSigningKeyProvider` generates key when none configured
    - [ ] `EcdsaSigningKeyProvider` loads ES256 key correctly
    - [ ] Generated tokens include `kid` in header
    - [ ] JWKS endpoint returns valid RSA public key structure
*   **Test Case (Integration):**
    - [ ] Token signed with RSA can be validated using JWKS public key
    - [ ] Token signed with ECDSA can be validated using JWKS public key
    - [ ] External JWT library can validate tokens using published JWKS
*   **Documentation:**
    - [ ] Update README.md with asymmetric key configuration examples
    - [ ] Add security guidance for key management

---

### Feature 0.3: Token Revocation Endpoint (RFC 7009)

*   **Component:** `ITokenRevocationStore` Interface
    - [ ] Create `CoreIdent.Core/Stores/ITokenRevocationStore.cs`
        ```csharp
        public interface ITokenRevocationStore
        {
            Task RevokeTokenAsync(string jti, string tokenType, DateTime expiry, CancellationToken ct = default);
            Task<bool> IsRevokedAsync(string jti, CancellationToken ct = default);
            Task CleanupExpiredAsync(CancellationToken ct = default);
        }
        ```
*   **Component:** `InMemoryTokenRevocationStore`
    - [ ] Create in-memory implementation using `ConcurrentDictionary`
    - [ ] Implement automatic cleanup of expired entries
*   **Component:** `EfTokenRevocationStore`
    - [ ] Create EF Core implementation in `CoreIdent.Storage.EntityFrameworkCore`
    - [ ] Add `RevokedToken` entity to `CoreIdentDbContext`
    - [ ] Add migration
*   **Component:** Revocation Endpoint
    - [ ] Create `POST /auth/revoke` endpoint in `TokenManagementEndpointsExtensions.cs`
        *   *Guidance:* Accept `token` and optional `token_type_hint` parameters
        *   *Guidance:* Support both access tokens and refresh tokens
        *   *Guidance:* For refresh tokens: mark as consumed in `IRefreshTokenStore`
        *   *Guidance:* For access tokens: add JTI to revocation store
        *   *Guidance:* Require client authentication for confidential clients
        *   *Guidance:* Always return 200 OK (per RFC 7009 - don't leak token validity)
*   **Component:** Token Validation Integration
    - [ ] Update token validation to check revocation store
    - [ ] Add `ITokenRevocationStore` check in protected endpoint middleware
*   **Test Case (Unit):**
    - [ ] `InMemoryTokenRevocationStore` stores and retrieves revocations correctly
    - [ ] Cleanup removes only expired entries
*   **Test Case (Integration):**
    - [ ] `POST /auth/revoke` with valid refresh token invalidates it
    - [ ] `POST /auth/revoke` with valid access token adds to revocation list
    - [ ] Revoked access token is rejected by protected endpoints
    - [ ] Revoked refresh token cannot be used for token refresh
    - [ ] Invalid token revocation returns 200 OK (no information leakage)
    - [ ] Confidential client must authenticate to revoke tokens
*   **Documentation:**
    - [ ] Add revocation endpoint to README.md
    - [ ] Document revocation behavior and client requirements

---

### Feature 0.4: Token Introspection Endpoint (RFC 7662)

*   **Component:** Introspection Endpoint
    - [ ] Create `POST /auth/introspect` endpoint in `TokenManagementEndpointsExtensions.cs`
        *   *Guidance:* Accept `token` and optional `token_type_hint` parameters
        *   *Guidance:* Require client authentication (resource server credentials)
        *   *Guidance:* Validate token signature, expiry, revocation status
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
    - [ ] Create `TokenIntrospectionRequest` record
    - [ ] Create `TokenIntrospectionResponse` record
*   **Test Case (Integration):**
    - [ ] Valid access token returns `active: true` with claims
    - [ ] Expired token returns `active: false`
    - [ ] Revoked token returns `active: false`
    - [ ] Invalid token returns `active: false`
    - [ ] Unauthenticated request returns 401
    - [ ] Response includes all standard claims
*   **Documentation:**
    - [ ] Add introspection endpoint to README.md
    - [ ] Document resource server integration pattern

---

### Feature 0.5: Test Infrastructure Overhaul

*   **Component:** `CoreIdent.Testing` Package
    - [ ] Create new project `tests/CoreIdent.Testing/CoreIdent.Testing.csproj`
    - [ ] Add package references: xUnit, Shouldly, Microsoft.AspNetCore.Mvc.Testing
*   **Component:** `CoreIdentWebApplicationFactory`
    - [ ] Create `CoreIdent.Testing/Fixtures/CoreIdentWebApplicationFactory.cs`
        *   *Guidance:* Encapsulate SQLite in-memory setup
        *   *Guidance:* Provide `ConfigureTestServices` hook
        *   *Guidance:* Provide `SeedDatabase` hook
        *   *Guidance:* Auto-seed standard OIDC scopes
        *   *Guidance:* Handle connection lifecycle properly
*   **Component:** `CoreIdentTestFixture` Base Class
    - [ ] Create `CoreIdent.Testing/Fixtures/CoreIdentTestFixture.cs`
        *   *Guidance:* Implement `IAsyncLifetime`
        *   *Guidance:* Provide `Client` (HttpClient) property
        *   *Guidance:* Provide `Services` (IServiceProvider) property
        *   *Guidance:* Provide helper methods: `CreateUserAsync()`, `CreateClientAsync()`, `AuthenticateAsAsync()`
*   **Component:** Fluent Builders
    - [ ] Create `CoreIdent.Testing/Builders/UserBuilder.cs`
        *   *Guidance:* Fluent API: `.WithEmail()`, `.WithPassword()`, `.WithClaim()`
    - [ ] Create `CoreIdent.Testing/Builders/ClientBuilder.cs`
        *   *Guidance:* Fluent API: `.WithClientId()`, `.WithSecret()`, `.AsPublicClient()`, `.AsConfidentialClient()`
    - [ ] Create `CoreIdent.Testing/Builders/ScopeBuilder.cs`
*   **Component:** Assertion Extensions
    - [ ] Create `CoreIdent.Testing/Extensions/JwtAssertionExtensions.cs`
        *   *Guidance:* `.ShouldBeValidJwt()`, `.ShouldHaveClaim()`, `.ShouldExpireAfter()`
    - [ ] Create `CoreIdent.Testing/Extensions/HttpResponseAssertionExtensions.cs`
        *   *Guidance:* `.ShouldBeSuccessful()`, `.ShouldBeUnauthorized()`, `.ShouldBeBadRequest()`
*   **Component:** Standard Seeders
    - [ ] Create `CoreIdent.Testing/Seeders/StandardScopes.cs`
        *   *Guidance:* Pre-defined openid, profile, email, offline_access scopes
    - [ ] Create `CoreIdent.Testing/Seeders/StandardClients.cs`
        *   *Guidance:* Pre-defined test clients (public, confidential)
*   **Component:** Refactor Existing Tests
    - [ ] Update `CoreIdent.Integration.Tests` to use new fixtures
    - [ ] Remove duplicated `WebApplicationFactory` code from test classes
    - [ ] Simplify test setup using builders
*   **Test Case:**
    - [ ] New fixture-based tests are simpler and more readable
    - [ ] All existing tests pass with new infrastructure
    - [ ] Test execution time is not significantly increased
*   **Documentation:**
    - [ ] Add testing guide to docs
    - [ ] Document fixture usage patterns

---

### Feature 0.6: OpenTelemetry Metrics Integration

*   **Component:** Metrics Instrumentation
    - [ ] Integrate with .NET 10's built-in `Microsoft.AspNetCore.Authentication` metrics
    - [ ] Integrate with `Microsoft.AspNetCore.Identity` metrics (user ops, sign-ins, 2FA)
    - [ ] Add CoreIdent-specific metrics:
        - `coreident.passwordless.email.sent` — Email magic links sent
        - `coreident.passwordless.email.verified` — Successful email verifications
        - `coreident.token.issued` — Tokens issued (by type)
        - `coreident.token.revoked` — Tokens revoked
        - `coreident.client.authenticated` — Client authentications
*   **Component:** Metrics Configuration
    - [ ] Add `AddCoreIdentMetrics()` extension method
    - [ ] Support filtering/sampling
*   **Test Case:**
    - [ ] Metrics are emitted for key operations
    - [ ] Metrics integrate with Aspire dashboard
*   **Documentation:**
    - [ ] Metrics and observability guide

---

## Phase 1: Passwordless & Developer Experience

**Goal:** Make passwordless authentication trivially easy; establish the "5-minute auth" story.

**Estimated Duration:** 3-4 weeks

**Prerequisites:** Phase 0 complete

---

### Feature 1.1: Email Magic Link Authentication

*   **Component:** `IEmailSender` Interface
    - [ ] Create `CoreIdent.Core/Services/IEmailSender.cs`
        ```csharp
        public interface IEmailSender
        {
            Task SendAsync(EmailMessage message, CancellationToken ct = default);
        }
        
        public record EmailMessage(string To, string Subject, string HtmlBody, string? TextBody = null);
        ```
*   **Component:** `SmtpEmailSender` Implementation
    - [ ] Create default SMTP implementation
    - [ ] Support configuration via `SmtpOptions` (host, port, credentials, TLS)
*   **Component:** `IPasswordlessTokenStore` Interface
    - [ ] Create `CoreIdent.Core/Stores/IPasswordlessTokenStore.cs`
        ```csharp
        public interface IPasswordlessTokenStore
        {
            Task<string> CreateTokenAsync(PasswordlessToken token, CancellationToken ct = default);
            Task<PasswordlessToken?> ValidateAndConsumeAsync(string token, CancellationToken ct = default);
            Task CleanupExpiredAsync(CancellationToken ct = default);
        }
        ```
*   **Component:** `PasswordlessToken` Model
    - [ ] Create model with: Id, Email, TokenHash, CreatedAt, ExpiresAt, Consumed, UserId
*   **Component:** `InMemoryPasswordlessTokenStore`
    - [ ] Create in-memory implementation
*   **Component:** `EfPasswordlessTokenStore`
    - [ ] Create EF Core implementation
    - [ ] Add entity and migration
*   **Component:** Passwordless Endpoints
    - [ ] Create `POST /auth/passwordless/email/start`
        *   *Guidance:* Accept email, generate secure token, store hashed, send email
        *   *Guidance:* Rate limit per email address
        *   *Guidance:* Always return success (don't leak email existence)
    - [ ] Create `GET /auth/passwordless/email/verify`
        *   *Guidance:* Accept token, validate, consume, create/find user, issue tokens
        *   *Guidance:* Redirect to configured success URL with tokens
*   **Component:** `PasswordlessEmailOptions`
    - [ ] Create configuration class
        ```csharp
        public class PasswordlessEmailOptions
        {
            public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromMinutes(15);
            public int MaxAttemptsPerHour { get; set; } = 5;
            public string EmailSubject { get; set; } = "Sign in to {AppName}";
            public string? EmailTemplatePath { get; set; }
            public string VerifyEndpointUrl { get; set; } = "/auth/passwordless/email/verify";
        }
        ```
*   **Component:** Email Templates
    - [ ] Create default HTML email template
    - [ ] Support custom template loading
*   **Test Case (Unit):**
    - [ ] Token generation creates unique, secure tokens
    - [ ] Token hashing is one-way and consistent
    - [ ] Rate limiting blocks excessive requests
*   **Test Case (Integration):**
    - [ ] `POST /auth/passwordless/email/start` sends email (mock sender)
    - [ ] `GET /auth/passwordless/email/verify` with valid token issues tokens
    - [ ] Expired token returns error
    - [ ] Already-consumed token returns error
    - [ ] New user is created if email not found
    - [ ] Existing user is authenticated if email found
*   **Documentation:**
    - [ ] Add passwordless email setup guide
    - [ ] Document SMTP configuration
    - [ ] Provide email template customization examples

---

### Feature 1.2: Passkey Integration (WebAuthn/FIDO2)

*   **Component:** `CoreIdentPasskeyOptions`
    - [ ] Create wrapper around .NET 10's `IdentityPasskeyOptions`
        ```csharp
        public class CoreIdentPasskeyOptions
        {
            public string? RelyingPartyId { get; set; }
            public string RelyingPartyName { get; set; } = "CoreIdent";
            public TimeSpan ChallengeTimeout { get; set; } = TimeSpan.FromMinutes(5);
            public UserVerificationRequirement UserVerification { get; set; } = UserVerificationRequirement.Preferred;
        }
        ```
*   **Component:** Passkey Service
    - [ ] Create `IPasskeyService` interface
    - [ ] Implement using .NET 10's built-in passkey support
    - [ ] Handle registration ceremony
    - [ ] Handle authentication ceremony
*   **Component:** Passkey Credential Storage
    - [ ] Create `IPasskeyCredentialStore` interface
    - [ ] Create `PasskeyCredential` model
    - [ ] Implement in-memory store
    - [ ] Implement EF Core store
*   **Component:** Passkey Endpoints
    - [ ] `POST /auth/passkey/register/options` - Get registration options
    - [ ] `POST /auth/passkey/register/complete` - Complete registration
    - [ ] `POST /auth/passkey/authenticate/options` - Get authentication options
    - [ ] `POST /auth/passkey/authenticate/complete` - Complete authentication
*   **Component:** DI Registration
    - [ ] Add `AddPasskeys()` extension method
*   **Test Case (Integration):**
    - [ ] Registration flow returns valid options
    - [ ] Authentication flow returns valid options
    - [ ] (Note: Full WebAuthn testing requires browser automation or mocks)
*   **Documentation:**
    - [ ] Add passkey setup guide
    - [ ] Document browser requirements
    - [ ] Provide JavaScript integration examples

---

### Feature 1.3: SMS OTP (Pluggable Provider)

*   **Component:** `ISmsProvider` Interface
    - [ ] Create `CoreIdent.Core/Services/ISmsProvider.cs`
        ```csharp
        public interface ISmsProvider
        {
            Task SendAsync(string phoneNumber, string message, CancellationToken ct = default);
        }
        ```
*   **Component:** `ConsoleSmsProvider` (Dev/Testing)
    - [ ] Create implementation that logs to console
*   **Component:** SMS OTP Endpoints
    - [ ] `POST /auth/passwordless/sms/start` - Send OTP
    - [ ] `POST /auth/passwordless/sms/verify` - Verify OTP
*   **Component:** OTP Generation and Storage
    - [ ] Reuse `IPasswordlessTokenStore` with SMS-specific token type
    - [ ] Generate 6-digit numeric OTP
*   **Test Case (Integration):**
    - [ ] OTP is sent via provider (mock)
    - [ ] Valid OTP authenticates user
    - [ ] Expired OTP fails
    - [ ] Rate limiting works
*   **Documentation:**
    - [ ] Document SMS provider interface
    - [ ] Provide Twilio implementation example (separate package)

---

### Feature 1.4: ClaimsPrincipal Extensions (C# 14)

*   **Component:** Extension Members
    - [ ] Create `CoreIdent.Core/Extensions/ClaimsPrincipalExtensions.cs`
        ```csharp
        public static class ClaimsPrincipalExtensions
        {
            extension(ClaimsPrincipal principal)
            {
                public string? Email => principal.FindFirstValue(ClaimTypes.Email) 
                                      ?? principal.FindFirstValue("email");
                public string? UserId => principal.FindFirstValue(ClaimTypes.NameIdentifier)
                                       ?? principal.FindFirstValue("sub");
                public string? Name => principal.FindFirstValue(ClaimTypes.Name)
                                     ?? principal.FindFirstValue("name");
                public Guid GetUserIdAsGuid() { /* ... */ }
                public T? GetClaim<T>(string type) where T : IParsable<T> { /* ... */ }
                public IEnumerable<string> GetRoles() { /* ... */ }
            }
        }
        ```
*   **Test Case (Unit):**
    - [ ] `Email` property returns correct value from various claim types
    - [ ] `UserId` property returns correct value
    - [ ] `GetUserIdAsGuid()` parses correctly or throws
    - [ ] `GetClaim<T>()` parses various types correctly
*   **Documentation:**
    - [ ] Add usage examples to README
    - [ ] Document available extension properties/methods

---

### Feature 1.5: `dotnet new` Templates

*   **Component:** Template Package Structure
    - [ ] Create `templates/` directory structure
    - [ ] Create `CoreIdent.Templates.csproj` for packaging
*   **Component:** `coreident-api` Template
    - [ ] Create minimal API template with CoreIdent auth
    - [ ] Include `template.json` with parameters (usePasswordless, useEfCore)
    - [ ] Include sample `appsettings.json`
*   **Component:** `coreident-server` Template
    - [ ] Create full OAuth/OIDC server template
    - [ ] Include EF Core setup
    - [ ] Include sample clients and scopes
*   **Component:** Template Testing
    - [ ] Create test that instantiates templates and builds them
*   **Documentation:**
    - [ ] Add template usage to getting started guide
    - [ ] Document template parameters

---

## Phase 1.5: Client Libraries

**Goal:** Enable any .NET application to authenticate against CoreIdent (or any OAuth/OIDC server) with minimal code.

**Estimated Duration:** 3-4 weeks

**Prerequisites:** Phase 1 complete (server-side passwordless)

---

### Feature 1.5.1: Core Client Library

*   **Component:** `CoreIdent.Client` Package (.NET Standard 2.0+)
    - [ ] Create new project targeting `netstandard2.0;net8.0;net10.0`
    - [ ] Define `ICoreIdentClient` interface
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
    - [ ] Define `CoreIdentClientOptions`
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
    - [ ] Define `ISecureTokenStorage` interface
        ```csharp
        public interface ISecureTokenStorage
        {
            Task StoreTokensAsync(TokenSet tokens, CancellationToken ct = default);
            Task<TokenSet?> GetTokensAsync(CancellationToken ct = default);
            Task ClearTokensAsync(CancellationToken ct = default);
        }
        ```
    - [ ] Implement `InMemoryTokenStorage` (default, non-persistent)
    - [ ] Implement `FileTokenStorage` (encrypted file, for console apps)
*   **Component:** Browser Abstraction
    - [ ] Define `IBrowserLauncher` interface
        ```csharp
        public interface IBrowserLauncher
        {
            Task<BrowserResult> LaunchAsync(string url, string redirectUri, CancellationToken ct = default);
        }
        ```
    - [ ] Implement `SystemBrowserLauncher` (opens default browser, listens on localhost)
*   **Component:** OAuth/OIDC Flow Implementation
    - [ ] Implement Authorization Code + PKCE flow
    - [ ] Implement token refresh logic
    - [ ] Implement logout (end session)
    - [ ] Handle discovery document fetching and caching
*   **Test Case (Unit):**
    - [ ] PKCE code verifier/challenge generation is correct
    - [ ] Token refresh triggers before expiry
    - [ ] State parameter prevents CSRF
*   **Test Case (Integration):**
    - [ ] Full login flow against CoreIdent test server
    - [ ] Token refresh works correctly
    - [ ] Logout clears tokens

---

### Feature 1.5.2: MAUI Client

*   **Component:** `CoreIdent.Client.Maui` Package
    - [ ] Create project targeting `net8.0-android;net8.0-ios;net8.0-maccatalyst;net10.0-android;net10.0-ios`
    - [ ] Implement `MauiSecureTokenStorage` using `SecureStorage`
    - [ ] Implement `MauiBrowserLauncher` using `WebAuthenticator`
    - [ ] Add `UseCoreIdentClient()` extension for `MauiAppBuilder`
*   **Test Case:**
    - [ ] Tokens persist across app restarts
    - [ ] WebAuthenticator flow completes successfully
*   **Documentation:**
    - [ ] MAUI integration guide with sample app

---

### Feature 1.5.3: WPF/WinForms Client

*   **Component:** `CoreIdent.Client.Wpf` Package
    - [ ] Create project targeting `net8.0-windows;net10.0-windows`
    - [ ] Implement `DpapiTokenStorage` using Windows DPAPI
    - [ ] Implement `WebView2BrowserLauncher` (embedded browser)
    - [ ] Implement `SystemBrowserLauncher` (external browser with localhost callback)
*   **Test Case:**
    - [ ] DPAPI storage encrypts/decrypts correctly
    - [ ] WebView2 flow works
*   **Documentation:**
    - [ ] WPF/WinForms integration guide

---

### Feature 1.5.4: Console Client

*   **Component:** `CoreIdent.Client.Console` Package
    - [ ] Create project targeting `net8.0;net10.0`
    - [ ] Implement `EncryptedFileTokenStorage`
    - [ ] Implement device code flow support (for headless scenarios)
*   **Test Case:**
    - [ ] Device code flow works
    - [ ] File storage is encrypted
*   **Documentation:**
    - [ ] Console/CLI app integration guide

---

### Feature 1.5.5: Blazor WASM Client

*   **Component:** `CoreIdent.Client.Blazor` Package
    - [ ] Create project targeting `net8.0;net10.0`
    - [ ] Implement `BrowserStorageTokenStorage` using `localStorage`/`sessionStorage`
    - [ ] Integrate with Blazor's `AuthenticationStateProvider`
*   **Test Case:**
    - [ ] Auth state propagates to Blazor components
    - [ ] Token refresh works in browser
*   **Documentation:**
    - [ ] Blazor WASM integration guide

---

## Phase 2: External Provider Integration

**Goal:** Seamless integration with third-party OAuth/OIDC providers.

**Estimated Duration:** 2-3 weeks

**Prerequisites:** Phase 1.5 complete

---

### Feature 2.1: Provider Abstraction Layer

*   **Component:** `CoreIdent.Providers.Abstractions` Package
    - [ ] Create new project
    - [ ] Define `IExternalAuthProvider` interface
    - [ ] Define `ExternalAuthResult` model
    - [ ] Define `ExternalUserProfile` model
*   **Component:** Account Linking
    - [ ] Add `ExternalLogin` entity to user model
    - [ ] Support linking multiple providers to one user
    - [ ] Handle provider-to-user mapping
*   **Documentation:**
    - [ ] Document provider implementation guide

---

### Feature 2.2: Google Provider

*   **Component:** `CoreIdent.Providers.Google` Package
    - [ ] Create new project
    - [ ] Implement `IExternalAuthProvider` for Google
    - [ ] Handle OAuth flow with Google
    - [ ] Map Google profile to `ExternalUserProfile`
*   **Component:** Configuration
    - [ ] Create `GoogleProviderOptions` (ClientId, ClientSecret, Scopes)
    - [ ] Add `AddGoogleProvider()` extension method
*   **Test Case (Integration):**
    - [ ] Configuration validation works
    - [ ] (Full flow requires manual testing or mock)
*   **Documentation:**
    - [ ] Add Google setup guide with screenshots

---

### Feature 2.3: Microsoft Provider

*   **Component:** `CoreIdent.Providers.Microsoft` Package
    - [ ] Create new project
    - [ ] Implement for Microsoft/Entra ID
    - [ ] Support both personal and work/school accounts
*   **Documentation:**
    - [ ] Add Microsoft/Entra setup guide

---

### Feature 2.4: GitHub Provider

*   **Component:** `CoreIdent.Providers.GitHub` Package
    - [ ] Create new project
    - [ ] Implement for GitHub OAuth
*   **Documentation:**
    - [ ] Add GitHub setup guide

---

## Phase 3: OAuth/OIDC Server Hardening

**Goal:** Production-grade OAuth 2.0 / OIDC server capabilities.

**Estimated Duration:** 4-5 weeks

**Prerequisites:** Phase 2 complete

---

### Feature 3.1: Key Rotation

*   **Component:** `IKeyRotationService`
    - [ ] Define interface for key rotation operations
    - [ ] Implement automatic rotation based on schedule
    - [ ] Support overlap period for old keys
*   **Component:** Multiple Keys in JWKS
    - [ ] Update JWKS endpoint to return all active keys
    - [ ] Include key expiry metadata
*   **Test Case:**
    - [ ] Old tokens remain valid during overlap period
    - [ ] New tokens use new key
    - [ ] JWKS contains both keys during rotation

---

### Feature 3.2: Session Management & OIDC Logout

*   **Component:** Session Tracking
    - [ ] Create `ISessionStore` interface
    - [ ] Track active sessions per user
*   **Component:** OIDC Logout Endpoint
    - [ ] Implement `GET /auth/logout` (end_session_endpoint)
    - [ ] Support `id_token_hint`, `post_logout_redirect_uri`, `state`
    - [ ] Revoke associated tokens
*   **Test Case:**
    - [ ] Logout invalidates session
    - [ ] Logout redirects correctly

---

### Feature 3.3: Dynamic Client Registration (RFC 7591)

*   **Component:** Registration Endpoint
    - [ ] Implement `POST /auth/register` for clients
    - [ ] Support initial access tokens for authorization
    - [ ] Return client credentials
*   **Test Case:**
    - [ ] Client can register and receive credentials
    - [ ] Invalid registration is rejected

---

### Feature 3.4: Device Authorization Flow (RFC 8628)

*   **Component:** Device Authorization Endpoint
    - [ ] Implement `POST /auth/device_authorization`
    - [ ] Return device_code, user_code, verification_uri
*   **Component:** Device Token Endpoint
    - [ ] Extend token endpoint for `urn:ietf:params:oauth:grant-type:device_code`
*   **Test Case:**
    - [ ] Device flow completes successfully
    - [ ] Polling returns appropriate responses

---

### Feature 3.5: Pushed Authorization Requests (RFC 9126)

*   **Component:** PAR Endpoint
    - [ ] Implement `POST /auth/par`
    - [ ] Return request_uri
*   **Component:** Authorize Endpoint Update
    - [ ] Support `request_uri` parameter
*   **Test Case:**
    - [ ] PAR flow works end-to-end

---

### Feature 3.6: DPoP - Demonstrating Proof of Possession (RFC 9449)

*   **Component:** DPoP Proof Validation
    - [ ] Implement DPoP proof parsing and validation
    - [ ] Validate `htm`, `htu`, `iat`, `jti`, signature
*   **Component:** Token Endpoint Update
    - [ ] Accept DPoP header
    - [ ] Bind tokens to DPoP key
*   **Component:** Token Validation Update
    - [ ] Validate DPoP proof on protected endpoints
*   **Test Case:**
    - [ ] DPoP-bound token requires valid proof
    - [ ] Token without DPoP is rejected if DPoP was used at issuance

---

### Feature 3.7: Rich Authorization Requests (RFC 9396)

*   **Component:** Authorization Details Support
    - [ ] Parse `authorization_details` parameter
    - [ ] Store with authorization code
    - [ ] Include in token claims
*   **Test Case:**
    - [ ] Authorization details flow through to token

---

### Feature 3.8: OIDC Conformance Testing

*   **Component:** Conformance Test Integration
    - [ ] Set up OIDC conformance test suite
    - [ ] Document test results
    - [ ] Fix any conformance issues
*   **Documentation:**
    - [ ] Publish conformance status

---

## Phase 4: UI & Administration

**Goal:** Optional UI components for common flows.

**Estimated Duration:** 3-4 weeks

**Prerequisites:** Phase 3 complete

---

### Feature 4.1: `CoreIdent.UI.Web` Package

*   **Component:** Package Setup
    - [ ] Create Razor Class Library project
    - [ ] Define themeable components
*   **Component:** Login Page
    - [ ] Username/password form
    - [ ] Passwordless options (email, passkey)
    - [ ] External provider buttons
*   **Component:** Registration Page
    - [ ] Registration form
    - [ ] Email verification flow
*   **Component:** Consent Page
    - [ ] Scope display
    - [ ] Allow/Deny buttons
*   **Component:** Account Management
    - [ ] Change email
    - [ ] Manage passkeys
    - [ ] View active sessions
*   **Documentation:**
    - [ ] UI customization guide

---

### Feature 4.2: Admin API

*   **Component:** User Management Endpoints
    - [ ] CRUD operations for users
    - [ ] Search and pagination
*   **Component:** Client Management Endpoints
    - [ ] CRUD operations for clients
*   **Component:** Authorization
    - [ ] Admin role/scope requirements
*   **Documentation:**
    - [ ] Admin API reference

---

## Phase 5: Advanced & Community

**Goal:** Extended capabilities for specialized use cases.

**Estimated Duration:** Ongoing

---

### Feature 5.1: MFA Framework

*   **Component:** TOTP Support
*   **Component:** Backup Codes
*   **Component:** MFA Enforcement Policies

---

### Feature 5.2: Fine-Grained Authorization Integration

*   **Component:** FGA/RBAC Hooks
*   **Component:** Policy evaluation interface

---

### Feature 5.3: Audit Logging

*   **Component:** `IAuditLogger` Interface
*   **Component:** Structured event logging
*   **Component:** Default console/file implementation

---

### Feature 5.4: SCIM Support (RFC 7643/7644)

*   **Component:** SCIM User endpoints
*   **Component:** SCIM Group endpoints

---

### Feature 5.5: SPIFFE/SPIRE Integration

*   **Component:** `CoreIdent.Identity.Spiffe` package
*   **Component:** Workload identity validation
*   **Component:** SVID integration

---

### Feature 5.6: Verifiable Credentials

*   **Component:** W3C VC issuance
*   **Component:** VC verification

---

## Protocol & Feature Status Summary

| Protocol / Feature | Phase | Status |
|-------------------|-------|--------|
| .NET 10 Migration | 0 | Planned |
| Asymmetric Keys (RS256/ES256) | 0 | Planned |
| Token Revocation (RFC 7009) | 0 | Planned |
| Token Introspection (RFC 7662) | 0 | Planned |
| Test Infrastructure | 0 | Planned |
| Email Magic Link | 1 | Planned |
| Passkey/WebAuthn | 1 | Planned |
| SMS OTP | 1 | Planned |
| ClaimsPrincipal Extensions | 1 | Planned |
| `dotnet new` Templates | 1 | Planned |
| Google Provider | 2 | Planned |
| Microsoft Provider | 2 | Planned |
| GitHub Provider | 2 | Planned |
| Key Rotation | 3 | Planned |
| OIDC Logout | 3 | Planned |
| Dynamic Client Registration | 3 | Planned |
| Device Authorization Flow | 3 | Planned |
| PAR (RFC 9126) | 3 | Planned |
| DPoP (RFC 9449) | 3 | Planned |
| RAR (RFC 9396) | 3 | Planned |
| UI Package | 4 | Planned |
| Admin API | 4 | Planned |
| MFA Framework | 5 | Planned |
| SCIM | 5 | Planned |
| SPIFFE/SPIRE | 5 | Planned |
| Verifiable Credentials | 5 | Planned |

---

## Preserved from 0.3.x (Already Implemented)

The following features from 0.3.x are preserved and will be maintained:

- [x] OAuth2 Authorization Code Flow with PKCE
- [x] JWT Access Tokens & Refresh Tokens
- [x] Refresh Token Rotation & Family Tracking
- [x] Token Theft Detection
- [x] OIDC Discovery Endpoint
- [x] JWKS Endpoint (to be updated for asymmetric keys)
- [x] ID Token Issuance
- [x] Client Credentials Flow
- [x] User Consent Mechanism
- [x] EF Core Storage Provider
- [x] Delegated User Store Adapter
- [x] Custom Claims Provider

---

## Removed from Roadmap

| Feature | Reason |
|---------|--------|
| Web3 Wallet Login | Niche adoption |
| LNURL-auth | Very niche |
| AI Framework SDK Integrations | Premature |
| CIBA for AI Actions | Specialized |
| Token Vault / Secrets Management | Out of scope |
