# CoreIdent Release Notes

## Version 0.3.2

- Update `README.md` to fully detail Phase 3 progress (Authorization Code Flow specifics, PKCE, ID Tokens).
- Enhance Developer Training Guide (`docs/Developer_Training_Guide.md`) with sections covering OAuth 2.0/OIDC concepts (Auth Code Flow, PKCE, ID Tokens).
- Implement comprehensive negative-path and edge-case integration tests for existing flows (e.g., invalid/expired tokens/codes, PKCE failures, mismatched redirect_uri, client auth errors, malformed requests, concurrency issues).
- Update `LLMINDEX.md` to include references to Phase 3 components and completed features (Authorization Code Flow, related models/stores).
- Improve setup guidance and examples, clarifying DI registration order (`AddCoreIdent`, `AddDbContext`, `AddCoreIdentEntityFrameworkStores`) and EF Core migration process.
- Add explicit documentation and examples emphasizing the security responsibilities when using `DelegatedUserStore` (especially `ValidateCredentialsAsync`).
- Provide clear documentation and code examples for integrating CoreIdent entity configurations into an existing `DbContext` (both inheritance and `ApplyConfigurationsFromAssembly` methods).
- Implement persistent `IAuthorizationCodeStore` using EF Core, including automatic cleanup/expiry.
- Ensure robust concurrency handling in the `IAuthorizationCodeStore` implementation (preventing race conditions).
- Define and document supported client authentication methods for the `/token` endpoint (e.g., Basic Auth header, request body parameters) and ensure secure handling/verification of client secrets.

## Version 0.3.1

This release introduces significant features from Phase 3, focusing on standard OAuth 2.0/OIDC flows and enhanced security.

**Key Features & Enhancements:**

*   **OAuth 2.0 / OIDC:**
    *   **Authorization Code Flow + PKCE:** Implemented `GET /authorize` and `POST /token` (with `grant_type=authorization_code`) endpoints to support the standard secure flow for web, SPA, and mobile clients. Requires client, scope, and auth code storage (see below).
    *   **ID Token Issuance:** OIDC-compliant ID Tokens are now generated alongside access tokens for the Authorization Code Flow.
    *   **Client/Scope/Auth Code Persistence:** Added interfaces (`IClientStore`, `IScopeStore`, `IAuthorizationCodeStore`) and EF Core implementations (`EfClientStore`, `EfScopeStore`, `EfAuthorizationCodeStore`). Requires new EF Core Migrations.
*   **Enhanced Token Security:**
    *   **Token Theft Detection:** Implemented refresh token family tracking to detect and respond to potential token theft when consumed tokens are reused. Includes configurable response modes (`TokenTheftDetectionMode`: `Silent`, `RevokeFamily`, `RevokeAllUserTokens` in `CoreIdentOptions.TokenSecurity`). Enabled by default (`EnableTokenFamilyTracking: true`).
    *   **Hashed Refresh Token Handles:** Refresh token handles are now securely hashed (salted SHA-256) before persistence in the database (`EfRefreshTokenStore`).
    *   **Refresh Token Cleanup Service:** Added an optional background service (`RefreshTokenCleanupService`) in the EF Core package to automatically remove expired/consumed refresh tokens based on `ConsumedTokenRetentionPeriod` configuration.
*   **Core Improvements:**
    *   **Credential Validation Refinement:** `IUserStore.ValidateCredentialsAsync` now returns `PasswordVerificationResult`, allowing stores (like `DelegatedUserStore`) to handle password verification logic, including re-hashing needs.
    *   **Configuration:** Added `TokenSecurityOptions` and `ConsumedTokenRetentionPeriod` to `CoreIdentOptions` for fine-grained security control. Updated `CoreIdentOptionsValidator`.
*   **Storage & Adapters:**
    *   Updated `CoreIdent.Storage.EntityFrameworkCore` to support new entities (Clients, Scopes, Auth Codes) and security features (hashing, cleanup service). **Requires new EF Core Migrations.**
    *   Updated `CoreIdent.Adapters.DelegatedUserStore` to align with the new `ValidateCredentialsAsync` signature. Note: Requires separate persistent stores for refresh tokens, auth codes, clients, and scopes (e.g., using EF Core).
*   **Documentation:** Updated `README.md`, `Developer_Training_Guide.md`, and `LLMINDEX.md` to reflect Phase 3 progress and new features/configurations.

**Breaking Changes:**

*   `IUserStore.ValidateCredentialsAsync` signature changed from `Task<bool>` to `Task<PasswordVerificationResult>`. Custom `IUserStore` implementations need updating.
*   `CoreIdent.Adapters.DelegatedUserStore.DelegatedUserStoreOptions.ValidateCredentialsAsync` delegate signature changed accordingly.
*   EF Core storage requires **new migrations** to add tables for Clients, Scopes, and Authorization Codes, and to update the Refresh Tokens table (for hashing and family tracking).

## Version 0.2.0

This is the initial public pre-release of CoreIdent, encompassing features developed during Phase 1 and Phase 2.

**Core Features (CoreIdent.Core):**

*   **Basic Authentication Endpoints:** `/register`, `/login`, `/token/refresh`.
*   **JWT Token Generation:** Secure JWT access tokens and opaque refresh tokens via `ITokenService` (`JwtTokenService` default).
*   **Password Hashing:** Secure password hashing via `IPasswordHasher` (`DefaultPasswordHasher` default, using PBKDF2).
*   **Core Configuration:** `CoreIdentOptions` for issuer, audience, signing key, token lifetimes with validation.
*   **Storage Abstraction:** Interfaces (`IUserStore`, `IRefreshTokenStore`, `IClientStore`, `IScopeStore`) defined for persistence layers.
*   **DI Extensions:** `AddCoreIdent()` for core service registration (Scoped `ITokenService`, Singleton `IPasswordHasher`), `MapCoreIdentEndpoints()` for routing.

**Storage & Adapters:**

*   **EF Core Persistence (CoreIdent.Storage.EntityFrameworkCore):**
    *   Provides implementations for `IUserStore` and `IRefreshTokenStore` using Entity Framework Core.
    *   Includes `CoreIdentDbContext` with entity configurations.
    *   Adds `AddCoreIdentEntityFrameworkStores<TContext>()` extension for DI setup.
    *   Supports EF Core migrations for schema management.
    *   Enables **Refresh Token Rotation** for enhanced security when using `EfRefreshTokenStore`.
*   **Delegated User Store (CoreIdent.Adapters.DelegatedUserStore):**
    *   Provides `DelegatedUserStore` implementation of `IUserStore`.
    *   Allows integrating CoreIdent with existing user databases/systems by providing custom delegates for user lookup and credential validation.
    *   Adds `AddCoreIdentDelegatedUserStore(Action<DelegatedUserStoreOptions>)` extension for DI setup.
    *   Requires a separate persistent store (like the EF Core one) for refresh tokens.

**Other:**

*   Comprehensive unit and integration tests for core services and storage implementations.
*   Updated developer documentation (`README.md`, `Developer_Training_Guide.md`).
*   Build pipeline configured for NuGet package generation. 