# CoreIdent Release Notes

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