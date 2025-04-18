# CoreIdent Project Index for LLMs (Updated for Phase 3.2)

## 1. Purpose of this Document

This document serves as a comprehensive index and manifest for the CoreIdent project, specifically tailored for Large Language Models (LLMs). Its goal is to provide a quick and detailed understanding of the project's structure, components, current status, and development plan, enabling more effective and context-aware assistance.

### Developer Addendum

Always, ALWAYS be sure you are implementing a system that complies with industry standard conventions, that the end result
package would be well and easily received and consumed, and that there are no test specific or use case specific blocks of code
or variables buried in common implementation code. Always remember that this should look and feel as standardized and as
consumable as the .NET BCL itself. Lastly, always update this file if you ever find yourself confused about where
things are or how they were supposed to work.

## 2. Project Overview & Vision

*   **Goal:** Create a modern, open-source, developer-friendly identity and authentication solution for .NET.
*   **Vision:** Empower developers with secure, easy-to-integrate authentication (traditional credentials, Passkeys, Web3, etc.) without vendor lock-in, using a modular, extensible architecture.
*   **Core Principles:** Open Source (MIT), Developer Experience, Modular & Extensible, .NET Native (9+), Secure by Default.
*   **References:**
    *   `README.md`: High-level overview, quick start, current status.
    *   `Project_Overview.md`: Detailed vision, goals, and scope.
    *   `Technical_Plan.md`: High-level technical architecture and design choices.

## 3. Current Status & Development Plan

*   **Current Status:** Phase 3 in progress. Authorization Code Flow with PKCE, ID Token generation, and token theft detection are complete. The EF Core implementation of `IAuthorizationCodeStore` (including cleanup and concurrency handling) is also complete.
*   **Development Phases (Summary - see `DEVPLAN.md` for details):**
    *   **Phase 1 (Completed):** MVP - Core Registration/Login/Tokens with In-Memory Storage.
        *   Features: `/register`, `/login`, `/token/refresh` endpoints. Core services (`IPasswordHasher`, `ITokenService`), models (`CoreIdentUser`), configuration (`CoreIdentOptions`). Defined core store interfaces (`IUserStore`, `IClientStore`, `IScopeStore`, `IRefreshTokenStore`).
        *   Storage: `InMemoryUserStore` (initial implementation).
    *   **Phase 2 (Completed):** Persistent Storage (EF Core) & Interface Refinement, Delegated Storage.
        *   Features: Implemented EF Core-based stores (`EfUserStore`, `EfClientStore`, `EfScopeStore`, `EfRefreshTokenStore`). Implemented `DelegatedUserStore` adapter. Refined DI registrations (Scoped lifetimes). Added Migrations.
        *   Storage: Defined `CoreIdentDbContext` and EF Core entities in `CoreIdent.Storage.EntityFrameworkCore`. Added `CoreIdent.Adapters.DelegatedUserStore` project.
        *   Refresh Tokens: Implemented Refresh Token Rotation.
        *   Unit & Integration tests created/fixed for EF Core stores and Delegated adapter.
    *   **Phase 3 (Current):** Core OAuth 2.0 / OIDC Server Mechanics
        *   **Completed:**
            *   Authorization Code Flow with PKCE (`/authorize` endpoint logic, `/token` endpoint update for `authorization_code` grant type).
            *   ID Token generation.
            *   Token theft detection security enhancements.
            *   Defined `AuthorizationCode` model, `IAuthorizationCodeStore` interface, and `InMemoryAuthorizationCodeStore` implementation (`src/CoreIdent.Core/Extensions/CoreIdentEndpointRouteBuilderExtensions.cs`).
            *   Implemented persistent `IAuthorizationCodeStore` using EF Core (`src/CoreIdent.Storage.EntityFrameworkCore/Stores/EfAuthorizationCodeStore.cs`).
            *   Added automatic cleanup/expiry for authorization codes (`src/CoreIdent.Storage.EntityFrameworkCore/Services/AuthorizationCodeCleanupService.cs`).
            *   Ensured robust concurrency handling in `IAuthorizationCodeStore` implementations.
        *   **In Progress:** Client Credentials Flow, Discovery endpoints.
    *   **Phase 4 (Future):** User Interaction & External Integrations (Consent, UI, MFA, Passwordless).
    *   **Phase 5 (Future):** Advanced Features & Polish (More Flows, Extensibility, Templates).
*   **Reference:** `DEVPLAN.md`: Detailed breakdown of tasks for each phase.

## 4. Project Structure (Solution Level)

*   **Solution File:** `c:\dev\prj\CoreIdent\CoreIdent.sln`
*   **Source Directory:** `c:\dev\prj\CoreIdent\src\`
    *   `CoreIdent.Core`: Core library containing interfaces, base models, core services, configuration, and endpoint logic.
    *   `CoreIdent.Storage.EntityFrameworkCore`: EF Core persistence layer (DbContext, entities configuration, store implementations).
    *   `CoreIdent.Adapters.DelegatedUserStore`: Adapter for using external user stores.
*   **Tests Directory:** `c:\dev\prj\CoreIdent\tests\`
    *   `CoreIdent.Core.Tests`: Unit tests for `CoreIdent.Core` and store implementations.
        *   `Stores/EfAuthorizationCodeStoreTests.cs`: Tests for the EF Core auth code store.
    *   `CoreIdent.Integration.Tests`: Integration tests using `TestServer`.
        *   `AuthorizationCodeFlowTests.cs`: Tests for the Auth Code flow.
    *   `CoreIdent.TestHost`: Shared test hosting setup.
*   **Docs Directory:** `c:\dev\prj\CoreIdent\docs\`
    *   Contains development documentation.
*   **Root Directory:** `c:\dev\prj\CoreIdent\`
    *   Contains solution file, README, planning documents, license, gitignore.

## 5. Core Project Details: `src\CoreIdent.Core`

This is the central library containing the core logic, interfaces, and models.

*   **Key Namespaces & Responsibilities:**
    *   `CoreIdent.Core.Configuration`: Handles configuration options.
        *   `CoreIdentOptions.cs`: Defines configuration settings (Issuer, Audience, Secret, Lifetimes).
            *   Includes `ConsumedTokenRetentionPeriod` for configuring refresh token cleanup.
            *   Includes `TokenSecurityOptions` for configuring token theft detection behavior.
            *   `TokenTheftDetectionMode` enum: Defines how to respond to potential token theft (Silent, RevokeFamily, RevokeAllUserTokens).
    *   `CoreIdent.Core.Models`: Defines core domain models/entities used across layers.
        *   `CoreIdentUser.cs`, `CoreIdentUserClaim.cs`
        *   `CoreIdentClient.cs`, `CoreIdentClientSecret.cs`
        *   `CoreIdentScope.cs`, `CoreIdentScopeClaim.cs`
        *   `CoreIdentRefreshToken.cs`: Includes family ID and parent-child relationship for token theft detection.
        *   `AuthorizationCode.cs`: Model for storing authorization code data (client ID, user subject, scopes, redirect URI, code challenge, nonce, creation time, lifetime).
        *   `Requests`: DTOs for API requests (`LoginRequest`, `RegisterRequest`, `RefreshTokenRequest`).
        *   `Responses`: DTOs for API responses (`TokenResponse`).
    *   `CoreIdent.Core.Stores`: Defines core persistence **interfaces**.
        *   `IUserStore.cs`: Interface for user persistence operations.
        *   `IRefreshTokenStore.cs`: Interface for refresh token persistence.
            *   Includes `RevokeTokenFamilyAsync` for token theft detection.
            *   Includes `FindTokensBySubjectIdAsync` for token management.
        *   `IClientStore.cs`: Interface for client persistence.
        *   `IScopeStore.cs`: Interface for scope persistence.
        *   `IAuthorizationCodeStore.cs`: Interface for authorization code persistence (`StoreAuthorizationCodeAsync`, `GetAuthorizationCodeAsync`, `RemoveAuthorizationCodeAsync`).
        *   `StoreResult.cs`: Enum for store operation outcomes.
    *   `CoreIdent.Core.Stores.InMemory`: Contains default **in-memory** implementations of store interfaces, primarily for testing and development. Registered by default `AddCoreIdent`.
        *   `InMemoryUserStore.cs`
        *   `InMemoryRefreshTokenStore.cs`: Updated to implement token family revocation.
        *   `InMemoryClientStore.cs`
        *   `InMemoryScopeStore.cs`
        *   `InMemoryAuthorizationCodeStore.cs`: Default in-memory implementation for `IAuthorizationCodeStore` (`src/CoreIdent.Core/Extensions/CoreIdentEndpointRouteBuilderExtensions.cs`).
    *   `CoreIdent.Core.Services`: Contains core service **interfaces** and default implementations.
        *   `IPasswordHasher.cs`: Interface for password hashing.
        *   `ITokenService.cs`: Interface for generating tokens.
            *   Includes token family handling with `GenerateAndStoreRefreshTokenAsync` overloads.
        *   `DefaultPasswordHasher.cs`: Default `IPasswordHasher` implementation.
        *   `JwtTokenService.cs`: Default `ITokenService` implementation.
            *   Implements token family tracking for refresh tokens.
    *   `CoreIdent.Core.Extensions`: Provides service registration extensions.
        *   `CoreIdentServiceCollectionExtensions.cs`: Contains `AddCoreIdent` (registers core services like `ITokenService` (Scoped), `IPasswordHasher` (Singleton)) and default in-memory stores (Scoped).
        *   `CoreIdentEndpointRouteBuilderExtensions.cs`: Contains `MapCoreIdentEndpoints` that maps all API endpoints.
            *   Maps `GET /authorize` endpoint. Includes robust concurrency handling for code generation.
            *   Enhances `POST /token` endpoint to handle `grant_type=authorization_code` with PKCE validation.
            *   Token refresh endpoint (`POST /token/refresh`) implements token theft detection with configurable behavior.

## 6. EF Core Storage Project Details: `src\CoreIdent.Storage.EntityFrameworkCore`

*   **Purpose:** Implements the persistence layer using Entity Framework Core.
*   **Key Components:**
    *   `CoreIdentDbContext.cs`: Main DbContext for the application, defines `DbSet`s for all entities and configures entity relationships using `OnModelCreating`.
    *   `Stores`: Contains EF Core implementations of the store interfaces defined in `CoreIdent.Core.Stores`.
        *   `EfUserStore.cs`
        *   `EfRefreshTokenStore.cs`: Updated to implement token family revocation and token theft detection.
        *   `EfClientStore.cs`
        *   `EfScopeStore.cs`
        *   `EfAuthorizationCodeStore.cs`: Implements `IAuthorizationCodeStore` for EF Core persistence. Uses `FindAsync` and handles concurrency.
    *   `Services`: Contains background services for data maintenance.
        *   `RefreshTokenCleanupService.cs`: Background service that automatically removes expired and old consumed tokens based on retention policy.
        *   `AuthorizationCodeCleanupService.cs`: Background service that automatically removes expired authorization codes.
    *   `Extensions`: Contains DI extensions.
        *   `CoreIdentEntityFrameworkCoreExtensions.cs`: Contains `AddCoreIdentEntityFrameworkStores` extension to register EF Core stores (Scoped) with optional token and authorization code cleanup services.

## 6.5 Delegated User Store Adapter Project Details: `src\CoreIdent.Adapters.DelegatedUserStore`

*   **Purpose:** Allows integration with existing external user databases/systems.
*   **Key Components:**
    *   `DelegatedUserStoreOptions.cs`: Defines `Func<>` delegates (`FindUserByIdAsync`, `FindUserByUsernameAsync`, `ValidateCredentialsAsync`, `GetClaimsAsync`) to be provided by the consumer.
    *   `DelegatedUserStore.cs`: Implements `IUserStore` by calling the configured delegates. Write operations throw `NotImplementedException`.
    *   `Extensions/CoreIdentDelegatedUserStoreExtensions.cs`: Contains `AddCoreIdentDelegatedUserStore` extension method (registers `DelegatedUserStore` as Scoped `IUserStore`, configures and validates options).

## 7. Test Project Details: `tests\CoreIdent.*`

*   **`CoreIdent.Core.Tests`:** Contains unit tests primarily for `CoreIdent.Core` services, validators, and store *interfaces* (using mocks).
*   **`CoreIdent.Integration.Tests`:** Contains higher-level integration tests. Includes tests for EF Core persistence, Delegated User Store adapter, and OAuth flows like Authorization Code Flow.
    *   `AuthorizationCodeFlowTests.cs`: Tests for the Authorization Code Flow with PKCE (including happy path and negative path tests).
    *   `RefreshTokenEndpointTests.cs`: Tests for the token refresh endpoint, including token theft detection scenarios.
*   **`CoreIdent.TestHost`:** A helper project providing a shared `WebApplicationFactory` for integration tests.
*   **Frameworks:** Uses `xUnit` as the test runner and `Shouldly` for assertions. Mocking is done using `Moq`.

## 8. Documentation & Root Files

*   `docs\Developer_Training_Guide.md`: Detailed guide explaining Phase 1 & 2 architecture, setup, configuration, EF Core persistence, and Delegated User Store adapter.
*   `README.md`: High-level overview, current status, phases summary, quick start guide including EF Core, Delegated Store, and OAuth endpoints.
*   `Project_Overview.md`: In-depth description of the project's vision, goals, and non-goals.
*   `Technical_Plan.md`: Outlines the planned technical architecture, components, and phases at a high level.
*   `DEVPLAN.md`: Granular task breakdown for each development phase, including user stories and test cases. Used for tracking progress.
*   `LLMINDEX.md`: This file.
*   `.gitignore`: Standard .NET Core gitignore file.
*   `LICENSE`: MIT License file.

## 9. Component-to-Phase Mapping (Current State)

*   **Phase 1 (Completed):**
    *   Established `src/CoreIdent.Core` with core services (Scoped/Singleton), endpoint logic, persistence interfaces.
*   **Phase 2 (Completed):**
    *   Created `src/CoreIdent.Storage.EntityFrameworkCore` with `DbContext` and EF Core store implementations (Scoped).
    *   Created `src/CoreIdent.Adapters.DelegatedUserStore` with delegate-based `IUserStore` implementation (Scoped).
    *   Added DI extensions (`AddCoreIdentEntityFrameworkStores`, `AddCoreIdentDelegatedUserStore`).
    *   Added EF Core Migrations.
    *   Implemented Refresh Token Rotation.
    *   Implemented automated cleanup of expired tokens with configurable retention policy.
    *   Added/updated unit and integration tests.
*   **Phase 3 (In Progress):**
    *   **Completed:**
        *   Authorization Code Flow with PKCE implementation:
            *   Added `AuthorizationCode.cs` model (`src/CoreIdent.Core/Models`).
            *   Added `IAuthorizationCodeStore.cs` interface (`src/CoreIdent.Core/Stores`).
            *   Added `InMemoryAuthorizationCodeStore.cs` implementation (`src/CoreIdent.Core/Extensions/CoreIdentEndpointRouteBuilderExtensions.cs`).
            *   Added `/authorize` endpoint logic in `CoreIdentEndpointRouteBuilderExtensions.cs` (includes concurrency-safe code generation).
            *   Enhanced `/token` endpoint logic in `CoreIdentEndpointRouteBuilderExtensions.cs` to support `authorization_code` grant type with PKCE validation.
        *   Added JWT ID Token generation for OpenID Connect (within `JwtTokenService` in `src/CoreIdent.Core/Services`).
        *   Implemented persistent `IAuthorizationCodeStore` using EF Core (`src/CoreIdent.Storage.EntityFrameworkCore/Stores/EfAuthorizationCodeStore.cs`, uses `FindAsync` and handles concurrency).
        *   Added automatic cleanup/expiry for authorization codes (`src/CoreIdent.Storage.EntityFrameworkCore/Services/AuthorizationCodeCleanupService.cs`).
        *   Added comprehensive tests for Authorization Code Flow (`tests/CoreIdent.Integration.Tests/AuthorizationCodeFlowTests.cs`).
        *   Implemented token theft detection security measures:
            *   Added token family tracking (parent-child relationship)
            *   Added configurable token theft detection response options (Silent, RevokeFamily, RevokeAllUserTokens)
            *   Enhanced refresh token stores (`IRefreshTokenStore` and implementations) to support family-wide revocation.
            *   Added unit and integration tests for token theft detection (`tests/CoreIdent.Integration.Tests/RefreshTokenEndpointTests.cs`).
            *   Enhanced `CoreIdentOptionsValidator` to validate token security configuration, ensuring consistent security behavior.
            *   Implemented secure hashing of refresh token handles using SHA-256 with user/client ID salting.
            *   Added support for storing both raw (legacy) and hashed token handles during migration period.
    *   **Next Steps:** Client Credentials Flow, Discovery endpoints

## 10. Conclusion

This index provides a snapshot of the CoreIdent project after completing the Authorization Code Flow, ID Token generation, token theft detection, and the EF Core Authorization Code Store implementation. Referencing this document should give an LLM a solid foundation for understanding the codebase, its current state, and the planned trajectory. Key documents like `DEVPLAN.md` and `Developer_Training_Guide.md` offer further details on specific aspects but require updates for the latest changes.
