# CoreIdent Project Index for LLMs (Updated for Phase 4 Start)

## 1. Purpose of this Document

This document serves as a comprehensive index and manifest for the CoreIdent project, specifically tailored for Large Language Models (LLMs). Its goal is to provide a quick and detailed understanding of the project's structure, components, current status, and development plan, enabling more effective and context-aware assistance.

The appendix is auto-generated for traceability of classes. If you add or remove classes, please update this 
section accordingly. In fact, please update this whole file (all sections) as you complete each action.

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

*   **Current Status:** Phase 4 started. User Consent Mechanism (Phase 4 feature from `DEVPLAN.md`) is complete, including backend logic (`/authorize` check, `/consent` endpoint, `IUserGrantStore`) and integration tests. Phase 3 (Core OAuth/OIDC Mechanics) is also complete.
*   **Recent Integration Test Focus:**
    *   Integration tests (`ConsentFlowTests.cs`) use cookie-based authentication (`/test-login`) to simulate a real user session.
    *   Tests verify the redirect to the consent endpoint when necessary, simulate POSTing consent decisions, and confirm correct subsequent redirects (back to `/authorize` on allow, back to client with error on deny, directly to client on subsequent requests after consent).
*   **Development Phases (Summary - see `DEVPLAN.md` for details):**
    *   **Phase 1 (Completed):** MVP - Core Registration/Login/Tokens with In-Memory Storage.
    *   **Phase 2 (Completed):** Persistent Storage (EF Core) & Interface Refinement, Delegated Storage, Refresh Token Rotation & Security.
    *   **Phase 3 (Completed):** Core OAuth 2.0 / OIDC Server Mechanics (Auth Code Flow + PKCE, Client Credentials Flow, Discovery, JWKS, ID Tokens, Authorization Code Storage & Cleanup).
    *   **Phase 4 (Current):** User Interaction & External Integrations
        *   **Completed:**
            *   User Consent Mechanism:
                *   `/authorize` endpoint updated to check `IUserGrantStore` and redirect to consent page if needed.
                *   `/consent` GET endpoint added (returns simple HTML form or redirects to configured UI URL).
                *   `/consent` POST endpoint added to handle user decisions, save grants via `IUserGrantStore`, and redirect appropriately.
                *   Defined `UserGrant` model (`src/CoreIdent.Core/Models`).
                *   Defined `IUserGrantStore` interface (`src/CoreIdent.Core/Stores`).
                *   Implemented `InMemoryUserGrantStore` (`src/CoreIdent.Core/Stores`).
                *   Implemented persistent `EfUserGrantStore` (`src/CoreIdent.Storage.EntityFrameworkCore/Stores`).
                *   Added integration tests (`tests/CoreIdent.Integration.Tests/ConsentFlowTests.cs`).
        *   **Next:** Basic Web UI (`CoreIdent.UI.Web` package), MFA Framework, External/Passwordless Providers.
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
    *   `CoreIdent.Integration.Tests`: Integration tests using `TestServer`.
        *   `AuthorizationCodeFlowTests.cs`: Tests for the Auth Code flow.
        *   `RefreshTokenEndpointTests.cs`: Tests for refresh tokens and theft detection.
        *   `ConsentFlowTests.cs`: Tests for the user consent flow.
    *   `CoreIdent.TestHost`: Shared test hosting setup.
*   **Samples Directory:** `c:\dev\prj\CoreIdent\samples\`
    *   `CoreIdent.Samples.UI.Consent.Web`: Example Razor Pages client application demonstrating OIDC flow (Login, Callback, Consent interaction).
*   **Docs Directory:** `c:\dev\prj\CoreIdent\docs\`
    *   Contains development documentation.
*   **Root Directory:** `c:\dev\prj\CoreIdent\`
    *   Contains solution file, README, planning documents, license, gitignore.

## 5. Core Project Details: `src\CoreIdent.Core`

This is the central library containing the core logic, interfaces, and models.

*   **Key Namespaces & Responsibilities:**
    *   `CoreIdent.Core.Configuration`: Handles configuration options.
        *   `CoreIdentOptions.cs`: Defines core settings.
        *   `CoreIdentRouteOptions.cs`: Defines endpoint paths (including `ConsentPath`, `DiscoveryPath`, `JwksPath`, `UserProfilePath`).
    *   `CoreIdent.Core.Models`: Defines core domain models/entities.
        *   `CoreIdentUser.cs`, `CoreIdentUserClaim.cs`
        *   `CoreIdentClient.cs`, `CoreIdentClientSecret.cs` (Includes `RequireConsent` flag)
        *   `CoreIdentScope.cs`, `CoreIdentScopeClaim.cs`
        *   `CoreIdentRefreshToken.cs`
        *   `AuthorizationCode.cs`
        *   `UserGrant.cs`: Model for storing user consent grants (SubjectId, ClientId, GrantedScopes, Expiration etc.).
        *   `Requests`: DTOs for API requests (`LoginRequest`, `RegisterRequest`, `RefreshTokenRequest`, `ConsentRequest`, `TokenRequest`, `UpdateUserProfileRequest`).
        *   `Responses`: DTOs for API responses (`TokenResponse`, `ErrorResponse`).
    *   `CoreIdent.Core.Stores`: Defines core persistence **interfaces**.
        *   `IUserStore.cs`
        *   `IRefreshTokenStore.cs`
        *   `IClientStore.cs`
        *   `IScopeStore.cs`
        *   `IAuthorizationCodeStore.cs`
        *   `IUserGrantStore.cs`: Interface for user consent grant persistence (`FindAsync`, `SaveAsync`, `StoreUserGrantAsync`, `HasUserGrantedConsentAsync`).
        *   `StoreResult.cs`
    *   `CoreIdent.Core.Stores.InMemory`: Contains default **in-memory** implementations.
        *   `InMemoryUserStore.cs`
        *   `InMemoryRefreshTokenStore.cs`
        *   `InMemoryClientStore.cs`
        *   `InMemoryScopeStore.cs`
        *   `InMemoryAuthorizationCodeStore.cs`
        *   `InMemoryUserGrantStore.cs`: In-memory implementation for `IUserGrantStore`.
    *   `CoreIdent.Core.Services`: Contains core service **interfaces** and default implementations.
        *   `IPasswordHasher.cs`
        *   `ITokenService.cs`
        *   `DefaultPasswordHasher.cs`
        *   `JwtTokenService.cs`
    *   `CoreIdent.Core.Extensions`: Provides service registration and endpoint mapping extensions.
        *   `CoreIdentServiceCollectionExtensions.cs`: `AddCoreIdent` (registers core services and default in-memory stores).
        *   `AuthEndpointsExtensions.cs`: `MapAuthEndpoints` (maps `/register`, `/login`).
        *   `OAuthEndpointsExtensions.cs`: `MapOAuthEndpoints` (maps `/authorize`, `/consent`).
        *   `UserProfileEndpointsExtensions.cs`: `MapUserProfileEndpoints` (maps `/me` or configured `UserProfilePath` relative to root or base path based on configuration).
        *   `TokenManagementEndpointsExtensions.cs`: `MapTokenManagementEndpoints` (maps endpoints relative to `TokenPath`, e.g., `token/introspect`, `token/revoke`).
        *   `TokenEndpointsExtensions.cs`: `MapTokenEndpoints` (maps `/token` using `TokenPath`, `/token/refresh`).
        *   `DiscoveryEndpointsExtensions.cs`: `MapDiscoveryEndpoints` (maps root-relative `/.well-known/openid-configuration`, `/.well-known/jwks.json`).
        *   `CoreIdentEndpointRouteBuilderExtensions.cs`: `MapCoreIdentEndpoints` (orchestrates mapping using the other `Map*` extensions).
    *   **Custom Claims Extensibility:**
        - Implemented via ICustomClaimsProvider, allowing injection of claims into tokens per user, client, scope, or request context. See README for usage.

## 6. EF Core Storage Project Details: `src\CoreIdent.Storage.EntityFrameworkCore`

*   **Purpose:** Implements the persistence layer using Entity Framework Core.
*   **Key Components:**
    *   `CoreIdentDbContext.cs`: Defines `DbSet<UserGrant>` and configures the `UserGrant` entity.
    *   `Stores`: Contains EF Core implementations.
        *   `EfUserStore.cs`
        *   `EfRefreshTokenStore.cs`
        *   `EfClientStore.cs`
        *   `EfScopeStore.cs`
        *   `EfAuthorizationCodeStore.cs`
        *   `EfUserGrantStore.cs`: Implements `IUserGrantStore` for EF Core persistence.
    *   `Services`: Background services for cleanup.
        *   `RefreshTokenCleanupService.cs`
        *   `AuthorizationCodeCleanupService.cs`
        *   (Future) `UserGrantCleanupService.cs`? (Consider adding for expired grants).
    *   `Extensions`: Contains DI extensions.
        *   `CoreIdentEntityFrameworkCoreExtensions.cs`: `AddCoreIdentEntityFrameworkStores` updated to register `EfUserGrantStore`.

## 6.5 Delegated User Store Adapter Project Details: `src\CoreIdent.Adapters.DelegatedUserStore`

*   **Purpose:** Allows integration with existing external user databases/systems.
*   **Key Components:**
    *   `DelegatedUserStoreOptions.cs`: Defines `Func<>` delegates (`FindUserByIdAsync`, `FindUserByUsernameAsync`, `ValidateCredentialsAsync`, `GetClaimsAsync`) to be provided by the consumer.
    *   `DelegatedUserStore.cs`: Implements `IUserStore` by calling the configured delegates. Write operations throw `NotImplementedException`.
    *   `Extensions/CoreIdentDelegatedUserStoreExtensions.cs`: Contains `AddCoreIdentDelegatedUserStore` extension method (registers `DelegatedUserStore` as Scoped `IUserStore`, configures and validates options).

## 7. Test Project Details: `tests\CoreIdent.*`

*   **`CoreIdent.Core.Tests`:** Unit tests.
    *   Includes tests for store interfaces (`IUserGrantStore` using mocks).
*   **`CoreIdent.Integration.Tests`:** Integration tests.
    *   `AuthorizationCodeFlowTests.cs`: Updated to handle potential consent redirects or pre-seed grants.
    *   `ConsentFlowTests.cs`: New test class specifically for verifying the consent flow logic (redirects, grant storage, subsequent requests).
*   **`CoreIdent.TestHost`:** Shared test hosting setup.

## 8. Documentation & Root Files

*   `docs\Developer_Training_Guide.md`: Needs update for Phase 3 completion and Phase 4 (Consent).
*   `README.md`: Needs update for Phase 3 completion and Phase 4 (Consent).
*   `Project_Overview.md`: (Largely stable)
*   `Technical_Plan.md`: Needs update for Phase 3/4 implementation details.
*   `DEVPLAN.md`: Updated to reflect Phase 3 completion and Phase 4 (Consent) completion.
*   `LLMINDEX.md`: This file.
*   `.gitignore`, `LICENSE`: (Unchanged)

## 9. Component-to-Phase Mapping (Current State)

*   **Phase 1 (Completed):**
    *   Established `src/CoreIdent.Core` with core services, endpoint logic, persistence interfaces.
*   **Phase 2 (Completed):**
    *   Created `src/CoreIdent.Storage.EntityFrameworkCore` (DbContext, EF stores).
    *   Created `src/CoreIdent.Adapters.DelegatedUserStore`.
    *   Added DI extensions, EF Core Migrations.
    *   Implemented Refresh Token Rotation & Security.
    *   Implemented automated cleanup of expired tokens.
*   **Phase 3 (Completed):**
    *   Authorization Code Flow + PKCE (`/authorize`, `/token`, `IAuthorizationCodeStore`, `EfAuthorizationCodeStore`, Cleanup Service).
    *   Client Credentials Flow (`/token`).
    *   ID Token Generation (`JwtTokenService`).
    *   Token Theft Detection Enhancements.
    *   OIDC Discovery & JWKS Endpoints.
*   **Phase 4 (In Progress):**
    *   **Completed:**
        *   User Consent Mechanism:
            *   Models: `UserGrant.cs`
            *   Stores: `IUserGrantStore.cs`, `InMemoryUserGrantStore.cs`, `EfUserGrantStore.cs`
            *   Endpoints: `/authorize` update, `/consent` GET/POST in `CoreIdentEndpointRouteBuilderExtensions.cs`.
            *   Configuration: `RequireConsent` flag in `CoreIdentClient`, `ConsentPath` in `CoreIdentRouteOptions`.
            *   Testing: `ConsentFlowTests.cs`.
    *   **Next:** Basic Web UI (`CoreIdent.UI.Web` package), MFA Framework, External/Passwordless Providers.
*   **Phase 5 (Future):** Advanced Features & Polish.

## 10. Conclusion

This index provides a snapshot of the CoreIdent project after completing the core OAuth/OIDC mechanics (Phase 3) and the User Consent mechanism (start of Phase 4). The focus shifts now to user-facing elements and provider integrations. Key documents require updates to reflect the latest completed features.

## 11. Appendix: Full Class Index (Traceability)

This appendix lists every class in the CoreIdent codebase (src and tests), with its full file path for maximum traceability. Classes are grouped by project/component.

### src/CoreIdent.Core
- Configuration/CoreIdentOptions.cs: CoreIdentOptions, TokenSecurityOptions, TokenTheftDetectionMode
- Configuration/CoreIdentOptionsValidator.cs: CoreIdentOptionsValidator
- Configuration/CoreIdentRouteOptions.cs: CoreIdentRouteOptions
- Extensions/AuthEndpointsExtensions.cs: AuthEndpointsExtensions
- Extensions/CoreIdentEndpointRouteBuilderExtensions.cs: CoreIdentEndpointRouteBuilderExtensions
- Extensions/CoreIdentServiceCollectionExtensions.cs: CoreIdentServiceCollectionExtensions
- Extensions/DiscoveryEndpointsExtensions.cs: DiscoveryEndpointsExtensions
- Extensions/OAuthEndpointsExtensions.cs: OAuthEndpointsExtensions
- Extensions/TokenEndpointsExtensions.cs: TokenEndpointsExtensions
- Extensions/TokenManagementEndpointsExtensions.cs: TokenManagementEndpointsExtensions
- Extensions/UserProfileEndpointsExtensions.cs: UserProfileEndpointsExtensions, UpdateUserProfileRequest
- Models/AuthorizationCode.cs: AuthorizationCode
- Models/CoreIdentClient.cs: CoreIdentClient, CoreIdentClientSecret
- Models/CoreIdentRefreshToken.cs: CoreIdentRefreshToken
- Models/CoreIdentScope.cs: CoreIdentScope, CoreIdentScopeClaim
- Models/CoreIdentUser.cs: CoreIdentUser, CoreIdentUserClaim
- Models/UserGrant.cs: UserGrant
- Models/Requests/ConsentRequest.cs: ConsentRequest
- Models/Requests/LoginRequest.cs: LoginRequest
- Models/Requests/RefreshTokenRequest.cs: RefreshTokenRequest
- Models/Requests/RegisterRequest.cs: RegisterRequest
- Models/Requests/TokenRequest.cs: TokenRequest
- Models/Responses/ErrorResponse.cs: ErrorResponse
- Models/Responses/TokenResponse.cs: TokenResponse
- Services/DefaultPasswordHasher.cs: DefaultPasswordHasher
- Services/IPasswordHasher.cs: IPasswordHasher
- Services/ITokenService.cs: ITokenService
- Services/JwtTokenService.cs: JwtTokenService
- Stores/IAuthorizationCodeStore.cs: IAuthorizationCodeStore
- Stores/IClientStore.cs: IClientStore
- Stores/IRefreshTokenStore.cs: IRefreshTokenStore
- Stores/IScopeStore.cs: IScopeStore
- Stores/IUserGrantStore.cs: IUserGrantStore
- Stores/IUserStore.cs: IUserStore
- Stores/StoreResult.cs: StoreResult
- Stores/InMemory/InMemoryAuthorizationCodeStore.cs: InMemoryAuthorizationCodeStore
- Stores/InMemory/InMemoryClientStore.cs: InMemoryClientStore
- Stores/InMemory/InMemoryRefreshTokenStore.cs: InMemoryRefreshTokenStore
- Stores/InMemory/InMemoryScopeStore.cs: InMemoryScopeStore
- Stores/InMemory/InMemoryUserGrantStore.cs: InMemoryUserGrantStore
- Stores/InMemory/InMemoryUserStore.cs: InMemoryUserStore

### src/CoreIdent.Storage.EntityFrameworkCore
- CoreIdentDbContext.cs: CoreIdentDbContext
- Extensions/CoreIdentEntityFrameworkBuilderExtensions.cs: CoreIdentEntityFrameworkBuilderExtensions
- Factories/DesignTimeDbContextFactory.cs: DesignTimeDbContextFactory
- Services/AuthorizationCodeCleanupService.cs: AuthorizationCodeCleanupService
- Services/RefreshTokenCleanupService.cs: RefreshTokenCleanupService
- Stores/EfAuthorizationCodeStore.cs: EfAuthorizationCodeStore
- Stores/EfClientStore.cs: EfClientStore
- Stores/EfRefreshTokenStore.cs: EfRefreshTokenStore
- Stores/EfScopeStore.cs: EfScopeStore
- Stores/EfUserGrantStore.cs: EfUserGrantStore
- Stores/EfUserStore.cs: EfUserStore
- Migrations/* (Multiple files)

### src/CoreIdent.Adapters.DelegatedUserStore
- DelegatedUserStore.cs: DelegatedUserStore
- DelegatedUserStoreOptions.cs: DelegatedUserStoreOptions
- Extensions/CoreIdentDelegatedUserStoreExtensions.cs: CoreIdentDelegatedUserStoreExtensions

### tests/CoreIdent.Core.Tests
- Endpoints/AuthorizeEndpointTests.cs: AuthorizeEndpointTests
- Endpoints/ConsentEndpointTests.cs: ConsentEndpointTests
- Extensions/CoreIdentServiceCollectionExtensionsTests.cs: CoreIdentServiceCollectionExtensionsTests
- Services/ConsentProcessingServiceTests.cs: ConsentProcessingServiceTests
- Services/DefaultPasswordHasherTests.cs: DefaultPasswordHasherTests
- Services/JwtTokenServiceTests.cs: JwtTokenServiceTests
- Stores/EfUserStoreTests.cs: EfUserStoreTests
- Stores/InMemoryUserStoreTests.cs: InMemoryUserStoreTests
- Infrastructure/SqliteInMemoryTestBase.cs: SqliteInMemoryTestBase

### tests/CoreIdent.Integration.Tests
- AuthorizationCodeFlowTests.cs: AuthorizationCodeFlowTests, AuthCodeTestWebApplicationFactory, HtmlFormParser
- ConsentFlowTests.cs: ConsentFlowTests
- DelegatedUserStoreIntegrationTests.cs: DelegatedUserStoreIntegrationTests, DelegatedUserStoreWebApplicationFactory
- RefreshTokenEndpointTests.cs: RefreshTokenEndpointTests, RefreshTokenTestWebApplicationFactory
- TokenCleanupServiceTests.cs: TokenCleanupServiceTests
- TokenTheftDetectionTests.cs: TokenTheftDetectionTests

### tests/CoreIdent.TestHost
- Program.cs: Program
- Setup/TestAuthHandler.cs: TestAuthHandler, TestAuthExtensions
- Setup/TestSetupFixture.cs: TestSetupFixture

## 2025-04-26 Updates

- Website deployed at https://coreident.net with accurate feature status and roadmap.
- Renamed sample project: `CoreIdent.Samples.UI.Web` → `CoreIdent.Samples.UI.Consent.Web`.
- Status and roadmap on website now reflect what is implemented vs. planned (see DEVPLAN.md for details).

---

**Note:** This appendix is auto-generated for traceability. If you add or remove classes, please update this section accordingly.
