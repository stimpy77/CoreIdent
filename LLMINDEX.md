# CoreIdent Project Index for LLMs (Updated after Phase 2)

## 1. Purpose of this Document

This document serves as a comprehensive index and manifest for the CoreIdent project, specifically tailored for Large Language Models (LLMs). Its goal is to provide a quick and detailed understanding of the project's structure, components, current status, and development plan, enabling more effective and context-aware assistance.

## 2. Project Overview & Vision

*   **Goal:** Create a modern, open-source, developer-friendly identity and authentication solution for .NET.
*   **Vision:** Empower developers with secure, easy-to-integrate authentication (traditional credentials, Passkeys, Web3, etc.) without vendor lock-in, using a modular, extensible architecture.
*   **Core Principles:** Open Source (MIT), Developer Experience, Modular & Extensible, .NET Native (9+), Secure by Default.
*   **References:**
    *   `README.md`: High-level overview, quick start, current status.
    *   `Project_Overview.md`: Detailed vision, goals, and scope.
    *   `Technical_Plan.md`: High-level technical architecture and design choices.

## 3. Current Status & Development Plan

*   **Current Status:** Phase 2 (EF Core Storage & Delegated Adapter) is complete. Phase 3 (Core OAuth/OIDC Flows) development is starting.
*   **Development Phases (Summary - see `DEVPLAN.md` for details):**
    *   **Phase 1 (Completed):** MVP - Core Registration/Login/Tokens with In-Memory Storage.
        *   Features: `/register`, `/login`, `/token/refresh` endpoints. Core services (`IPasswordHasher`, `ITokenService`), models (`CoreIdentUser`), configuration (`CoreIdentOptions`). Defined core store interfaces (`IUserStore`, `IClientStore`, `IScopeStore`, `IRefreshTokenStore`).
        *   Storage: `InMemoryUserStore` (initial implementation).
    *   **Phase 2 (Completed):** Persistent Storage (EF Core) & Interface Refinement, Delegated Storage.
        *   Features: Implemented EF Core-based stores (`EfUserStore`, `EfClientStore`, `EfScopeStore`, `EfRefreshTokenStore`). Implemented `DelegatedUserStore` adapter. Refined DI registrations (Scoped lifetimes). Added Migrations.
        *   Storage: Defined `CoreIdentDbContext` and EF Core entities in `CoreIdent.Storage.EntityFrameworkCore`. Added `CoreIdent.Adapters.DelegatedUserStore` project.
        *   Refresh Tokens: Implemented Refresh Token Rotation.
        *   Unit & Integration tests created/fixed for EF Core stores and Delegated adapter.
    *   **Phase 3 (Current):** Core OAuth 2.0 / OIDC Server Mechanics (Authorization Code Flow + PKCE, Client Credentials, Discovery).
    *   **Phase 4:** User Interaction & External Integrations (Consent, UI, MFA, Passwordless).
    *   **Phase 5:** Advanced Features & Polish (More Flows, Extensibility, Templates).
*   **Reference:** `DEVPLAN.md`: Detailed breakdown of tasks for each phase.

## 4. Project Structure (Solution Level)

*   **Solution File:** `c:\dev\prj\CoreIdent\CoreIdent.sln`
*   **Source Directory:** `c:\dev\prj\CoreIdent\src\`
    *   `CoreIdent.Core`: Core library containing interfaces, base models, core services, configuration, and endpoint logic.
    *   `CoreIdent.Storage.EntityFrameworkCore`: EF Core persistence layer (DbContext, entities configuration, store implementations).
    *   `CoreIdent.Adapters.DelegatedUserStore`: Adapter for using external user stores.
*   **Tests Directory:** `c:\dev\prj\CoreIdent\tests\`
    *   `CoreIdent.Core.Tests`: Unit tests for `CoreIdent.Core` and store implementations. Uses `Shouldly` for assertions.
    *   `CoreIdent.Integration.Tests`: Integration tests using `TestServer`.
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
        *   `CoreIdentOptionsValidator.cs`: Validates `CoreIdentOptions` (e.g., secret length).
    *   `CoreIdent.Core.Models`: Defines core domain models/entities used across layers.
        *   `CoreIdentUser.cs`, `CoreIdentUserClaim.cs`
        *   `CoreIdentClient.cs`, `CoreIdentClientSecret.cs`
        *   `CoreIdentScope.cs`, `CoreIdentScopeClaim.cs`
        *   `CoreIdentRefreshToken.cs`
        *   `Requests`: DTOs for API requests (`LoginRequest`, `RegisterRequest`, `RefreshTokenRequest`).
        *   `Responses`: DTOs for API responses (`TokenResponse`).
    *   `CoreIdent.Core.Stores`: Defines core persistence **interfaces**.
        *   `IUserStore.cs`: Interface for user persistence operations.
        *   `IRefreshTokenStore.cs`: Interface for refresh token persistence.
        *   `IClientStore.cs`: Interface for client persistence.
        *   `IScopeStore.cs`: Interface for scope persistence.
        *   `StoreResult.cs`: Enum for store operation outcomes.
    *   `CoreIdent.Core.Services`: Contains core service **interfaces** and default implementations.
        *   `IPasswordHasher.cs`: Interface for password hashing.
        *   `ITokenService.cs`: Interface for generating tokens.
        *   `DefaultPasswordHasher.cs`: Default `IPasswordHasher` implementation.
        *   `JwtTokenService.cs`: Default `ITokenService` implementation.
    *   `CoreIdent.Core.Extensions`: Provides service registration extensions.
        *   `CoreIdentServiceCollectionExtensions.cs`: Contains `AddCoreIdent` (registers core services like `ITokenService` (Scoped), `IPasswordHasher` (Singleton)) and default in-memory stores (Scoped).

## 6. EF Core Storage Project Details: `src\CoreIdent.Storage.EntityFrameworkCore`

*   **Purpose:** Implements the persistence layer using Entity Framework Core.
*   **Key Components:**
    *   `CoreIdentDbContext.cs`: Main DbContext for the application, defines `DbSet`s for all entities and configures entity relationships using `OnModelCreating`.
    *   `Stores`: Contains EF Core implementations of the store interfaces defined in `CoreIdent.Core.Stores`.
        *   `EfUserStore.cs`
        *   `EfRefreshTokenStore.cs`
        *   `EfClientStore.cs`
        *   `EfScopeStore.cs`
    *   `Extensions`:
        *   `CoreIdentEntityFrameworkCoreExtensions.cs`: Contains `AddCoreIdentEntityFrameworkStores` extension to register EF Core stores (Scoped).

## 6.5 Delegated User Store Adapter Project Details: `src\CoreIdent.Adapters.DelegatedUserStore`

*   **Purpose:** Allows integration with existing external user databases/systems.
*   **Key Components:**
    *   `DelegatedUserStoreOptions.cs`: Defines `Func<>` delegates (`FindUserByIdAsync`, `FindUserByUsernameAsync`, `ValidateCredentialsAsync`, `GetClaimsAsync`) to be provided by the consumer.
    *   `DelegatedUserStore.cs`: Implements `IUserStore` by calling the configured delegates. Write operations throw `NotImplementedException`.
    *   `Extensions/CoreIdentDelegatedUserStoreExtensions.cs`: Contains `AddCoreIdentDelegatedUserStore` extension method (registers `DelegatedUserStore` as Scoped `IUserStore`, configures and validates options).

## 7. Test Project Details: `tests\CoreIdent.*`

*   **`CoreIdent.Core.Tests`:** Contains unit tests primarily for `CoreIdent.Core` services, validators, and store *interfaces* (using mocks).
*   **`CoreIdent.Integration.Tests`:** Contains higher-level integration tests. Includes tests for EF Core persistence and the Delegated User Store adapter (using a custom `WebApplicationFactory` with mock delegates).
*   **`CoreIdent.TestHost`:** A helper project providing a shared `WebApplicationFactory` for integration tests.
*   **Frameworks:** Uses `xUnit` as the test runner and `Shouldly` for assertions. Mocking is done using `Moq`.

## 8. Documentation & Root Files

*   `docs\Developer_Training_Guide.md`: Detailed guide explaining Phase 1 & 2 architecture, setup, configuration, EF Core persistence, and Delegated User Store adapter.
*   `README.md`: High-level overview, current status, phases summary, quick start guide including EF Core and Delegated Store setup.
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
    *   Added/updated unit and integration tests.
*   **Phase 3 (Current):**
    *   Focuses on implementing core OAuth 2.0 / OIDC server mechanics (Authorization Code Flow, Client Credentials Flow, Discovery endpoints).

## 10. Conclusion

This index provides a snapshot of the CoreIdent project after the completion of Phase 2. Referencing this document should give an LLM a solid foundation for understanding the codebase, its current state, and the planned trajectory. Key documents like `DEVPLAN.md` and `Developer_Training_Guide.md` offer further details on specific aspects but require updates for the latest changes.
