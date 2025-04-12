# CoreIdent Project Index for LLMs (as of Phase 1 Completion)

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

*   **Current Status:** Phase 1 (MVP) is complete. Phase 2 development is starting.
*   **Development Phases (Summary - see `DEVPLAN.md` for details):**
    *   **Phase 1 (Completed):** MVP - Core Registration/Login/Tokens with In-Memory Storage.
        *   Features: `/register`, `/login`, `/token/refresh` endpoints.
        *   Storage: `InMemoryUserStore`, non-persistent refresh token validation.
        *   Authentication: JWT Access Tokens, basic Refresh Tokens.
        *   Hashing: `IPasswordHasher` using ASP.NET Core Identity defaults (PBKDF2).
    *   **Phase 2 (Current):** Persistent Storage (EF Core) & Interface Refinement.
        *   Goal: Implement `IUserStore` and `IRefreshTokenStore` using Entity Framework Core.
        *   Goal: Define `DbContext` and entities (`CoreIdentUser`, `CoreIdentRefreshToken`).
        *   Goal: Refine storage interfaces as needed.
    *   **Phase 3:** Enhanced Token Management & Security (Revocation, Sliding Expiration).
    *   **Phase 4:** UI/Admin Portal (Basic Management).
    *   **Phase 5:** Pluggable Providers & Advanced Features (Social Logins, Passkeys, etc.).
*   **Reference:** `DEVPLAN.md`: Detailed breakdown of tasks for each phase.

## 4. Project Structure (Solution Level)

*   **Solution File:** `c:\dev\prj\CoreIdent\CoreIdent.sln`
*   **Source Directory:** `c:\dev\prj\CoreIdent\src\`
    *   `CoreIdent.Core`: Core library containing interfaces, base models, services, configuration, and endpoint logic for Phase 1.
    *   *(Future: `CoreIdent.Stores.EFCore` for EF Core persistence)*
*   **Tests Directory:** `c:\dev\prj\CoreIdent\tests\`
    *   `CoreIdent.Core.Tests`: Unit and integration tests for `CoreIdent.Core`. Uses `Shouldly` for assertions.
*   **Docs Directory:** `c:\dev\prj\CoreIdent\docs\`
    *   Contains development documentation.
*   **Root Directory:** `c:\dev\prj\CoreIdent\`
    *   Contains solution file, README, planning documents, license, gitignore.

## 5. Core Project Details: `src\CoreIdent.Core`

This is the central library containing the core logic as of Phase 1.

*   **Key Namespaces & Responsibilities:**
    *   `CoreIdent.Core.Abstractions`: Defines core interfaces.
        *   `Hashing\IPasswordHasher.cs`: Interface for password hashing and verification.
        *   `Services\ITokenService.cs`: Interface for generating access and refresh tokens.
        *   `Stores\IUserStore.cs`: Interface for user persistence operations (CRUD-like methods).
        *   *(Future: `Stores\IRefreshTokenStore.cs`)*
    *   `CoreIdent.Core.Configuration`: Handles configuration options.
        *   `CoreIdentOptions.cs`: Defines configuration settings (Issuer, Audience, Secret, Lifetimes).
        *   `Validators\CoreIdentOptionsValidator.cs`: Validates `CoreIdentOptions` (e.g., secret length).
    *   `CoreIdent.Core.DTOs` (Data Transfer Objects): Defines request/response models for endpoints.
        *   `LoginRequest.cs`: Contains `Email`, `Password`.
        *   `RegisterRequest.cs`: Contains `Email`, `Password`.
        *   `RefreshTokenRequest.cs`: Contains `RefreshToken`.
        *   `TokenResponse.cs`: Contains `AccessToken`, `RefreshToken`.
    *   `CoreIdent.Core.Endpoints`: Defines the Minimal API endpoints.
        *   `CoreIdentEndpointRouteBuilderExtensions.cs`: Contains `MapCoreIdentEndpoints` extension method to register routes (`/register`, `/login`, `/token/refresh`). Implements the logic for each endpoint, coordinating calls to services and stores.
    *   `CoreIdent.Core.Extensions`: Provides service registration extensions.
        *   `ServiceCollectionExtensions.cs`: Contains `AddCoreIdent` extension method for easy DI setup (registers options, validators, services, stores).
    *   `CoreIdent.Core.Models`: Defines core domain models.
        *   `CoreIdentUser.cs`: Represents a user entity (Id, UserName, NormalizedUserName, PasswordHash).
    *   `CoreIdent.Core.Services`: Contains implementations of service interfaces.
        *   `DefaultPasswordHasher.cs`: Default `IPasswordHasher` implementation wrapping `Microsoft.AspNetCore.Identity.PasswordHasher`.
        *   `JwtTokenService.cs`: Default `ITokenService` implementation generating JWTs and basic refresh tokens. Uses `System.IdentityModel.Tokens.Jwt`.
    *   `CoreIdent.Core.Stores`: Contains default (Phase 1) store implementations.
        *   `InMemoryUserStore.cs`: Default, non-persistent `IUserStore` implementation using `ConcurrentDictionary`.

## 6. Test Project Details: `tests\CoreIdent.Core.Tests`

*   **Purpose:** Contains unit and integration tests for the `CoreIdent.Core` library.
*   **Frameworks:** Uses `xUnit` as the test runner and `Shouldly` for assertions.
*   **Structure:** Tests are generally organized mirroring the structure of `CoreIdent.Core` (e.g., `ServiceTests`, `EndpointTests`, `ValidatorTests`).
*   **Key Tests:** Includes tests for `JwtTokenService` generation/validation, `DefaultPasswordHasher`, `CoreIdentOptionsValidator`, `InMemoryUserStore` operations, and end-to-end tests for the `/register`, `/login`, and `/token/refresh` endpoints.

## 7. Documentation & Root Files

*   `docs\Developer_Training_Guide.md`: Detailed guide explaining Phase 1 architecture, setup, configuration, and features for developers using/integrating CoreIdent.
*   `README.md`: High-level overview, current status, phases summary, quick start guide for Phase 1.
*   `Project_Overview.md`: In-depth description of the project's vision, goals, and non-goals.
*   `Technical_Plan.md`: Outlines the planned technical architecture, components, and phases at a high level.
*   `DEVPLAN.md`: Granular task breakdown for each development phase, including user stories and test cases. Used for tracking progress.
*   `LLMINDEX.md`: This file.
*   `.gitignore`: Standard .NET Core gitignore file.
*   `LICENSE`: MIT License file.

## 8. Component-to-Phase Mapping (Current State)

*   **Phase 1 (Completed):**
    *   All components currently within `src/CoreIdent.Core` represent the completed Phase 1 implementation.
    *   `InMemoryUserStore` is the Phase 1 default for `IUserStore`.
    *   Endpoints in `MapCoreIdentEndpoints` provide Phase 1 functionality.
    *   `JwtTokenService` and `DefaultPasswordHasher` are the Phase 1 service implementations.
*   **Phase 2 (Starting):**
    *   The primary goal is to create the `src/CoreIdent.Stores.EFCore` project.
    *   This new project will contain EF Core implementations of `IUserStore` and a new `IRefreshTokenStore`.
    *   Configuration extensions will be needed to allow switching between `InMemoryUserStore` and `EFCoreUserStore`.

## 9. Conclusion

This index provides a snapshot of the CoreIdent project after the completion of Phase 1. Referencing this document should give an LLM a solid foundation for understanding the codebase, its current state, and the planned trajectory. Key documents like `DEVPLAN.md` and `Developer_Training_Guide.md` offer further details on specific aspects.
