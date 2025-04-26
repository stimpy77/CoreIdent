# CoreIdent: Technical Plan

This document outlines the technical components, architecture, and requirements for each phase of the CoreIdent project.

## Core Technology Stack

*   **.NET 9/10+** (LTS preferred)
*   **ASP.NET Core Minimal APIs** (for core endpoints)
*   **JWT** (JSON Web Tokens) for token issuance (`System.IdentityModel.Tokens.Jwt`)
*   **ASP.NET Core Identity** (can be leveraged or replaced for user management, TBD based on flexibility needs)
*   **Standard .NET Dependency Injection**

## Architecture Principles

*   **Modular:** Functionality split into NuGet packages (`CoreIdent.Core`, `CoreIdent.Storage.*`, `CoreIdent.Providers.*`).
*   **Interface-Driven:** Key components (user stores, token services, etc.) defined by interfaces to allow custom implementations.
*   **Convention over Configuration:** Minimize boilerplate setup; provide sensible defaults. Extension methods for `IServiceCollection` (`AddCoreIdent()`) will encapsulate setup.
*   **Testability:** Design components with unit and integration testing in mind.
*   **Protocol Readiness:** Leverages ASP.NET Core/Kestrel's built-in support for HTTP/1.1, HTTP/2, and HTTP/3. The platform is architected to support WebSocket communication as a core capability.

## Testing Strategy

A comprehensive testing strategy is essential for reliability and maintainability.

*   **Unit Tests:**
    *   **Goal:** Verify individual components (services, helpers, validators) in isolation.
    *   **Tools:** Test frameworks (xUnit, NUnit, MSTest), Mocking libraries (`Moq`, `NSubstitute`), Assertion libraries (`Shouldly`, `FluentAssertions`).
    *   **Focus:** Logic correctness, edge cases, dependency mocking.
*   **Integration Tests:**
    *   **Goal:** Verify interactions between components within the application, including API endpoints and data persistence layers, without external network dependencies.
    *   **Tools:**
        *   `Microsoft.AspNetCore.Mvc.Testing`: For in-memory hosting and HTTP client interactions.
        *   EF Core In-Memory Database or SQLite In-Memory Mode: For database tests.
        *   `Testcontainers`: Optionally, for testing against real database engines (e.g., PostgreSQL) in ephemeral Docker containers.
    *   **Focus:** API endpoint responses, request validation, data persistence correctness, middleware behaviour.
*   **End-to-End (E2E) / Functional Tests:**
    *   **Goal:** Validate complete user flows and features from an external client's perspective, potentially against a deployed instance.
    *   **Tools:**
        *   `HttpClient` within C# test projects.
        *   Language-agnostic tools (e.g., `Postman`/`Newman`, `k6`, scripts using `curl`) for black-box HTTP validation.
    *   **Focus:** Authentication flows (registration, login, token refresh, accessing protected resources), provider integration (using test accounts or mocks where appropriate), overall system behaviour.

## Phased Technical Breakdown

### Phase 1: MVP Core (Foundation)

*   **`CoreIdent.Core` Package:**
    *   **Endpoints:**
        *   `POST /register`: User registration (e.g., email/password). Hashing passwords securely (ASP.NET Core Identity password hasher).
        *   `POST /login`: User login, validates credentials.
        *   `POST /token`: Issues JWT access token upon successful login. Optionally issues refresh token (simple implementation initially).
        *   `POST /token/refresh`: (Optional in MVP) Accepts a refresh token, validates it, and issues a new access token.
        *   `GET /userinfo`: (Optional, standard OIDC) Authenticated endpoint returning basic user claims.
    *   **Services:**
        *   `ITokenService`: Interface for JWT generation (claims, signing, expiry).
        *   `JwtTokenService`: Default implementation using symmetric or asymmetric keys configured via options.
        *   `IUserStore`: Interface for basic user CRUD (Create, Read By Username/ID).
        *   `InMemoryUserStore`: Default implementation for MVP. Stores users in memory.
        *   `IPasswordHasher`: Interface for password hashing/verification.
        *   `DefaultPasswordHasher`: Implementation (potentially wrapping ASP.NET Core's).
    *   **Configuration (`CoreIdentOptions`):**
        *   Issuer URL
        *   Audience
        *   Signing Key (symmetric secret or key material path/details for asymmetric)
        *   Token Lifetimes (Access Token, Refresh Token)
    *   **Setup:**
        *   `IServiceCollection.AddCoreIdent(Action<CoreIdentOptions> configureOptions)` extension method.
        *   `IApplicationBuilder.UseCoreIdent()` (or similar for endpoint mapping).
        *   Integration with `Microsoft.AspNetCore.Authentication.JwtBearer` for token validation in consuming APIs.
    *   **Interface Design Consideration:** `IUserStore` definition will focus on data retrieval/validation needs of the core engine, keeping implementation details flexible to support both integrated and delegated storage models introduced later.

### Phase 2: Storage & Core Extensibility

*   **Refine Interfaces:**
    *   `IUserStore`: Expand to include methods needed for password management, claim management, etc., ensuring compatibility with both integrated (e.g., EF Core) and delegated (external system) implementations.
    *   `IRefreshTokenStore`: Interface for storing and validating refresh tokens (potentially linked to users/clients).
    *   `IClientStore`: Define interface for managing OAuth client application registrations (ID, secrets, redirect URIs, allowed grant types, scopes).
    *   `IScopeStore`: Define interface for managing available OAuth scopes (name, description, associated claims).
*   **`CoreIdent.Storage.EntityFrameworkCore` Package:**
    *   **Dependencies:** `Microsoft.EntityFrameworkCore`, `Microsoft.EntityFrameworkCore.Relational`.
    *   **Components:**
        *   `CoreIdentDbContext`: EF Core DbContext inheriting from a base or defining `DbSet`s for `CoreIdentUser`, `CoreIdentRefreshToken`, `CoreIdentClient`, `CoreIdentScope` etc.
        *   `EfUserStore`: Implementation of `IUserStore`.
        *   `EfRefreshTokenStore`: Implementation of `IRefreshTokenStore`.
        *   `EfClientStore`: Implementation of `IClientStore`.
        *   `EfScopeStore`: Implementation of `IScopeStore`.
    *   **Setup:**
        *   `IServiceCollection.AddCoreIdent().AddEntityFrameworkStores<TContext>()` extension method, requiring `DbContextOptions` configuration.
*   **`CoreIdent.Storage.Sqlite` Package (Alternative):**
    *   **Dependencies:** `Microsoft.EntityFrameworkCore.Sqlite`.
    *   **Components:** EF Core implementation for SQLite.
    *   **Setup:** `IServiceCollection.AddCoreIdent().AddSqliteStores(...)`.
*   **`CoreIdent.Adapters.DelegatedUserStore` Package (New):**
    *   **Goal:** Allow integration with existing application user databases/logic.
    *   **Components:**
        *   `DelegatedUserStore`: Implementation of `IUserStore`.
        *   Configuration options/services to register application-specific delegates/services for: Finding users (by ID, username, provider subject), Creating users (optional, based on external provider info), Validating credentials (optional, if CoreIdent needs to handle password flows against the external store), Getting/Setting claims.
    *   **Setup:** `IServiceCollection.AddCoreIdent().AddDelegatedUserStore(Action<DelegatedUserStoreOptions> configure)` extension method.
*   **Refresh Token Logic:** Implement robust refresh token generation, storage (hashed token), validation (prevent replay), and revocation using the configured `IRefreshTokenStore`.

### Phase 3: Core OAuth 2.0 / OIDC Server Mechanics

*   **Goal:** Implement backend logic for standard flows and discovery.
*   **Note:** Focus is on the core protocol mechanics and endpoints. User-facing elements like consent are deferred to Phase 4.
*   **Core Functionality:**
    *   Implement **Authorization Code Flow** endpoints:
        *   `GET /authorize`: Handles user authentication redirection and initial request validation.
        *   `POST /token` (grant type `authorization_code`): Exchanges authorization code for tokens.
        *   **Requirement:** Must support **PKCE (Proof Key for Code Exchange)** for public clients like mobile apps.
    *   Implement **Client Credentials Flow** endpoint:
        *   `POST /token` (grant type `client_credentials`): Issues tokens directly to M2M clients.
    *   Implement **OIDC Discovery Endpoint:**
        *   `GET /.well-known/openid-configuration`: Publishes server metadata.
    *   Implement **JWKS Endpoint:**
        *   `GET /.well-known/jwks.json`: Publishes public signing keys.
    *   **ID Token Issuance:** Add capability to issue OIDC ID Tokens alongside access tokens for relevant flows.
    *   **Client/Scope Management Backend:** Integrate with `IClientStore` and `IScopeStore` to validate client requests, scopes, grant types, and redirect URIs.

### Phase 4: User Interaction & External Integrations

*   **Goal:** Add user-facing elements and external login capabilities.
*   **Deliverables:**
    *   **User Consent:** Implement a basic consent mechanism/page displayed during the Authorization Code Flow (can start minimal and be refined later).
    *   **OIDC Logout:** Implement standard logout endpoint (`GET /endsession` or similar) to terminate user session.
    *   **MFA Framework:**
        *   Core logic to track MFA status/requirements per user.
        *   Mechanism to trigger second-factor prompts during login/authorize flows.
        *   Interfaces for pluggable MFA providers (`IMfaProvider`).
    *   **`CoreIdent.Providers.Abstractions` Package:**
        *   Defines interfaces and base classes for external authentication providers.
        *   Standardizes callback handling and user profile mapping.
    *   **`CoreIdent.Providers.Passkeys` Package:**
        *   Implements WebAuthn/FIDO2 registration and authentication ceremonies.
        *   Endpoints for challenge generation, credential registration, assertion verification.
        *   Storage for public key credentials linked to users.
    *   **`CoreIdent.Providers.Totp` Package:**
        *   Implements `IMfaProvider`.
        *   Logic for TOTP setup (QR code generation, secret storage) and validation.
    *   **`CoreIdent.Providers.Google` Package:**
        *   Handles OAuth2 flow with Google, maps profile to CoreIdent user.
        *   Setup: `AddGoogleProvider(...)`.
    *   **`CoreIdent.Providers.Web3` Package:**
        *   Challenge/signature verification for wallet login.
        *   Setup: `AddWeb3Provider(...)`.
    *   **`CoreIdent.Providers.LNURL` Package:**
        *   LNURL-auth spec implementation.
        *   Setup: `AddLnurlAuthProvider(...)`.
    *   **`CoreIdent.AdminUI` Package (Optional):**
        *   Basic UI for managing users, potentially clients/scopes.
        *   Technology: Razor Pages, Blazor Server/WASM.
        *   **Note:** Given potential complexity, could start with a CLI or very minimal web interface if resources are constrained.

### Phase 5: Community, Documentation & Tooling

*   **Goal:** Facilitate adoption, usage, and contribution.
*   **Deliverables:**
    *   **Documentation Site:**
        *   Technology: Static Site Generator (e.g., Docusaurus, VitePress, MkDocs).
        *   Content: Getting started, configuration, API reference, architecture, provider guides, contribution guide.
    *   **`dotnet new` Templates:**
        *   `coreident-server`: Minimal project with CoreIdent and EF Core storage.
        *   `coreident-api`: Minimal API using CoreIdent for auth.
    *   **Example Projects:** Showcase integration patterns.
    *   **Build & Test Pipeline:** CI/CD setup (e.g., GitHub Actions) for builds, tests, NuGet publishing.
    *   **Contribution Guidelines & Community Setup.**

## Protocol & Feature Roadmap

Below is a summary of major protocols and features, their status in CoreIdent, and what's coming next. For implementation details, see [DEVPLAN.md](https://github.com/stimpy77/CoreIdent/blob/main/DEVPLAN.md). For the latest status, see the [Feature Roadmap](https://coreident.net/features.html) on the website.

| Protocol / Feature | Description / Notes | CoreIdent Status |
|--------------------|--------------------|------------------|
| OAuth2 Authorization Code Flow (with PKCE) | Secure web-app flow with PKCE for public clients | **Fully implemented** |
| JWT Access Tokens & Refresh Tokens | Standard issuance of JWTs plus refresh grant for long-lived sessions | **Fully implemented** |
| External Identity Providers (Social/Enterprise Login) | OIDC/OAuth federation (Google, Facebook, SAML/WS-Fed) | *Planned* |
| Multi-Factor Authentication (MFA) & Passwordless | 2nd-factor (TOTP/WebAuthn) and passwordless options | *Planned* |
| Dynamic Client Registration (RFC 7591) | Programmatic registration of OAuth clients | *Planned* |
| Client-Initiated Backchannel Authentication (CIBA, RFC 9126) | Asynchronous user-approval flow for critical AI actions | *Planned* |
| Pushed Authorization Requests (PAR, RFC 9121) | Secure “push” of auth requests to avoid leaking request parameters | *Planned* |
| Device Authorization Flow (RFC 8628) | Grant for devices with limited input (e.g. IoT, consoles) | *Planned* |
| Token Introspection (RFC 7662) | Endpoint for resource servers to validate token metadata | *Planned* |
| Token Revocation (RFC 7009) | Endpoint to revoke tokens on logout or compromise | *Planned* |
| JWKS & Key Rotation | JWKS endpoint and automated key-rotation for signing keys | *Planned* |
| Consent Screen (OIDC) | User-facing UI to approve scopes/permissions | *Planned* |
| Audit Logging | Structured logging of login, consent, token events | *Planned* |
| Fine-Grained Authorization (FGA/RBAC) | Relationship-based or attribute-based access control for per-document/data enforcement | Under consideration |
| Token Vault / Secrets Management | Secure storage of 3rd-party API tokens (so secrets never go into prompts) | Under consideration |
| Out-of-Band Approvals for AI Actions | Human-in-the-loop confirmation for high-risk AI requests (beyond CIBA) | Under consideration |
| AI-Framework SDK Integrations | Turn-key libraries (LangChain, LlamaIndex, Vercel AI SDK, etc.) | Under consideration |
| Management Dashboard & Admin UI | Web UI to configure connections, policies, guardrails, logs | *Planned* |
| Anomaly Detection & Alerts | Automated detection of suspicious auth behaviors (brute-force, credential stuffing, etc.) | Under consideration |

## Security Considerations

*   **Password Hashing:** Use industry-standard algorithms (e.g., Argon2id or PBKDF2 via ASP.NET Core Identity).
*   **Token Security:** Use strong signing keys (asymmetric keys recommended for production), short access token lifetimes, secure refresh token handling (storage, rotation).
*   **Input Validation:** Validate all inputs to prevent injection attacks.
*   **Rate Limiting:** Implement rate limiting on sensitive endpoints like login, register, token refresh.
*   **Comprehensive Audit Logging:** Implement structured logging for all significant security events (logins, failures, token issuance, MFA events, admin actions) to enable external monitoring and threat detection (e.g., by SIEM systems).
*   **Dependency Scanning:** Regularly scan dependencies for vulnerabilities.
*   **Secure Headers:** Apply standard security headers (CSP, HSTS, etc.) especially for the Admin UI. 