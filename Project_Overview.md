# CoreIdent: Project Overview & Development Plan

## Vision

CoreIdent aims to be the modern, open-source, developer-friendly identity and authentication solution for the .NET ecosystem. It prioritizes convention over configuration, modularity, and ease of integration, filling the gap left by the commercialization of popular predecessors. CoreIdent will empower developers to quickly implement secure authentication and authorization without vendor lock-in, embracing both traditional and emerging identity paradigms like Decentralized Identity (DID) concepts. It offers a clear path for extending functionality through a pluggable provider model.

## Core Principles

*   **Open Source:** MIT or similar permissive license.
*   **Developer Experience:** Minimize boilerplate, maximize productivity through conventions and clear APIs.
*   **Modular & Extensible:** Core functionality is lean; advanced features and storage options are separate NuGet packages.
*   **.NET Native:** Built on modern .NET (currently .NET 9/10+), leveraging ASP.NET Core best practices.
*   **Secure by Default:** Implement security best practices for token handling, password storage, and endpoint protection.
*   **Protocol Support:** Designed for modern web communication, including standard HTTP APIs (HTTP/1.1, HTTP/2, HTTP/3) and built-in support for WebSocket communication channels.
*   **Future-Ready Authentication:** Support for both traditional credentials and modern passwordless methods (like Passkeys/WebAuthn) alongside decentralized approaches (Web3, LNURL).
*   **User Control & Data Portability Alignment:** Design with principles of user consent, control over identity data, and alignment with emerging data portability regulations in mind.
*   **Community Driven:** Encourage contributions for new providers, storage mechanisms, and features.

## High-Level Feature Summary

*   **Core Authentication (HTTP API):**
    *   User Registration (email/password)
    *   User Login (email/password)
    *   JWT Token Issuance (Access Tokens, OIDC ID Tokens)
    *   Refresh Token Flow (for extending sessions)
    *   Multi-Factor Authentication (MFA) Framework.
*   **Machine-to-Machine (M2M) Authentication:**
    *   Client Credentials Flow for service/application authentication.
*   **Platform Capabilities:**
    *   Support for standard HTTP/1.1, HTTP/2, HTTP/3 via ASP.NET Core.
    *   Built-in infrastructure readiness for WebSocket communication.
    *   Standard OAuth 2.0 / OIDC Flows (Authorization Code + PKCE, Client Credentials).
    *   OIDC Discovery & JWKS endpoints.
*   **Client Libraries:**
    *   `CoreIdent.Client` - Core client library for mobile & desktop applications.
    *   Platform-specific implementations (.NET MAUI, WPF, Xamarin, etc.).
    *   Token management (secure storage, auto-refresh, validation).
    *   Offline authentication support.
*   **Pluggable Storage & User Management:**
    *   Core interfaces (`IUserStore`, `IRefreshTokenStore`, etc.) allow flexible backends.
    *   In-Memory Store (default for testing/development).
    *   Entity Framework Core Store (SQL Server, PostgreSQL, SQLite, etc.).
    *   Delegated User Store Adapter (for integrating with existing user systems).
*   **Extensible Provider Model:**
    *   Passwordless Login (Passkeys / WebAuthn / FIDO2).
    *   Time-based One-Time Password (TOTP) MFA Provider.
    *   Google Login (Example Social Provider).
    *   Web3 Wallet Login (e.g., MetaMask via signature verification).
    *   LNURL-auth Login (Bitcoin Lightning Network).
    *   (Future) Other social providers, SAML, etc.
*   **User Interface Components:**
    *   Optional package (`CoreIdent.UI.Web`) providing basic, themeable UI components (e.g., Razor Components/Pages) for core user flows (Login, Register, Consent, MFA prompts).
*   **Administration:**
    *   Optional Admin UI (separate package) for managing users, potentially clients/scopes and basic data export.
*   **Tooling:**
    *   `dotnet new` templates for easy project setup.
    *   Clear documentation and examples.

## Protocol & Feature Roadmap

A summary of major protocols and features, their status in CoreIdent, and what's coming next. For technical details, see [DEVPLAN.md](https://github.com/stimpy77/CoreIdent/blob/main/DEVPLAN.md). See also the [Feature Roadmap](https://coreident.net/features.html) on the website for the latest status.

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

## Phased Managerial Development Plan

This plan outlines the major deliverables and focus for each development phase. Each phase builds upon the previous one, delivering incremental value.

### Phase 1: MVP Core (Foundation - Estimated: 4-6 weeks)
*   **Goal:** Establish the fundamental authentication flow and core package structure.
*   **Deliverables:**
    *   `CoreIdent.Core` NuGet package.
    *   Basic JWT issuance (login/token endpoints).
    *   Basic registration endpoint.
    *   In-memory user store.
    *   Core configuration options.
    *   Basic `AddCoreIdent()` setup extension.
    *   Unit tests for core services.
    *   Initial README with basic setup instructions.
*   **Focus:** Core API design, token generation logic, minimal viable setup.

### Phase 2: Storage & Core Extensibility (Estimated: 3-5 weeks)
*   **Goal:** Enable persistent user storage and provide options for integrating with existing user systems, refining core interfaces for extensibility.
*   **Deliverables:**
    *   Refined `IUserStore`, `IRefreshTokenStore` interfaces (designed for both integrated and delegated scenarios).
    *   Defined `IClientStore`, `IScopeStore` interfaces.
    *   `CoreIdent.Storage.EntityFrameworkCore` NuGet package (and potentially `CoreIdent.Storage.Sqlite`) providing integrated user/token/client/scope persistence.
    *   `CoreIdent.Adapters.DelegatedUserStore` (or similar) providing an adapter to plug into external user management systems via configured callbacks/services.
    *   Robust refresh token implementation (storage, validation, rotation) using the storage interfaces.
    *   Updated setup extensions (`AddEntityFrameworkStores`, `AddSqliteStores`, `AddDelegatedUserStore`).
    *   Integration tests for storage layer (both EF Core and delegated scenarios where possible).
*   **Focus:** Database persistence, interface refinement, reliable session management, defining client/scope structures, providing clear paths for both integrated and delegated user management.

### Phase 3: Core OAuth 2.0 / OIDC Server Mechanics (Estimated: 4-6 weeks)
*   **Goal:** Implement the essential backend logic for standard authorization flows and discovery.
*   **Deliverables:**
    *   Implementation of Authorization Code Flow endpoints.
    *   Implementation of Client Credentials Flow endpoint.
    *   Implementation of OIDC Discovery & JWKS endpoints.
    *   Capability to issue OIDC ID Tokens.
    *   Backend logic for validating clients and scopes using defined stores.
    *   Integration tests for core OAuth/OIDC flows.
*   **Focus:** Standard protocol implementation, token exchange logic, server metadata publishing.

### Phase 4: User Interaction & External Integrations (Estimated: 6-9 weeks - parallel work possible)
*   **Goal:** Introduce user-facing elements for OAuth/OIDC flows, MFA, and add external/passwordless login capabilities.
*   **Deliverables:**
    *   Basic User Consent mechanism/page.
    *   `CoreIdent.UI.Web` package providing basic, themeable/overridable UI components (e.g., Razor Components/Pages) for core flows (Login, Register, Consent, MFA prompt).
    *   Standard OIDC Logout endpoint implementation.
    *   MFA Framework implementation (logic to enforce/trigger second factors).
    *   `CoreIdent.Providers.Abstractions` package.
    *   `CoreIdent.Providers.Passkeys` package (WebAuthn/FIDO2 support).
    *   `CoreIdent.Providers.Totp` package (MFA provider).
    *   `CoreIdent.Providers.Google` package.
    *   `CoreIdent.Providers.Web3` package.
    *   `CoreIdent.Providers.LNURL` package.
    *   (Optional) `CoreIdent.AdminUI` package (basic user/client management UI, potential data export).
    *   Unit/Integration tests for providers and UI elements.
*   **Focus:** User experience in auth flows, passwordless auth, MFA, external identity integration, optional administration features.

### Phase 5: Community, Documentation & Tooling (Ongoing / Estimated: 4+ weeks after Phase 3 starts)
*   **Goal:** Make CoreIdent easy to adopt, use, and contribute to.
*   **Deliverables:**
    *   Dedicated documentation website (e.g., `docs.coreident.net`).
    *   Comprehensive guides (Getting Started, Configuration, API Reference, Providers, MFA Setup).
    *   `dotnet new` project templates (`coreident-server`, `coreident-api`).
    *   Example applications showcasing integration.
    *   CI/CD pipeline for automated builds, testing, and NuGet publishing.
    *   Contribution guidelines and community setup (e.g., GitHub Discussions).
*   **Focus:** User adoption, developer support, community building, polish.

## Success Metrics

*   NuGet package downloads.
*   GitHub stars/forks.
*   Community contributions (issues, PRs, provider additions).
*   Adoption in open-source or commercial projects.
*   Positive feedback on ease of use and developer experience.