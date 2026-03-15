
# CoreIdent: Detailed Development Plan (DEVPLAN.md)

This document provides a detailed breakdown of tasks, components, test cases, and technical guidance for CoreIdent. It aligns with the vision in `Project_Overview.md` and technical specifications in `Technical_Plan.md`.

> ### Maintaining this document
>
> This file is paired with [`DEVPLAN_completed.md`](DEVPLAN_completed.md). Together they form the authoritative task-level record of CoreIdent development.
>
> **While a feature is in progress**, keep its full checklist here in DEVPLAN.md — all checkboxes, code snippets, guidance notes, and test cases.
>
> **Once a feature is fully complete** (every checkbox checked, all tests passing, no remaining concerns), archive it:
>
> 1. **Move** the entire feature section (header, checkboxes, code snippets, guidance, test cases — everything) into `DEVPLAN_completed.md` under the appropriate phase heading.
> 2. **Replace** the moved section in this file with a compact summary:
>    ```markdown
>    ### Feature X.Y: [Name] — COMPLETE
>    > Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-xy-name)
>
>    **Summary:** [1-2 sentence description of what was implemented]
>    **Key entry points:** `src/path/to/main/file.cs`
>    ```
> 3. **Update** the TL;DR status summary table at the top of this file.
>
> Do **not** move partially complete features. If even one checkbox is unchecked or there are known concerns, the feature stays here in full detail until resolved.

**Key priorities:**
- Phase 0 (Foundation) is now first priority — asymmetric keys, revocation, introspection
- Passwordless authentication is Phase 1
- Test infrastructure overhaul is a dedicated effort
- Removed: Web3, LNURL, AI integrations
- Added: DPoP, RAR, SPIFFE/SPIRE (later phases)

> **Note:** References to "creating" components mean implementing the feature within the current architecture.

**Checklist Legend:**
- `[x]` — Complete
- `[ ]` — Not started
- `[~]` — Partial / needs revisit after prior feature is implemented

**LX Levels (LLM capability required):**
- `L1`: Low stakes, low accuracy requirements — if wrong, easy to fix, doesn't break anything important
- `L2`: Moderate stakes — should be correct, errors catchable in review/testing
- `L3`: High stakes, high accuracy requirements — must be correct, worth spending money to succeed

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
| OIDC UserInfo Endpoint | 1 | 1.10 | ✅ Complete |
| Resource Owner Endpoints (Register/Login/Profile) | 1 | 1.11 | ✅ Complete |
| Password Grant (ROPC) | 1 | 1.12 | ✅ Extracted to Legacy Package |
| Follow-Up Cleanup | 1 | 1.13 | ✅ Complete |
| OAuth 2.1 Compliance Declaration | 1 | 1.14 | 🔲 Planned |
| JWT Access Token Profile (RFC 9068) | 1 | 1.15 | 🔲 Planned |
| OIDC Authorize Parameters | 1 | 1.16 | 🔲 Planned |
| Auth Session Management | 1 | 1.17 | 🔲 Planned |
| Account Recovery / Password Reset | 1 | 1.18 | 🔲 Planned |
| Incremental Consent | 1 | 1.19 | ✅ Complete |
| CORS Convenience | 1 | 1.20 | 🔲 Planned |
| RFC 8414 OAuth AS Metadata | 1 | 1.21 | 🔲 Planned |
| ROPC Extraction to Legacy Package | 1 | 1.22 | ✅ Complete |
| Blazor Unification (Rename) | 1 | 1.23 | 🔲 Planned |
| Provider Abstraction Layer | 2 | 2.1 | ✅ Complete |
| Google Provider | 2 | 2.2 | 🔲 Planned |
| Microsoft Provider | 2 | 2.3 | 🔲 Planned |
| GitHub Provider | 2 | 2.4 | 🔲 Planned |
| Apple Provider | 2 | 2.5 | 🔲 Planned |
| JS/TS Client Documentation | 2 | 2.6 | 🔲 Planned |
| Rate Limiting (IRateLimiter) | 2 | 2.7 | 🔲 Planned |
| Key Rotation | 3 | 3.1 | 🔲 Planned |
| Session Management & OIDC Logout (incl. Back-Channel) | 3 | 3.2 | 🔲 Planned |
| Dynamic Client Registration | 3 | 3.3 | 🔲 Planned |
| Device Authorization Flow | 3 | 3.4 | 🔲 Planned |
| PAR (RFC 9126) | 3 | 3.5 | 🔲 Planned |
| DPoP (RFC 9449) | 3 | 3.6 | 🔲 Planned |
| RAR (RFC 9396) | 3 | 3.7 | 🔲 Planned |
| MCP-Compatible Authorization Server | 3 | 3.13 | 🔲 Planned |
| mTLS Client Authentication (RFC 8705) | 3 | 3.14 | 🔲 Planned |
| UI Package | 4 | 4.1 | 🔲 Planned |
| Admin API | 4 | 4.3 | 🔲 Planned |
| Domain Verification | 4 | 4.5 | 🔲 Planned |
| Connected Apps (Post-Auth Account Linking) | 4 | 4.6 | 🔲 Planned |
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

### Feature 0.1: .NET 10 Migration — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-01-net-10-migration)

**Summary:** Migrated entire solution to .NET 10 with C# 14, including all library, test, and adapter projects. NuGet packages updated to 10.x.
**Key entry points:** all `.csproj` files

---

### Feature 0.2: Asymmetric Key Support (RS256/ES256) — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-02-asymmetric-key-support-rs256es256)

**Summary:** RS256/ES256 signing with ISigningKeyProvider, JWKS endpoint, key loading from PEM/cert. Includes HS256 for dev/testing.
**Key entry points:** `src/CoreIdent.Core/Services/ISigningKeyProvider.cs`, `RsaSigningKeyProvider.cs`, `EcdsaSigningKeyProvider.cs`

---

### Feature 0.3: Client Store & Model — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-03-client-store--model)

**Summary:** CoreIdentClient model, IClientStore with in-memory and EF Core implementations, PBKDF2 secret hashing.
**Key entry points:** `src/CoreIdent.Core/Stores/IClientStore.cs`, `src/CoreIdent.Core/Models/CoreIdentClient.cs`
---

### Feature 0.4: Scope & Core Models — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-04-scope--core-models)

**Summary:** CoreIdentScope, IScopeStore, CoreIdentRefreshToken, IRefreshTokenStore with in-memory and EF Core implementations, standard OIDC scopes pre-seeded.
**Key entry points:** `src/CoreIdent.Core/Stores/IScopeStore.cs`, `src/CoreIdent.Core/Stores/IRefreshTokenStore.cs`

---

### Feature 0.4.1: Core Registration & Routing — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-041-core-registration--routing-unambiguous-host-integration)

**Summary:** AddCoreIdent() and MapCoreIdentEndpoints() with CoreIdentOptions (issuer/audience validation) and CoreIdentRouteOptions (BasePath, root-relative OIDC paths).
**Key entry points:** `src/CoreIdent.Core/Extensions/ServiceCollectionExtensions.cs`

---

### Feature 0.4.2: OIDC Discovery Metadata — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-042-oidc-discovery-metadata-unambiguous-well-knownopenid-configuration)

**Summary:** `/.well-known/openid-configuration` with issuer, endpoints, scopes, grant types, and signing algorithms from configured providers.
**Key entry points:** `src/CoreIdent.Core/Endpoints/DiscoveryEndpointsExtensions.cs`

---

### Feature 0.4.3: User Model & Store Foundation — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-043-user-model--store-foundation-required-for-all-user-based-flows)

**Summary:** CoreIdentUser model, IUserStore with in-memory and EF Core implementations, IPasswordHasher using ASP.NET Core Identity hasher.
**Key entry points:** `src/CoreIdent.Core/Stores/IUserStore.cs`, `src/CoreIdent.Core/Models/CoreIdentUser.cs`

---

### Feature 0.5: Token Issuance Endpoint — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-05-token-issuance-endpoint)

**Summary:** POST /auth/token with client_credentials and refresh_token grants, JWT access tokens, refresh token rotation with theft detection, ICustomClaimsProvider hook.
**Key entry points:** `src/CoreIdent.Core/Endpoints/TokenEndpointExtensions.cs`

---

### Feature 0.6: Token Revocation Endpoint (RFC 7009) — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-06-token-revocation-endpoint-rfc-7009)

**Summary:** POST /auth/revoke (RFC 7009), ITokenRevocationStore with in-memory and EF Core implementations, revocation validation middleware, client ownership checks.
**Key entry points:** `src/CoreIdent.Core/Stores/ITokenRevocationStore.cs`, `src/CoreIdent.Core/Endpoints/TokenManagementEndpointsExtensions.cs`

---

### Feature 0.7: Token Introspection Endpoint (RFC 7662) — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-07-token-introspection-endpoint-rfc-7662)

**Summary:** POST /auth/introspect (RFC 7662), validates signature/expiry/revocation for both access and refresh tokens, requires client authentication.
**Key entry points:** `src/CoreIdent.Core/Endpoints/TokenManagementEndpointsExtensions.cs`

---

### Feature 0.8: Test Infrastructure Overhaul — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-08-test-infrastructure-overhaul)

**Summary:** CoreIdent.Testing package with CoreIdentTestFixture, WebApplicationFactory, fluent builders (User/Client/Scope), assertion extensions, and standard seeders.
**Key entry points:** `tests/CoreIdent.Testing/`

---

### Feature 0.9: OpenTelemetry Metrics Integration — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-09-opentelemetry-metrics-integration)

**Summary:** CoreIdent-specific metrics (token.issued, token.revoked, client.authenticated) plus .NET 10 built-in authentication/identity metrics integration.
**Key entry points:** `src/CoreIdent.Core/Observability/`

---

### Feature 0.10: CLI Tool (`dotnet coreident`) — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-010-cli-tool-dotnet-coreident)

**Summary:** dotnet coreident with init, keys generate, client add, and migrate commands. Packaged as a .NET global tool.
**Key entry points:** `src/CoreIdent.Cli/`

---

### Feature 0.11: Dev Container Configuration — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-011-dev-container-configuration)

**Summary:** .devcontainer setup with .NET 10 SDK, VS Code extensions, SQLite, and Codespaces support.
**Key entry points:** `.devcontainer/`

---

## Phase 1: Passwordless & Developer Experience

**Goal:** Make passwordless authentication trivially easy; establish the "5-minute auth" story.

**Estimated Duration:** 3-4 weeks

**Prerequisites:** Phase 0 complete

---

### Feature 1.1: Email Magic Link Authentication — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-11-email-magic-link-authentication)

**Summary:** IEmailSender, IPasswordlessTokenStore, POST /auth/passwordless/email/start and GET /verify endpoints, SMTP default sender, rate limiting, auto user creation.
**Key entry points:** `src/CoreIdent.Core/Endpoints/PasswordlessEmailEndpointsExtensions.cs`

---

### Feature 1.2: Passkey Integration (WebAuthn/FIDO2) — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-12-passkey-integration-webauthnfido2)

**Summary:** WebAuthn/FIDO2 via .NET 10 passkey support, IPasskeyService, registration and authentication ceremonies, credential storage with in-memory and EF Core stores.
**Key entry points:** `src/CoreIdent.Passkeys/`, `src/CoreIdent.Passkeys.AspNetIdentity/`

---

### Feature 1.3: SMS OTP (Pluggable Provider) — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-13-sms-otp-pluggable-provider)

**Summary:** ISmsProvider, ConsoleSmsProvider, POST /auth/passwordless/sms/start and /verify endpoints, 6-digit OTP with rate limiting.
**Key entry points:** `src/CoreIdent.Core/Endpoints/PasswordlessSmsEndpointsExtensions.cs`

---

### Feature 1.4: F# Compatibility — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-14-f-compatibility)

**Summary:** Verified F#-friendly APIs, Giraffe/Saturn sample, coreident-api-fsharp template.
**Key entry points:** `templates/coreident-api-fsharp/`

---

### Feature 1.5: `dotnet new` Templates — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-15-dotnet-new-templates)

**Summary:** coreident-api, coreident-server, coreident-api-fsharp templates with configurable parameters, packaged in CoreIdent.Templates.
**Key entry points:** `src/CoreIdent.Templates/`, `templates/`

---

### Feature 1.6: Aspire Integration — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-16-aspire-integration)

**Summary:** CoreIdent.Aspire package with health checks, OpenTelemetry metrics/tracing, service defaults, and AppHost integration for Aspire v13.
**Key entry points:** `src/CoreIdent.Aspire/`

---

### Feature 1.7: OAuth 2.0 Authorization Code Flow (PKCE Required) — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-17-oauth-20-authorization-code-flow-pkce-required)

**Summary:** Full auth code flow with PKCE enforcement, IAuthorizationCodeStore, ID token issuance for openid scope, cleanup hosted service.
**Key entry points:** `src/CoreIdent.Core/Endpoints/AuthorizationEndpointExtensions.cs`

---

### Feature 1.8: User Consent & Grants — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-18-user-consent--grants)

**Summary:** IUserGrantStore, consent UI endpoints (GET/POST /auth/consent), authorize endpoint consent integration, deny returns access_denied.
**Key entry points:** `src/CoreIdent.Core/Endpoints/ConsentEndpointExtensions.cs`

---

### Feature 1.9: Delegated User Store Adapter — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-19-delegated-user-store-adapter-integrate-existing-user-systems)

**Summary:** DelegatedUserStoreOptions with delegate-based IUserStore for existing user systems, startup validation for required delegates.
**Key entry points:** `src/CoreIdent.Adapters.DelegatedUserStore/`

---

### Feature 1.10: OIDC UserInfo Endpoint — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-110-oidc-userinfo-endpoint)

**Summary:** GET /auth/userinfo with scope-based claim filtering (profile, email, address, phone), bearer auth required.
**Key entry points:** `src/CoreIdent.Core/Endpoints/UserInfoEndpointExtensions.cs`

---

### Feature 1.11: Resource Owner Endpoints (Register/Login/Profile) — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-111-resource-owner-endpoints-registerloginprofile)

**Summary:** POST /auth/register, POST /auth/login, GET /auth/profile with content negotiation (JSON/HTML) and delegate customization via CoreIdentResourceOwnerOptions.
**Key entry points:** `src/CoreIdent.Core/Endpoints/ResourceOwnerEndpointsExtensions.cs`

---

### Feature 1.12: Password Grant (Resource Owner Password Credentials) — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-112-password-grant-resource-owner-password-credentials)

**Summary:** DEPRECATED -- Extracted to CoreIdent.Legacy.PasswordGrant package via IGrantTypeHandler. Logs deprecation warning per OAuth 2.1.
**Key entry points:** `src/CoreIdent.Legacy.PasswordGrant/`

### Feature 1.13: Follow-Up Cleanup — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-113-follow-up-cleanup)

**Summary:** TimeProvider consistency, route options refactoring, RFC 7807 error responses, structured logging, PII audit, OpenAPI docs (CoreIdent.OpenApi), version string updates to 1.0, code quality gates, 90% coverage gate. Includes sub-features 1.13.1-1.13.10.
**Key entry points:** multiple files across `src/CoreIdent.Core/`, `src/CoreIdent.OpenApi/`
**Remaining:** `[ ] (L1) Tag release in git as v1.0.0` (in 1.13.5)

---

### Feature 1.14: OAuth 2.1 Compliance Declaration

- [ ] (L2) Verify exact redirect URI matching in `AuthorizationEndpointExtensions.cs`
- [ ] (L1) Verify no implicit grant response types accepted
- [ ] (L1) Verify no hybrid flow response types accepted
- [ ] (L2) Add `/.well-known/oauth-authorization-server` metadata (Feature 1.21)
- [ ] (L1) Document OAuth 2.1 compliance status in Developer_Guide.md
- [ ] (L1) Add RFC 9725 to Technical_Plan.md references

---

### Feature 1.15: JWT Access Token Profile (RFC 9068)

*   **Component:** Access Token Claims Enhancement
    - [ ] (L2) Add `auth_time` claim (epoch timestamp from session auth properties or current time)
    - [ ] (L2) Add `acr` claim to access tokens when available
    - [ ] (L2) Add `typ: "at+jwt"` header to access tokens per RFC 9068
    - [ ] (L1) Update discovery document `claims_supported`
*   **Test Case:**
    - [ ] (L2) Tokens include `auth_time`, `acr`, correct `typ` header

---

### Feature 1.16: OIDC Authorize Endpoint Parameters

*   **Component:** Parameter Parsing
    - [ ] (L2) Parse `login_hint`, pass to Challenge() AuthenticationProperties
    - [ ] (L3) Parse `prompt` parameter:
        - `prompt=login` — Force re-authentication (clear session, re-challenge)
        - `prompt=consent` — Force consent screen even if grant exists
        - `prompt=none` — Return `login_required` or `consent_required` error if interaction needed
    - [ ] (L2) Parse `max_age` — compare against `auth_time` in session; re-auth if exceeded
    - [ ] (L2) Parse `acr_values` — store, flow into token claims via Feature 1.15
    - [ ] (L1) Parse `ui_locales` — make available to consent UI via HttpContext.Items
*   **Test Case:**
    - [ ] (L3) Tests for each parameter (especially `prompt=none` edge cases)

---

### Feature 1.17: Auth Session Management

*   **Component:** `CoreIdentSessionOptions`
    - [ ] (L2) Create `CoreIdentSessionOptions` in `src/CoreIdent.Core/Configuration/`
        - Cookie name, session duration, idle timeout, sliding expiration, remember-me
    - [ ] (L2) Create `AddCoreIdentAuthSession()` in `src/CoreIdent.Core/Extensions/AuthSessionServiceCollectionExtensions.cs`
        - Configures ASP.NET Core cookie authentication with CoreIdent defaults
        - Stores `auth_time` in AuthenticationProperties when session established
*   **Component:** Session Tracking
    - [ ] (L2) Create `ISessionStore` interface for tracking active sessions (lightweight)
    - [ ] (L2) Create `InMemorySessionStore` default implementation
*   **Component:** Authorize Endpoint Integration
    - [ ] (L3) Integrate with authorize endpoint: `prompt=login` clears session, `max_age` checks `auth_time`
*   **Test Case:**
    - [ ] (L2) Session cookie issued, auth_time flows to tokens, max_age enforced

---

### Feature 1.18: Account Recovery / Password Reset

*   **Component:** Recovery Endpoints
    - [ ] (L2) Create `POST /auth/account/recover` — accept email, send reset link via IEmailSender
        - Reuse IPasswordlessTokenStore with `TokenType = "password_reset"`
        - Rate limit per email (reuse existing passwordless rate limiting)
        - Always return success (don't leak email existence)
    - [ ] (L2) Create `POST /auth/account/reset-password` — accept token + new password
        - Validate token, hash new password via IPasswordHasher, update user via IUserStore
    - [ ] (L1) Create `GET /auth/account/reset-password` — minimal HTML form (replaceable)
*   **Component:** Configuration
    - [ ] (L2) Add routes to `CoreIdentRouteOptions`: `AccountRecoverPath`, `ResetPasswordPath`
    - [ ] (L2) Add HTML email template for password reset
*   **Test Case:**
    - [ ] (L3) Full recovery flow, expired token, rate limiting
*   **Documentation:**
    - [ ] (L1) Document in Developer_Guide.md

---

### Feature 1.19: Incremental Consent — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-119-incremental-consent)

**Summary:** Added MergeScopesAsync() to IUserGrantStore with default interface method. Consent endpoint merges scopes instead of overwriting.
**Key entry points:** `src/CoreIdent.Core/Stores/IUserGrantStore.cs`, `src/CoreIdent.Core/Endpoints/ConsentEndpointExtensions.cs`

---

### Feature 1.20: CORS Convenience

*   **Component:** CORS Integration
    - [ ] (L1) Create `AddCoreIdentCors()` extension in `src/CoreIdent.Core/Extensions/CorsServiceCollectionExtensions.cs`
        - Extract origins from registered `CoreIdentClient.RedirectUris`
        - Use ASP.NET Core built-in `AddCors()` / `UseCors()` under the hood
        - Allow manual origin additions via options
    - [ ] (L1) Create `UseCoreIdentCors()` middleware extension
*   **Test Case:**
    - [ ] (L2) CORS headers returned for registered client origins
*   **Documentation:**
    - [ ] (L1) Document in Developer_Guide.md

---

### Feature 1.21: RFC 8414 OAuth Authorization Server Metadata

*   **Component:** Discovery Endpoint
    - [ ] (L2) Add `/.well-known/oauth-authorization-server` endpoint
    - [ ] (L2) Share builder logic with existing openid-configuration endpoint
    - [ ] (L1) Register in `MapCoreIdentEndpoints()`
*   **Test Case:**
    - [ ] (L2) Endpoint returns valid metadata

---

### Feature 1.22: ROPC Extraction to Legacy Package — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-122-ropc-extraction-to-legacy-package)

**Summary:** Extracted password grant to CoreIdent.Legacy.PasswordGrant via IGrantTypeHandler extensibility. Discovery endpoint dynamically advertises registered grant types.
**Key entry points:** `src/CoreIdent.Core/Services/IGrantTypeHandler.cs`, `src/CoreIdent.Legacy.PasswordGrant/PasswordGrantHandler.cs`

---

### Feature 1.23: Blazor Unification (Rename)

- [ ] (L1) Rename all `CoreIdent.Client.BlazorServer` references to `CoreIdent.Client.BlazorWeb`
- [ ] (L1) Target unified Blazor Web App model (InteractiveServer, InteractiveWebAssembly, InteractiveAuto)
- Documentation-only change (project doesn't exist in code yet)

---

### Feature 1.24: AuthorizationCode Delivery Mode for Passwordless Email

*   **Component:** Token Delivery (Tier 3 of deferred item A)
    - [ ] (L2) Implement `TokenDeliveryMode.AuthorizationCode` in `PasswordlessEmailEndpointsExtensions.cs`
        - Verify endpoint issues a short-lived authorization code instead of tokens directly
        - Client exchanges the code at the token endpoint for access + refresh tokens
        - Follows the same pattern as OAuth 2.1 authorization code exchange
    - [ ] (L2) Add `IAuthorizationCodeStore` integration for code issuance and exchange
*   **Test Case:**
    - [ ] (L2) Integration test: verify returns code, exchange at token endpoint yields tokens

---

### Feature 1.25: Refresh Token Rotation Atomicity

*   **Component:** Atomic Token Exchange
    - [ ] (L2) Add compensating rollback to `IRefreshTokenStore` — if new token storage fails after old token consumption, restore the old token
    - [ ] (L3) Alternative: atomic exchange operation on `IRefreshTokenStore` that consumes old and stores new in a single transaction
    - [ ] (L2) Update `InMemoryRefreshTokenStore` with atomic exchange
    - [ ] (L2) Update `EfRefreshTokenStore` with transaction-wrapped exchange
*   **Test Case:**
    - [ ] (L2) Simulate storage failure during rotation — verify old token is not consumed

---

## Phase 1.5: Client Libraries

**Goal:** Enable any .NET application to authenticate against CoreIdent (or any OAuth/OIDC server) with minimal code.

**Estimated Duration:** 3-4 weeks

**Prerequisites:** Phase 1 complete (server-side passwordless)

---

### Feature 1.5.1: Core Client Library — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-151-core-client-library)

**Summary:** ICoreIdentClient with auth code + PKCE, token refresh, logout, discovery caching, ISecureTokenStorage, IBrowserLauncher, and PKCE/state CSRF protection.
**Key entry points:** `src/CoreIdent.Client/CoreIdentClient.cs`

---

### Feature 1.5.2: Browser Automation Testing Infrastructure — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-152-browser-automation-testing-infrastructure)

**Summary:** Playwright-based E2E testing infrastructure with 3-tier strategy (unit, headless integration, browser E2E). Includes Host/Http/Browser helpers, OAuth flow coverage, passkey E2E, and CI lane configuration.
**Key entry points:** `tests/CoreIdent.Testing/Browser/`

---

### Feature 1.5.3: MAUI Client — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-153-maui-client)

**Summary:** CoreIdent.Client.Maui with MauiSecureTokenStorage (SecureStorage) and MauiBrowserLauncher (WebAuthenticator) for Android/iOS/macCatalyst.
**Key entry points:** `src/CoreIdent.Client.Maui/`

---

### Feature 1.5.4: WPF/WinForms Client

*   **Component:** `CoreIdent.Client.Wpf` Package
    - [ ] (L1) Create project targeting `net10.0-windows`
    - [ ] (L3) Implement `DpapiTokenStorage` using Windows DPAPI
    - [ ] (L3) Implement `WebView2BrowserLauncher` (embedded browser)
    - [ ] (L2) Implement `SystemBrowserLauncher` (external browser with localhost callback)
*   **Test Case:**
    - [ ] (L2) DPAPI storage encrypts/decrypts correctly
    - [ ] (L3) WebView2 flow works
*   **Test Case (Integration):**
    - [ ] (L2) Tier 2 integration: SystemBrowserLauncher login against CoreIdent test host with localhost callback (1.5.2)
    - [ ] (L3) Tier 3 UI automation (Windows runner): WebView2 flow completes (1.5.2)
*   **Documentation:**
    - [ ] (L1) WPF/WinForms integration guide

---

### Feature 1.5.5: Console Client

*   **Component:** `CoreIdent.Client.Console` Package
    - [ ] (L1) Create project targeting `net10.0`
    - [ ] (L3) Implement `EncryptedFileTokenStorage`
    - [ ] (L2) Implement device code flow support (for headless scenarios)
*   **Test Case:**
    - [ ] (L2) Device code flow works
    - [ ] (L3) File storage is encrypted
*   **Test Case (Integration):**
    - [ ] (L2) Tier 2 integration: device code flow against CoreIdent test host (1.5.2)
    - [ ] (L2) Tier 2 integration: token refresh + logout against CoreIdent test host (1.5.2)
*   **Documentation:**
    - [ ] (L1) Console/CLI app integration guide

---

### Feature 1.5.6: Blazor WASM Client

*   **Component:** `CoreIdent.Client.Blazor` Package
    - [ ] (L1) Create project targeting `net10.0`
    - [ ] (L3) Implement `BrowserStorageTokenStorage` using `localStorage`/`sessionStorage`
    - [ ] (L3) Integrate with Blazor's `AuthenticationStateProvider`
*   **Test Case:**
    - [ ] (L2) Auth state propagates to Blazor components
    - [ ] (L2) Token refresh works in browser
*   **Test Case (Integration):**
    - [ ] (L2) Tier 2 integration: Blazor WASM login in Playwright against CoreIdent test host (1.5.2)
    - [ ] (L2) Tier 3 browser smoke: token refresh + logout in real browser (1.5.2)
*   **Documentation:**
    - [ ] (L1) Blazor WASM integration guide

---

## Phase 2: External Provider Integration

**Goal:** Seamless integration with third-party OAuth/OIDC providers.

**Estimated Duration:** 2-3 weeks

**Prerequisites:** Phase 1.5 complete

---

### Feature 2.1: Provider Abstraction Layer — COMPLETE
> Full detail: [`DEVPLAN_completed.md`](DEVPLAN_completed.md#feature-21-provider-abstraction-layer)

**Summary:** IExternalAuthProvider, ExternalAuthResult, ExternalUserProfile models, ExternalLogin entity with multi-provider account linking support.
**Key entry points:** `src/CoreIdent.Providers.Abstractions/`

---

### Feature 2.2: Google Provider

*   **Component:** `CoreIdent.Providers.Google` Package
    - [ ] (L1) Create new project
    - [ ] (L3) Implement `IExternalAuthProvider` for Google
    - [ ] (L3) Handle OAuth flow with Google
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
    - [ ] (L3) Implement for Microsoft/Entra ID
    - [ ] (L3) Support both personal and work/school accounts
*   **Documentation:**
    - [ ] (L1) Add Microsoft/Entra setup guide

---

### Feature 2.4: GitHub Provider

*   **Component:** `CoreIdent.Providers.GitHub` Package
    - [ ] (L1) Create new project
    - [ ] (L3) Implement for GitHub OAuth
*   **Documentation:**
    - [ ] (L1) Add GitHub setup guide

---

### Feature 2.5: Apple Provider

*   **Component:** `CoreIdent.Providers.Apple` Package
    - [ ] (L1) Create `src/CoreIdent.Providers.Apple/CoreIdent.Providers.Apple.csproj`
    - [ ] (L3) Implement `IExternalAuthProvider` for Apple Sign-In
        - Apple uses `id_token` (JWT) instead of userinfo endpoint
        - Handle Apple's "private relay" email addresses
        - Handle Apple's `user` JSON body (only sent on first auth)
    - [ ] (L2) Create `AppleProviderOptions` (Services ID, Key ID, Team ID, Private Key path)
    - [ ] (L1) Add `AddAppleProvider()` extension method
*   **Test Case:**
    - [ ] (L2) Configuration validation, ID token parsing
*   **Documentation:**
    - [ ] (L1) Apple Developer Console setup guide

---

### Feature 2.6: JS/TS Client Compatibility Documentation

- [ ] (L1) Add section to Developer_Guide.md: "Using CoreIdent with JavaScript/TypeScript clients"
- [ ] (L2) Provide oidc-client-ts configuration example
- [ ] (L2) Provide vanilla JS authorization code + PKCE example
- [ ] (L1) Document CORS requirements (reference Feature 1.20)
- [ ] (L1) Document token refresh patterns from browser
- Documentation-only (no npm package)

---

### Feature 2.7: Rate Limiting (`IRateLimiter`)

> Currently listed in Project_Overview.md extension points but does NOT exist in code.

*   **Component:** Rate Limiter Interface
    - [ ] (L2) Create `src/CoreIdent.Core/Services/IRateLimiter.cs` interface
    - [ ] (L2) Create default implementation using ASP.NET Core `Microsoft.AspNetCore.RateLimiting`
    - [ ] (L2) Create `AddCoreIdentRateLimiting()` extension method
*   **Component:** Integration
    - [ ] (L2) Integrate with: token endpoint, login endpoint, passwordless endpoints, registration endpoint
    - [ ] (L2) Configuration: per-client, per-IP, per-endpoint rate limit policies
    - [ ] (L2) Migrate existing passwordless per-recipient throttling to use `IRateLimiter`
*   **Test Case:**
    - [ ] (L2) Rate limiting blocks excessive requests across endpoint types

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
    - [ ] (L3) Support overlap period for old keys
*   **Component:** Multiple Keys in JWKS
    - [ ] (L3) Extend JWKS endpoint to return all active keys
    - [ ] (L1) Include key expiry metadata
*   **Test Case:**
    - [ ] (L3) Old tokens remain valid during overlap period
    - [ ] (L3) New tokens use new key
    - [ ] (L3) JWKS contains both keys during rotation

---

### Feature 3.2: Session Management & OIDC Logout (incl. Back-Channel)

*   **Component:** Session Tracking
    - [ ] (L1) Create `ISessionStore` interface
    - [ ] (L2) Track active sessions per user
*   **Component:** OIDC Logout Endpoint
    - [ ] (L3) Implement `GET /auth/logout` (end_session_endpoint)
    - [ ] (L3) Support `id_token_hint`, `post_logout_redirect_uri`, `state`
    - [ ] (L3) Revoke associated tokens
*   **Component:** Back-Channel Logout
    - [ ] (L3) Add `backchannel_logout_uri` and `backchannel_logout_session_required` to `CoreIdentClient`
    - [ ] (L3) Generate logout token (JWT with `events` claim: `http://schemas.openid.net/event/backchannel-logout`)
    - [ ] (L3) Include `sid` (session ID) claim when session-required
    - [ ] (L3) HTTP POST delivery to registered URIs with `logout_token` form parameter
    - [ ] (L2) Retry logic for failed deliveries
*   **Component:** Front-Channel Logout
    - [ ] (L2) Add `frontchannel_logout_uri` and `frontchannel_logout_session_required` to `CoreIdentClient`
    - [ ] (L2) End session endpoint renders iframes for each registered front-channel URI
*   **Component:** Discovery Metadata
    - [ ] (L2) Advertise `end_session_endpoint`, `backchannel_logout_supported`, `backchannel_logout_session_supported`, `frontchannel_logout_supported`, `frontchannel_logout_session_supported`
*   **Test Case:**
    - [ ] (L3) Logout invalidates session
    - [ ] (L1) Logout redirects correctly
    - [ ] (L3) Logout triggers backchannel notification, front-channel iframes rendered, tokens revoked

---

### Feature 3.3: Dynamic Client Registration (RFC 7591)

*   **Component:** Registration Endpoint
    - [ ] (L3) Implement `POST /auth/register` for clients
    - [ ] (L3) Support initial access tokens for authorization
    - [ ] (L1) Return client credentials
*   **Test Case:**
    - [ ] (L3) Client can register and receive credentials
    - [ ] (L1) Invalid registration is rejected

---

### Feature 3.4: Device Authorization Flow (RFC 8628)

*   **Component:** Device Authorization Endpoint
    - [ ] (L3) Implement `POST /auth/device_authorization`
    - [ ] (L1) Return device_code, user_code, verification_uri
*   **Component:** Device Token Endpoint
    - [ ] (L3) Extend token endpoint for `urn:ietf:params:oauth:grant-type:device_code`
*   **Test Case:**
    - [ ] (L3) Device flow completes successfully
    - [ ] (L3) Polling returns appropriate responses

---

### Feature 3.5: Pushed Authorization Requests (RFC 9126)

*   **Component:** PAR Endpoint
    - [ ] (L3) Implement `POST /auth/par`
    - [ ] (L1) Return request_uri
*   **Component:** Authorize Endpoint Extension
    - [ ] (L3) Add `request_uri` parameter support to authorize endpoint
*   **Test Case:**
    - [ ] (L3) PAR flow works end-to-end

---

### Feature 3.6: DPoP - Demonstrating Proof of Possession (RFC 9449)

*   **Component:** DPoP Proof Validation
    - [ ] (L3) Implement DPoP proof parsing and validation
    - [ ] (L3) Validate `htm`, `htu`, `iat`, `jti`, signature
*   **Component:** Token Endpoint DPoP Support
    - [ ] (L3) Add DPoP header acceptance to token endpoint
    - [ ] (L3) Bind tokens to DPoP key
*   **Component:** Token Validation DPoP Support
    - [ ] (L3) Add DPoP proof validation to protected endpoints
*   **Component:** Client Library DPoP Support
    - [ ] (L3) Implement DPoP proof JWT creation (ES256) with `typ=dpop+jwt` and public JWK header
    - [ ] (L3) Send `DPoP` header on token endpoint requests when enabled
    - [ ] (L3) Send `Authorization: DPoP <token>` + `DPoP` proof (with `ath`) for UserInfo when enabled
    - [ ] (L3) Handle `DPoP-Nonce` replay/nonce requirements (header + `use_dpop_nonce` errors)
    - [ ] (L3) Ensure DPoP key material lifecycle is handled safely (no leaks)
*   **Test Case:**
    - [ ] (L3) DPoP-bound token requires valid proof
    - [ ] (L3) Token without DPoP is rejected if DPoP was used at issuance
    - [ ] (L3) Client sends DPoP headers when `UseDPoP=true`

---

### Feature 3.7: Rich Authorization Requests (RFC 9396)

*   **Component:** Authorization Details Support
    - [ ] (L3) Parse `authorization_details` parameter
    - [ ] (L3) Store with authorization code
    - [ ] (L3) Include in token claims
*   **Test Case:**
    - [ ] (L3) Authorization details flow through to token

---

### Feature 3.8: Token Exchange (RFC 8693)

*   **Component:** Token Exchange Endpoint
    - [ ] (L3) Implement `POST /auth/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
    - [ ] (L3) Support `subject_token` and `actor_token`
    - [ ] (L3) Support token type indicators
*   **Component:** Exchange Policies
    - [ ] (L1) Define `ITokenExchangePolicy` interface
    - [ ] (L3) Implement delegation policy
    - [ ] (L3) Implement impersonation policy
*   **Test Case:**
    - [ ] (L3) Delegation exchange produces valid token
    - [ ] (L3) Impersonation exchange includes `act` claim
    - [ ] (L3) Unauthorized exchanges are rejected
*   **Documentation:**
    - [ ] (L1) Token exchange guide with use cases

---

### Feature 3.9: JWT-Secured Authorization Request (JAR)

*   **Component:** Request Object Support
    - [ ] (L3) Parse `request` parameter (JWT)
    - [ ] (L3) Validate signature against registered client keys
    - [ ] (L3) Support `request_uri` for remote request objects
*   **Component:** Encryption Support (Optional)
    - [ ] (L3) Decrypt JWE request objects
*   **Test Case:**
    - [ ] (L3) Signed request object is validated
    - [ ] (L3) Invalid signature is rejected
*   **Documentation:**
    - [ ] (L1) JAR implementation guide

---

### Feature 3.10: Webhook System & SET/RISC

*   **Component:** `IWebhookService` Interface
    - [ ] (L1) Define webhook event types
    - [ ] (L3) Define delivery mechanism
*   **Component:** Webhook Configuration
    - [ ] (L1) Per-event endpoint configuration
    - [ ] (L3) Secret for signature verification
    - [ ] (L2) Retry policy configuration
*   **Component:** Event Types
    - [ ] (L1) `user.created`, `user.updated`, `user.deleted`
    - [ ] (L1) `user.login.success`, `user.login.failed`
    - [ ] (L1) `token.issued`, `token.revoked`
    - [ ] (L1) `consent.granted`, `consent.revoked`
    - [ ] (L1) `client.created`, `client.updated`
*   **Component:** Delivery
    - [ ] (L2) HTTP POST with JSON payload
    - [ ] (L3) HMAC signature header
    - [ ] (L3) Exponential backoff retry
*   **Component:** Security Event Tokens (SET/RISC)
    - [ ] (L2) Security Event Token format (JWT-based, per RFC 8417)
    - [ ] (L2) RISC event types: credential-compromise, account-credential-change-required, account-disabled, sessions-revoked
    - [ ] (L2) SET delivery: push (HTTP POST) and poll (GET endpoint) modes
    - [ ] (L1) Recommend SET over simple webhooks for standards compliance in documentation
*   **Test Case:**
    - [ ] (L3) Webhooks fire on events
    - [ ] (L3) Retry logic works correctly
    - [ ] (L3) Signature verification works
*   **Test Case (SET):**
    - [ ] (L2) SET tokens are valid JWTs with correct `events` claim structure
*   **Documentation:**
    - [ ] (L1) Webhook integration guide

---

### Feature 3.11: OIDC Conformance Testing

*   **Component:** Conformance Test Integration
    - [ ] (L3) Set up OIDC conformance test suite
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
    - [ ] (L3) Add caching strategy and guidance (fail-closed by default; configurable TTL; protect introspection endpoint)
*   **Component:** Optional Opaque/Reference Access Tokens
    - [ ] (L3) Add configuration to issue opaque/reference access tokens (instead of JWT) for APIs that require immediate revocation
    - [ ] (L3) Ensure introspection becomes the validation path for opaque tokens
*   **Test Case (Integration):**
    - [ ] (L3) Revoked access token becomes inactive via introspection across services
    - [ ] (L3) Cache behaves correctly (revocation latency bounded by cache TTL)
*   **Documentation:**
    - [ ] (L2) Document validation modes: offline JWT vs introspection vs opaque/reference tokens
    - [ ] (L2) Document when to choose which mode (embedded vs distributed)

---

### Feature 3.13: MCP-Compatible Authorization Server

> **Goal:** Extend the OAuth 2.1 server to support the Model Context Protocol (MCP) authorization specification, enabling fine-grained authorization for AI agent workflows. MCP is the emerging standard (originated at Anthropic, now broadly adopted) for how AI agents connect to external tools and data sources. This is a protocol-level extension of the existing OAuth server — distinct from the removed "AI Framework SDK Integrations" and "CIBA for AI Actions" items, which concerned embedding AI SDKs or niche backchannel protocols.

*   **Component:** MCP Authorization Metadata Discovery
    - [ ] (L2) Extend `/.well-known/oauth-authorization-server` metadata for MCP compatibility
    - [ ] (L1) Advertise supported MCP authorization capabilities
*   **Component:** Third-Party Client Registration for MCP
    - [ ] (L3) Support dynamic registration of MCP clients (tool servers)
    - [ ] (L2) Define default restricted scopes for MCP tool access
*   **Component:** Consent & Delegation for Agent Access
    - [ ] (L3) Scoped consent UI for agent/tool authorization ("App X wants Agent Y to access Z on your behalf")
    - [ ] (L3) Token scoping to limit agent capabilities per-session
    - [ ] (L2) Support for audience-restricted tokens targeting specific MCP tool servers
*   **Component:** Token Lifecycle for Agent Workflows
    - [ ] (L2) Short-lived access tokens with constrained scopes for agent sessions
    - [ ] (L3) Revocation hooks for agent session termination
*   **Test Case:**
    - [ ] (L3) MCP client can obtain scoped token via authorization code flow
    - [ ] (L3) Agent token is rejected when scope is insufficient for requested tool
    - [ ] (L2) MCP authorization metadata is correctly advertised
*   **Documentation:**
    - [ ] (L1) MCP integration guide with sample agent workflow
    - [ ] (L2) Security considerations for agent authorization

---

### Feature 3.14: mTLS Client Authentication (RFC 8705)

*   **Component:** mTLS Authentication
    - [ ] (L3) Parse client certificate from TLS connection (`HttpContext.Connection.ClientCertificate`)
    - [ ] (L3) `tls_client_auth` token endpoint authentication method
    - [ ] (L3) `self_signed_tls_client_auth` support
*   **Component:** Certificate-Bound Tokens
    - [ ] (L3) Add `cnf` claim with `x5t#S256` thumbprint to access tokens
*   **Component:** Discovery
    - [ ] (L2) Update discovery: `tls_client_certificate_bound_access_tokens`, `token_endpoint_auth_methods_supported`
*   **Test Case:**
    - [ ] (L3) mTLS-authenticated client can obtain tokens, certificate-bound tokens validated

---

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
    - [ ] (L3) Email verification flow
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
    - [ ] (L3) Change email (with verification)
    - [ ] (L3) Change password
    - [ ] (L3) Enable/disable MFA
*   **Component:** Session Management
    - [ ] (L2) List active sessions (device, location, time)
    - [ ] (L3) Revoke individual sessions
    - [ ] (L3) "Sign out everywhere" option
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
    - [ ] (L3) Session revocation works
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
    - [ ] (L3) Admin role/scope requirements
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

### Feature 4.5: Domain Verification

*   **Component:** Domain Claim & Verification
    - [ ] (L2) `IDomainVerificationService` interface
    - [ ] (L3) DNS TXT record verification method
    - [ ] (L2) HTTP well-known file verification method
    - [ ] (L2) Store verified domains per tenant/organization
*   **Component:** Automatic Organization Association
    - [ ] (L3) Auto-associate users with matching email domains on login/registration
    - [ ] (L2) Configurable policy: auto-join vs require admin approval
*   **Component:** SSO Enforcement
    - [ ] (L3) Require SSO for verified domain users (block password login)
    - [ ] (L2) Grace period configuration for SSO migration
*   **Test Case:**
    - [ ] (L3) DNS verification succeeds for correct TXT record
    - [ ] (L3) Users with verified domain are associated to organization
    - [ ] (L3) SSO enforcement blocks password login for domain users
*   **Documentation:**
    - [ ] (L1) Domain verification setup guide for B2B SaaS

---

### Feature 4.6: Connected Apps (Post-Auth Account Linking)

*   **Component:** Connected App Registration
    - [ ] (L1) `IConnectedAppProvider` interface
    - [ ] (L2) Store connected app definitions (name, OAuth config, required scopes)
    - [ ] (L1) Admin API for managing connected app definitions (coordinate with Feature 4.3)
*   **Component:** User-Initiated OAuth Linking
    - [ ] (L3) Initiate OAuth 2.0 authorization code flow to third-party service
    - [ ] (L3) Store resulting tokens securely per user per connected app
    - [ ] (L2) Token refresh lifecycle management for connected apps
*   **Component:** User Portal Integration
    - [ ] (L2) "Connected Accounts" section in self-service portal (coordinate with Feature 4.2)
    - [ ] (L2) Connect / disconnect actions
    - [ ] (L1) Display connection status and last-used time
*   **Test Case:**
    - [ ] (L3) User can link external account via OAuth flow
    - [ ] (L3) Disconnecting removes stored tokens
    - [ ] (L2) Token refresh keeps connection alive
*   **Documentation:**
    - [ ] (L1) Connected Apps integration guide

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

> **Strategy:** CoreIdent does not aim to build a full authorization engine (Zanzibar/ReBAC). Instead, it provides clean integration points so teams can plug in purpose-built systems like OpenFGA, Cerbos, Ory Keto, SpiceDB, or Warrant. CoreIdent's role is to enrich tokens with the identity and context that authorization engines need, and to provide middleware that bridges authorization decisions into .NET request pipelines.

*   **Component:** Authorization Decision Interface
    - [ ] (L2) `IAuthorizationDecider` interface — check(subject, action, resource) → permit/deny
    - [ ] (L1) Default pass-through implementation
    - [ ] (L2) Middleware to enforce decisions on protected endpoints
*   **Component:** Token Claims Enrichment for Authorization
    - [ ] (L2) Configurable claims that external FGA systems typically consume (roles, groups, org membership, tenant context)
    - [ ] (L1) `IAuthorizationContextProvider` — supply additional context at token issuance
*   **Component:** Reference Integrations
    - [ ] (L2) OpenFGA adapter example
    - [ ] (L1) Documentation: mapping CoreIdent identity model to common FGA relationship schemas
*   **Component:** RBAC Convenience Layer
    - [ ] (L2) Built-in role/permission model for teams that don't need full FGA
    - [ ] (L2) Role-to-scope mapping
    - [ ] (L1) Admin API endpoints for role management (coordinate with Feature 4.3)

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

> **Strategy:** CoreIdent provides extensible risk-assessment interfaces and reference implementations. For teams needing a turnkey fraud/abuse engine with proprietary signal intelligence, integrate a dedicated service (e.g., Castle, Arkose Labs) via the `IRiskScorer` / `IRequestClassifier` hooks. The goal is composability, not competing with dedicated fraud platforms.

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
*   **Component:** Credential Stuffing Protection
    - [ ] (L2) Brute-force rate limiting per account
    - [ ] (L3) Leaked credential detection integration (coordinate with Feature 5.7)
    - [ ] (L2) Progressive challenge escalation (CAPTCHA → MFA → lockout)
*   **Component:** Bot / Abuse Detection Hooks
    - [ ] (L1) `IRequestClassifier` interface (human / bot / suspicious)
    - [ ] (L2) Pluggable classification provider model
    - [ ] (L1) Default: header/behavior heuristic classifier
*   **Component:** Dormant Account Monitoring
    - [ ] (L1) Track last-active timestamp per user
    - [ ] (L2) Configurable dormancy threshold and policy (alert, disable, require re-verification)
*   **Component:** Free-Tier / Signup Abuse Detection
    - [ ] (L2) Email domain and alias pattern analysis hooks
    - [ ] (L1) Configurable signup rate limits per IP/fingerprint
*   **Component:** Admin Alerting
    - [ ] (L1) `IRiskAlertSink` interface for risk event notifications
    - [ ] (L2) Default implementations: log, webhook, email
*   **Component:** Custom Blocking Rules
    - [ ] (L2) IP range / country / device-based block/challenge rules
    - [ ] (L1) Admin API for managing rules (coordinate with Feature 4.3)
*   **Test Case:**
    - [ ] (L2) Unknown device triggers step-up
    - [ ] (L3) Impossible travel is detected
*   **Documentation:**
    - [ ] (L1) Risk-based auth configuration guide

---

### Feature 5.7: Credential Breach Detection

*   **Component:** HaveIBeenPwned Integration
    - [ ] (L3) k-Anonymity API integration
    - [ ] (L1) Check on registration
    - [ ] (L1) Check on password change
    - [ ] (L2) Optional check on login
*   **Component:** Policy Configuration
    - [ ] (L1) Block compromised passwords
    - [ ] (L1) Warn but allow
    - [ ] (L3) Force password change
*   **Component:** Alerts
    - [ ] (L3) Notify user of compromised credential
    - [ ] (L1) Admin notification option
*   **Test Case:**
    - [ ] (L3) Known compromised password is detected
    - [ ] (L3) Policy enforcement works
*   **Documentation:**
    - [ ] (L1) Breach detection setup guide

---

### Feature 5.8: API Gateway Integration

*   **Component:** YARP Integration Examples
    - [ ] (L3) Token validation middleware
    - [ ] (L3) Token transformation
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

## Feature coverage notes

The following items are tracked here for completeness and cross-referencing:

- [x] (L2) JWKS Endpoint (now with asymmetric keys) — *Covered in Feature 0.2*
- [x] (L2) JWT Access Tokens — *Covered in Feature 0.2 (JwtTokenService)*
- [x] (L2) Refresh Tokens — *Covered in Features 0.4-0.5*
- [x] (L3) Refresh Token Rotation & Family Tracking — *Covered in Feature 0.5*
- [x] (L3) Token Theft Detection — *Covered in Feature 0.5*
- [x] (L2) Client Credentials Flow — *Covered in Feature 0.5*
- [x] (L3) OAuth2 Authorization Code Flow with PKCE — *Covered in Feature 1.7*
- [x] (L2) ID Token Issuance — *Covered in Feature 1.7 (OIDC ID token)*
- [x] (L2) OIDC Discovery Endpoint — *Covered in Feature 0.4.2*
- [x] (L2) OIDC UserInfo Endpoint — *Covered in Feature 1.10*
- [x] (L2) User Consent Mechanism — *Covered in Feature 1.8*
- [x] (L2) EF Core Storage Provider — *Covered in Features 0.3-0.4 (EfClientStore, EfScopeStore, etc.)*
- [x] (L2) Delegated User Store Adapter — *Covered in Feature 1.9*
- [x] (L2) User Registration Endpoint — *Covered in Feature 1.11*
- [x] (L2) User Login Endpoint — *Covered in Feature 1.11*
- [x] (L2) User Profile Endpoint — *Covered in Feature 1.11*
- [x] (L2) Password Grant (ROPC) — *Covered in Feature 1.12*
- [x] (L1) Custom Claims Provider — *Covered in Feature 0.5*

> **Note:** Many items are now explicitly covered in Phase 0 features and referenced here for clarity.

---

## Removed from Roadmap

| Feature | Reason |
|---------|--------|
| Web3 Wallet Login | Niche adoption |
| LNURL-auth | Very niche |
| AI Framework SDK Integrations | Premature (note: MCP-compatible authorization in Feature 3.13 is a distinct, protocol-level OAuth 2.1 extension — not an AI SDK integration) |
| CIBA for AI Actions | Specialized (note: MCP Auth in Feature 3.13 addresses AI agent authorization via standard OAuth flows, not the niche CIBA backchannel protocol) |
| Token Vault / Secrets Management | Out of scope |
| Feature Flags / Rollout Control | Out of scope; not an identity concern. Use dedicated tools (LaunchDarkly, Unleash, Flagsmith, etc.) |
| **Resource Owner Password Credentials (ROPC)** | Deprecated in OAuth 2.1 (RFC 9725). Extracted to `CoreIdent.Legacy.PasswordGrant` for migration support. |
