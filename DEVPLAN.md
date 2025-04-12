# CoreIdent: Detailed Development Plan (DEVPLAN.md)

This document provides a detailed breakdown of tasks, components, features, test cases, and technical guidance for each phase of the CoreIdent project. It synthesizes information from `Project_Overview.md`, `Technical_Plan.md`, `Development_Roadmap.md`, and related documents.

## Phase 1: MVP Core (Foundation)

**Goal:** Establish the fundamental authentication flow and core package structure. Provide a runnable, testable alpha.

**Estimated Duration:** 4-6 weeks / 35-50 hours

---

### Feature: Core Package Structure & Setup

*   **Component:** `CoreIdent.Core` NuGet Package Project
    - [x] Create initial `.csproj` file targeting .NET 9/10+.
        *   *Guidance:* Define basic metadata (PackageId, Version, Authors, Description, License).
    - [x] Define core namespace (e.g., `CoreIdent`).
*   **Component:** Configuration (`CoreIdentOptions`)
    - [x] Define `CoreIdentOptions` class.
        *   *Guidance:* Include properties for
	        * `Issuer`, 
	        * `Audience`, 
	        * `SigningKeySecret` (for symmetric initially), 
	        * `AccessTokenLifetime`, 
	        * `RefreshTokenLifetime`. Use `TimeSpan` for lifetimes.
    - [x] Implement validation for `CoreIdentOptions` 
          (e.g., using `IValidateOptions<CoreIdentOptions>`).
        *   *Guidance:* Ensure required fields like Issuer, Audience, SigningKeySecret are provided. Check lifetime values.
*   **Component:** Dependency Injection Setup
    - [x] Create `IServiceCollection` extension method: 
          `AddCoreIdent(Action<CoreIdentOptions> configureOptions)`.
        *   *Guidance:* 
            * Register 
                * `CoreIdentOptions`, 
                * core services (`ITokenService`, `IUserStore`, `IPasswordHasher`), 
                * and necessary ASP.NET Core services. 
            * Validate options during setup.
    - [x] Create `IEndpointRouteBuilder` extension method for endpoint mapping (e.g., `MapCoreIdentEndpoints()`).
        *   *Guidance:* Map the core Minimal API endpoints defined below (`/register`, `/login`, `/token/refresh`).
*   **Test Case:**
    - [x] Verify `AddCoreIdent` successfully registers required services in the DI container.
    - [x] Verify `AddCoreIdent` throws an exception if essential configuration is missing.
    - [x] Verify `MapCoreIdentEndpoints` correctly maps expected HTTP routes.
        - [*Note:* Requires integration testing setup (e.g., WebApplicationFactory) with an ASP.NET Core host.]
    - [*Note:* Test suite refactored to use Shouldly; build errors and warnings resolved.]

---

### Feature: User Registration

*   **Component:** Registration Endpoint (`POST /register`)
    - [x] Implement Minimal API endpoint for user registration.
        *   *Guidance:* Accepts DTO (e.g., `RegisterRequest { Email, Password }`). Validate input (e.g., email format, password complexity minimums).
    - [x] Integrate with `IPasswordHasher` to hash the password.
    - [x] Integrate with `IUserStore` to create the user.
        *   *Guidance:* Handle potential conflicts (e.g., username/email already exists). Return appropriate HTTP status codes (e.g., 201 Created, 409 Conflict).
*   **Component:** Password Hashing (`IPasswordHasher`, `DefaultPasswordHasher`)
    - [x] Define `IPasswordHasher` interface 
          (`HashPassword`, `VerifyHashedPassword`).
    - [x] Implement `DefaultPasswordHasher` 
          using `Microsoft.AspNetCore.Identity.PasswordHasher<TUser>`.
        *   *Guidance:* Configure appropriate compatibility mode and iteration count. Register this as the default implementation.
*   **Component:** User Storage (`IUserStore`, `InMemoryUserStore`)
    - [x] Define `IUserStore` interface 
          (methods: `CreateUserAsync`, `FindUserByIdAsync`, `FindUserByUsernameAsync`, `UpdateUserAsync`, `DeleteUserAsync`). 
          Define `StoreResult` enum/class (Success, Failure, Conflict).
    - [x] Implement `InMemoryUserStore`.
        *   *Guidance:* Use thread-safe collections (e.g., `ConcurrentDictionary`) to store users in memory. Implement username normalization (e.g., `ToUpperInvariant`). Register this as the default store for Phase 1.
*   **Test Case (Unit):**
    - [x] `DefaultPasswordHasher` correctly hashes and verifies passwords.
    - [x] `InMemoryUserStore` correctly creates and retrieves users. 
          Handles non-existent users. Prevents duplicate usernames.
*   **Test Case (Integration):**
    - [x] `POST /register` with valid data creates a user and returns 201.
    - [x] `POST /register` with an existing email returns 409.
    - [x] `POST /register` with invalid input (e.g., weak password, invalid email) returns 400.

---

### Feature: User Login & Token Issuance

*   **Component:** Login Endpoint (`POST /login`)
    - [x] Implement Minimal API endpoint for user login.
        *   *Guidance:* Accepts DTO (e.g., `LoginRequest { Email, Password }`). Validate input.
    - [x] Integrate with `IUserStore` to find the user by email/username.
    - [x] Integrate with `IPasswordHasher` to verify the password.
        *   *Guidance:* Return 401 Unauthorized if user not found or password incorrect.
    - [x] If login successful, integrate with `ITokenService` to generate tokens.
    - [x] Return tokens (Access, potentially Refresh) in the response (e.g., `LoginResponse { AccessToken, RefreshToken, ExpiresIn }`).
*   **Component:** Token Service (`ITokenService`, `JwtTokenService`)
    - [x] Define `ITokenService` interface 
          (`GenerateAccessTokenAsync`, `GenerateRefreshTokenAsync` 
            - simple string initially).
    - [x] Implement `JwtTokenService`.
        *   *Guidance:* Use `System.IdentityModel.Tokens.Jwt`. 
            Read configuration (`Issuer`, `Audience`, `SigningKeySecret`, `AccessTokenLifetime`) from `CoreIdentOptions`.
        *   *Guidance:* Include standard claims 
          (`sub`, `iss`, `aud`, `exp`, `iat`, `jti`). 
            Add user-specific claims (e.g., `name`, `email`) retrieved from `IUserStore`.
        *   *Guidance:* Implement basic refresh token generation (e.g., secure random string).
    - [x] Register `JwtTokenService` as the default `ITokenService`.
*   **Test Case (Unit):**
    - [x] `JwtTokenService` generates valid JWTs with correct claims, 
          issuer, audience, expiry, and signature (using configured key).
*   **Test Case (Integration):**
    - [x] `POST /login` with valid credentials returns 200 and expected token structure.
    - [x] `POST /login` with invalid username returns 401.
    - [x] `POST /login` with valid username but invalid password returns 401.
    - [x] Access token can be validated using standard JWT middleware (`AddJwtBearer`).

---

### Feature: Basic Refresh Token Flow (Optional in MVP)

*   **Component:** Refresh Token Endpoint (`POST /token/refresh`)
    - [x] Implement Minimal API endpoint for refreshing tokens.
        *   *Guidance:* Accepts DTO (e.g., `RefreshTokenRequest { RefreshToken }`).
    - [x] Validate the incoming refresh token (initially: check if it exists in a simple in-memory store/list associated with the user).
        *   *Guidance:* This will be significantly improved in Phase 2 with `IRefreshTokenStore`.
    - [x] If valid, invalidate the old refresh token (remove from store).
    - [x] Generate new Access and Refresh tokens using `ITokenService`.
    - [x] Store the new refresh token.
    - [x] Return new tokens in the response.
*   **Test Case (Integration):**
    - [x] `POST /token/refresh` with a valid refresh token 
          returns new access and refresh tokens.
    - [x] `POST /token/refresh` with an invalid or expired refresh token 
          returns 401/400.
    - [x] Attempting to use a refresh token twice fails.

---

### Feature: Basic Documentation & Testing

*   **Component:** README.md
    - [x] Create initial `README.md` with project vision, 
          basic setup instructions (`AddCoreIdent`, minimal configuration), 
          and how to run.
*   **Component:** Unit Tests
    - [x] Set up unit test project (e.g., xUnit).
    - [x] Write unit tests covering core services (`JwtTokenService`, `DefaultPasswordHasher`, `InMemoryUserStore`). 
          Use mocking (e.g., Moq) for dependencies.
*   **Component:** Integration Tests
    - [x] Set up integration test project using `Microsoft.AspNetCore.Mvc.Testing`.
    - [x] Write integration tests covering API endpoints 
          (`/register`, `/login`, `/token/refresh`).

---

## Phase 2: Storage & Core Extensibility

**Goal:** Enable persistent user storage, refine core interfaces for extensibility, implement robust refresh tokens, and define client/scope storage.

**Estimated Duration:** 3-5 weeks / 30-45 hours

---

### Feature: Refined Core Interfaces

*   **Component:** `IUserStore` Interface
    - [ ] Review and refine `IUserStore`.
        *   *Guidance:* 
            * Add methods needed for 
              * password management (`SetPasswordHashAsync`, `GetPasswordHashAsync`), 
              * claim management (`GetClaimsAsync`, `AddClaimsAsync`, `ReplaceClaimAsync`, `RemoveClaimsAsync`), 
              * potentially lockout (`GetLockoutEndDateAsync`, `IncrementAccessFailedCountAsync`, `ResetAccessFailedCountAsync`). 
            * Ensure methods are suitable for both integrated (EF Core) and delegated implementations. 
            * Update `CoreIdentUser` model if needed (e.g., add `Claims` collection, lockout properties).
*   **Component:** `IRefreshTokenStore` Interface
    - [ ] Define `IRefreshTokenStore` interface.
        *   *Guidance:* 
            * Methods: `StoreRefreshTokenAsync(CoreIdentRefreshToken token)`, `GetRefreshTokenAsync(string tokenHandle)`, `RemoveRefreshTokenAsync(string tokenHandle)`. 
            * Define `CoreIdentRefreshToken` model 
              (e.g., Handle (hashed), SubjectId, ClientId, CreationTime, ExpirationTime, ConsumedTime?).
*   **Component:** `IClientStore` Interface
    - [ ] Define `IClientStore` interface.
        *   *Guidance:* 
            * Methods: `FindClientByIdAsync(string clientId)`. 
            * Define `CoreIdentClient` model 
              (e.g., ClientId, ClientSecrets (hashed), AllowedGrantTypes, RedirectUris, AllowedScopes, RequirePkce, AllowOfflineAccess).
*   **Component:** `IScopeStore` Interface
    - [ ] Define `IScopeStore` interface.
        *   *Guidance:* 
            * Methods: `FindScopesByNameAsync(IEnumerable<string> scopeNames)`, `GetAllScopesAsync()`. 
            * Define `CoreIdentScope` model 
              (e.g., Name, DisplayName, Description, Required, Emphasize, UserClaims). 
            * Include standard OIDC scopes (`openid`, `profile`, `email`, `offline_access`).

---

### Feature: Entity Framework Core Storage Provider

*   **Component:** `CoreIdent.Storage.EntityFrameworkCore` NuGet Package
    - [ ] Create `.csproj` file. 
          Add dependencies (`Microsoft.EntityFrameworkCore`, `Microsoft.EntityFrameworkCore.Relational`).
*   **Component:** EF Core DbContext (`CoreIdentDbContext`)
    - [ ] Define `CoreIdentDbContext`.
        *   *Guidance:* 
            * Include `DbSet` properties for `CoreIdentUser`, `CoreIdentRefreshToken`, `CoreIdentClient`, `CoreIdentScope`. 
            * Define entity configurations (keys, relationships, indexing, value converters for collections). 
            * Hash client secrets and refresh token handles before storing.
*   **Component:** EF Core Store Implementations
    - [ ] Implement `EfUserStore` : `IUserStore`.
    - [ ] Implement `EfRefreshTokenStore` : `IRefreshTokenStore`.
    - [ ] Implement `EfClientStore` : `IClientStore`.
    - [ ] Implement `EfScopeStore` : `IScopeStore`.
*   **Component:** EF Core Setup Extensions
    - [ ] Create `IServiceCollection` extension: 
          `AddCoreIdentEntityFrameworkStores<TContext>(Action<DbContextOptionsBuilder> optionsAction)` 
          where `TContext : DbContext, ICoreIdentDbContext` 
          (define marker interface `ICoreIdentDbContext` if needed).
        *   *Guidance:* 
            * Registers the `DbContext` and the EF Core store implementations 
              (`EfUserStore`, etc.) replacing the `InMemory` versions.
*   **Test Case (Integration):**
    - [ ] Configure CoreIdent with EF Core (using InMemory provider or SQLite for tests). 
          Verify user registration persists data.
    - [ ] Verify login retrieves user from DB.
    - [ ] Verify client and scope data can be added and retrieved via EF Core stores.
*   **Test Case (Unit):**
    - [ ] Unit test EF Core store implementations 
          using `Mock<DbSet<T>>` or InMemory provider.

---

### Feature: Robust Refresh Token Implementation

*   **Component:** Refresh Token Service Logic
    - [ ] Update `/token/refresh` endpoint logic.
        *   *Guidance:* 
            * Hash the incoming refresh token handle before lookup in `IRefreshTokenStore`.
        *   *Guidance:* 
            * Implement refresh token rotation: 
              * When a refresh token is used successfully, consume/remove the old one 
              * and issue a *new* refresh token alongside the new access token. 
            * Store the new refresh token handle (hashed) in `IRefreshTokenStore`.
        *   *Guidance:* 
            * Handle potential race conditions or replay attacks 
              (if a consumed token is presented, potentially revoke the entire token family/session).
    - [ ] Update `/login` and `/token` (Client Credentials) 
          to store issued refresh tokens using `IRefreshTokenStore`.
*   **Test Case (Integration):**
    - [ ] Refresh token flow works correctly with EF Core persistence.
    - [ ] Using a refresh token successfully invalidates it and issues a new one (rotation).
    - [ ] Attempting to use a refresh token twice fails.
    - [ ] Refresh tokens expire correctly based on stored lifetime.

---

### Feature: Delegated User Store Adapter (Optional Integration Path)

*   **Component:** `CoreIdent.Adapters.DelegatedUserStore` NuGet Package
    - [ ] Create `.csproj` file.
*   **Component:** `DelegatedUserStore` Implementation
    - [ ] Implement `DelegatedUserStore` : `IUserStore`.
        *   *Guidance:* 
            * Constructor accepts configuration (`DelegatedUserStoreOptions`) containing delegates 
              (e.g., `Func<string, Task<CoreIdentUser>> findUserByIdDelegate`, 
                     `Func<string, string, Task<bool>> validateCredentialsDelegate`).
        *   *Guidance:* 
            * Implementation calls the provided delegates to interact with the external user system. 
            * Handles cases where delegates are not provided.
*   **Component:** Configuration (`DelegatedUserStoreOptions`)
    - [ ] Define `DelegatedUserStoreOptions` class 
          to hold delegates for finding users, validating credentials, getting claims, etc.
*   **Component:** Setup Extension
    - [ ] Create `IServiceCollection` extension: 
          `AddCoreIdentDelegatedUserStore(Action<DelegatedUserStoreOptions> configure)`.
        *   *Guidance:* 
            * Registers `DelegatedUserStore` as the `IUserStore`. 
            * Requires essential delegates (like finding user) to be configured.
*   **Test Case (Integration):**
    - [ ] Configure CoreIdent with `DelegatedUserStore` and mock delegates. 
          Verify login flow calls the `validateCredentialsDelegate`.
    - [ ] Verify token issuance uses user data returned by the 
          `findUserByIdDelegate` or `findUserByUsernameDelegate`.

---

## Phase 3: Core OAuth 2.0 / OIDC Server Mechanics

**Goal:** Implement backend logic for standard authorization flows (Authorization Code + PKCE, Client Credentials) and discovery endpoints.

**Estimated Duration:** 4-6 weeks / 40-60 hours

---

### Feature: Authorization Code Flow (+ PKCE) Backend

*   **Component:** Authorize Endpoint (`GET /authorize`)
    - [ ] Implement Minimal API endpoint for `/authorize`.
        *   *Guidance:* 
            * Parses OIDC request parameters 
              (`client_id`, `redirect_uri`, `response_type=code`, `scope`, `state`, `nonce`, `code_challenge`, `code_challenge_method`).
        *   *Guidance:* 
            * Validate client (`IClientStore`), redirect URI, requested scopes (`IScopeStore`).
        *   *Guidance:* 
            * Check if user is authenticated (via cookie). 
            * If not, redirect to login page (UI needed in Phase 4, for now, assume authenticated or return error).
        *   *Guidance:* 
            * Store authorization request details 
              (client, scopes, redirect URI, code challenge, nonce) 
              associated with a short-lived, securely generated authorization code. 
            * Persist this code (e.g., in a temporary cache or DB table).
        *   *Guidance:* 
            * Redirect user back to the client's `redirect_uri` with `code` and `state`.
*   **Component:** Token Endpoint (Grant Type: `authorization_code`)
    - [ ] Extend `POST /token` endpoint to handle `grant_type=authorization_code`.
        *   *Guidance:* 
            * Accepts parameters: `grant_type`, `code`, `redirect_uri`, `client_id`, 
                              `client_secret` (for confidential clients), `code_verifier`.
        *   *Guidance:* 
            * Validate client authentication (secret or public client check).
        *   *Guidance:* 
            * Retrieve the stored authorization request details using the `code`. 
            * Verify `redirect_uri` matches.
        *   *Guidance:* 
            * Validate PKCE: Hash the incoming `code_verifier` using the 
              `code_challenge_method` stored with the code and compare against the `code_challenge`.
        *   *Guidance:* 
            * If valid, consume the authorization code (prevent reuse).
        *   *Guidance:* 
            * Issue Access Token, Refresh Token (if `offline_access` scope granted), 
              and ID Token using `ITokenService`.
        *   *Guidance:* 
            * Return tokens in the response.
*   **Test Case (Integration):**
    - [ ] Simulate `/authorize` request, verify redirect with code and state.
    - [ ] Use the code, client credentials, and correct PKCE verifier 
          at `/token` endpoint, verify tokens are issued.
    - [ ] `/token` request fails if code is invalid, expired, or already used.
    - [ ] `/token` request fails if PKCE verification fails.
    - [ ] `/token` request fails if client secret is incorrect (for confidential clients).
    - [ ] `/token` request fails if `redirect_uri` does not match the initial request.

---

### Feature: Client Credentials Flow Backend

*   **Component:** Token Endpoint (Grant Type: `client_credentials`)
    - [ ] Extend `POST /token` endpoint to handle `grant_type=client_credentials`.
        *   *Guidance:* 
            * Accepts parameters: `grant_type`, `client_id`, `client_secret`, `scope` (optional).
        *   *Guidance:* 
            * Authenticate the client using `client_id` and `client_secret` against `IClientStore`.
        *   *Guidance:* 
            * Validate requested scopes against the client's allowed scopes.
        *   *Guidance:* 
            * Issue Access Token using `ITokenService` 
              (no user context, token represents the client). 
            * No Refresh Token typically issued.
        *   *Guidance:* 
            * Return access token in the response.
*   **Test Case (Integration):**
    - [ ] `POST /token` with `grant_type=client_credentials` and valid client credentials 
          returns an access token.
    - [ ] Token represents the client (e.g., `sub` claim is `client_id`).
    - [ ] Request fails if client credentials are invalid.
    - [ ] Request fails if requested scopes are not allowed for the client.

---

### Feature: OIDC Discovery & JWKS Endpoints

*   **Component:** Discovery Endpoint (`GET /.well-known/openid-configuration`)
    - [ ] Implement Minimal API endpoint for discovery.
        *   *Guidance:* 
            * Return JSON document conforming to OIDC Discovery spec. 
            * Include endpoints (`authorization_endpoint`, `token_endpoint`, `jwks_uri`, `userinfo_endpoint` - if implemented), 
              supported scopes, response types, grant types, claims, etc. 
            * Read values from configuration and registered services.
*   **Component:** JWKS Endpoint (`GET /.well-known/jwks.json`)
    - [ ] Implement Minimal API endpoint for JWKS.
        *   *Guidance:* 
            * Return JSON Web Key Set (JWKS) containing the public key(s) used for signing JWTs. 
            * If using asymmetric keys, retrieve public key material. 
            * If symmetric, this endpoint might not be strictly necessary or could return metadata differently.
        *   *Guidance:* 
            * Key generation/management strategy needs consideration 
              (e.g., load from config, generate on startup, key rotation).
*   **Test Case (Integration):**
    - [ ] `GET /.well-known/openid-configuration` returns a valid JSON document 
          with correct endpoint URLs.
    - [ ] `GET /.well-known/jwks.json` returns a valid JWKS document. 
          Public key can be used to validate tokens issued by the server (if using asymmetric keys).

---

### Feature: ID Token Issuance

*   **Component:** Token Service (`ITokenService`) Enhancement
    - [ ] Update `ITokenService` to generate OIDC ID Tokens.
        *   *Guidance:* 
            * Generate ID Token (JWT) alongside Access Token for relevant flows 
              (Authorization Code, Hybrid - if implemented later).
        *   *Guidance:* 
            * Include required ID Token claims: `iss`, `sub`, `aud`, `exp`, `iat`. 
            * Include `nonce` if provided in the original request. 
            * Include user claims based on requested scopes (`profile`, `email`). 
            * Sign the ID Token.
*   **Test Case (Integration):**
    - [ ] ID Token is included in the `/token` response for Authorization Code flow.
*   **Test Case (Unit):**
    - [ ] Generated ID Token is a valid JWT with required claims and correct signature.
    - [ ] User claims included in ID Token match requested scopes.
    - [ ] `nonce` claim matches the value from the authorization request.

---

## Phase 4: User Interaction & External Integrations

**Goal:** Introduce user-facing elements (consent, UI), MFA framework, and external/passwordless login capabilities.

**Estimated Duration:** 6-9 weeks / 60-90 hours (Parallel work possible)

---

### Feature: User Consent Mechanism

*   **Component:** Consent Logic
    - [ ] Modify `/authorize` endpoint logic.
        *   *Guidance:* 
            * After user authentication, check if consent is required for the client/scopes. 
            * Check stored grants/consent for the user/client combination.
        *   *Guidance:* 
            * If consent needed, redirect user to the Consent Page URL, passing request details.
    - [ ] Implement Consent Decision Endpoint (`POST /consent`).
        *   *Guidance:* 
            * Accepts user decision (allow/deny) and original request context. 
            * If allowed, store the consent/grant (scopes granted) for the user/client. 
            * Redirect back to `/authorize` logic to complete the flow and issue the code. 
            * If denied, redirect back to client with `error=access_denied`.
*   **Component:** Consent Storage (Extend existing stores or new store)
    - [ ] Design storage for user consents/grants 
          (e.g., `UserGrant` entity: UserId, ClientId, Scopes, Expiration).
    - [ ] Update EF Core DbContext and create `EfGrantStore` 
          or extend `EfUserStore`/`EfClientStore`.
*   **Test Case (Integration):**
    - [ ] `/authorize` flow redirects to consent page if new scopes are requested for a client.
    - [ ] Submitting consent 'allow' results in code issuance.
    - [ ] Submitting consent 'deny' results in error redirect to client.
    - [ ] Subsequent `/authorize` requests for the same client/scopes (within consent lifetime) 
          do not require consent again.

---

### Feature: Basic Web UI (`CoreIdent.UI.Web`)

*   **Component:** `CoreIdent.UI.Web` NuGet Package Project
    - [ ] Create `.csproj` file. Choose UI technology 
          (Razor Pages recommended for simplicity, Blazor optional). 
          Add necessary ASP.NET Core dependencies.
*   **Component:** UI Pages/Components
    - [ ] Implement Login Page (`/Account/Login`).
    - [ ] Implement Registration Page (`/Account/Register`).
    - [ ] Implement Consent Page (`/Consent`).
        *   *Guidance:* Display client name, requested scopes (with descriptions from `IScopeStore`), 
                      allow/deny buttons.
    - [ ] Implement MFA Prompt Page (`/Account/Mfa`).
    - [ ] Implement Error Page.
*   **Component:** UI Setup Extension
    - [ ] Create `IServiceCollection` extension `AddCoreIdentUI()` (or similar).
        *   *Guidance:* Registers Razor Pages/Controllers, potentially adds necessary static files middleware.
*   **Component:** Theming/Overriding Mechanism
    - [ ] Design a way for consuming applications to easily theme or replace the default UI components.
        *   *Guidance:* Use standard ASP.NET Core mechanisms 
                      (e.g., Razor Class Libraries, view overrides).
*   **Test Case (Manual/E2E):**
    - [ ] User can navigate to login page, enter credentials, and log in successfully (cookie set).
    - [ ] User can navigate to register page and create an account.
    - [ ] During `/authorize` flow, user is presented with the consent page, 
          can grant/deny, and flow completes correctly.
    - [ ] Basic UI elements are reasonably styled and functional.

---

### Feature: OIDC Logout

*   **Component:** End Session Endpoint (`GET /endsession`)
    - [ ] Implement Minimal API endpoint for `/endsession`.
        *   *Guidance:* Accepts parameters like `id_token_hint`, `post_logout_redirect_uri`, `state`.
        *   *Guidance:* Validate `id_token_hint` (optional but recommended).
        *   *Guidance:* Validate `post_logout_redirect_uri` against client's registered URIs.
        *   *Guidance:* Sign the user out (clear authentication cookie).
        *   *Guidance:* Redirect user to a logged-out confirmation page 
                      or the `post_logout_redirect_uri` if valid.
*   **Test Case (Integration):**
    - [ ] Calling `/endsession` clears the authentication cookie.
    - [ ] Calling `/endsession` with a valid `post_logout_redirect_uri` 
          redirects the user back correctly.
    - [ ] Calling `/endsession` with an invalid `post_logout_redirect_uri` 
          shows a local logged-out page or error.

---

### Feature: Multi-Factor Authentication (MFA) Framework

*   **Component:** Core MFA Logic
    - [ ] Update user model/store (`CoreIdentUser`, `IUserStore`) 
          to track MFA enabled status and potentially preferred provider/configuration.
    - [ ] Modify login/authorize flows to check MFA requirement. 
          If needed, redirect to MFA prompt page (`/Account/Mfa`).
    - [ ] Define `IMfaProvider` interface 
          (e.g., `InitiateChallengeAsync`, `ValidateChallengeAsync`, `ProviderName`).
    - [ ] Implement service to manage/invoke registered `IMfaProvider`s.
*   **Component:** MFA Prompt Page (`/Account/Mfa`)
    - [ ] Display prompt for the required second factor (e.g., "Enter TOTP code").
    - [ ] Submit challenge response to a validation endpoint.
*   **Test Case (Integration):**
    - [ ] Login flow for MFA-enabled user redirects to MFA prompt after password validation.
    - [ ] Submitting correct MFA challenge completes login.
    - [ ] Submitting incorrect MFA challenge shows error, does not complete login.

---

### Feature: Provider Abstractions & Specific Providers

*   **Component:** `CoreIdent.Providers.Abstractions` NuGet Package
    - [ ] Create `.csproj` file. Define base classes/interfaces for external providers 
          (e.g., `IExternalAuthenticationProvider`, callback handling logic).
*   **Component:** `CoreIdent.Providers.Passkeys` Package (WebAuthn/FIDO2)
    - [ ] Create `.csproj`. Add WebAuthn library dependency (e.g., `Fido2NetLib`).
    - [ ] Implement endpoints for challenge generation (`/passkey/challenge`), 
          credential registration (`/passkey/register`), 
          assertion verification (`/passkey/verify`).
    - [ ] Implement storage for public key credentials 
          (extend `IUserStore` or new store `IPasskeyCredentialStore`).
    - [ ] Implement `AddPasskeyProvider()` setup extension.
*   **Test Case (Integration):**
    - [ ] User can register a passkey (device authenticator or security key).
*   **Component:** `CoreIdent.Providers.Totp` Package (MFA Provider)
    - [ ] Create `.csproj`. Add TOTP library dependency (e.g., `Otp.NET`).
    - [ ] Implement `IMfaProvider` for TOTP.
    - [ ] Implement logic for TOTP setup (generate secret, display QR code). 
          Store secret securely (encrypted) associated with user.
    - [ ] Implement validation logic.
    - [ ] Implement `AddTotpProvider()` setup extension.
*   **Test Case (Integration):**
    - [ ] User can enable TOTP MFA, scan QR code.
*   **Component:** `CoreIdent.Providers.Google` Package (Social Login)
    - [ ] Create `.csproj`. Add `Microsoft.AspNetCore.Authentication.Google` dependency.
    - [ ] Implement provider logic using standard ASP.NET Core external login handlers. 
          Map Google profile claims to `CoreIdentUser`. 
          Handle linking/creation of local user.
    - [ ] Implement `AddGoogleProvider(Action<GoogleOptions> configure)` setup extension.
*   **Test Case (Integration):**
    - [ ] User can initiate login via Google, authenticate with Google, 
          and be logged into CoreIdent (new user created or linked).
*   **Component:** `CoreIdent.Providers.Web3` Package (Wallet Login)
    - [ ] Create `.csproj`. Add Nethereum or similar library if needed for signature verification.
    - [ ] Implement challenge generation endpoint.
    - [ ] Implement login endpoint verifying message signature against wallet address. 
          Link/create local user based on verified address.
    - [ ] Implement `AddWeb3Provider()` setup extension.
*   **Test Case (Integration):**
    - [ ] User can request challenge, sign with wallet, and log in.
*   **Component:** `CoreIdent.Providers.LNURL` Package (Lightning Login)
    - [ ] Create `.csproj`. Add LNURL library dependency (or implement spec).
    - [ ] Implement LNURL-auth flow (generate `k1`, provide LNURL endpoint, verify signature against linking key).
    - [ ] Implement `AddLnurlAuthProvider()` setup extension.
*   **Test Case (Integration):**
    - [ ] User can scan LNURL QR code with wallet, approve login, and be logged in.

---

### Feature: Administration UI (Optional)

*   **Component:** `CoreIdent.AdminUI` NuGet Package
    - [ ] Create `.csproj`. Choose UI tech (Razor Pages/Blazor). Secure appropriately (admin role/policy).
    - [ ] Implement basic User Management UI 
          (List, View, Create, Edit Roles/Claims - Readonly initially?).
    - [ ] Implement basic Client Management UI (List, View).
    - [ ] Implement basic Scope Management UI (List, View).
    - [ ] Implement `AddCoreIdentAdminUI()` setup extension.
*   **Test Case (Manual/E2E):**
    - [ ] Admin user can log in and access the Admin UI.
    - [ ] Admin can view list of users/clients/scopes.
    - [ ] (If implemented) Admin can perform basic CRUD operations.

---

## Phase 5: Community, Documentation & Tooling

**Goal:** Make CoreIdent easy to adopt, use, and contribute to. Polish and prepare for wider release.

**Estimated Duration:** 4+ weeks / 40-60 hours (Ongoing / Parallel)

---

### Feature: Documentation Website

*   **Component:** Docs Site Project
    - [ ] Choose static site generator (e.g., Docusaurus, VitePress). Set up repository.
    - [ ] Write "Getting Started" guide.
    - [ ] Write Configuration guide (`CoreIdentOptions`, Storage setup, Provider setup).
    - [ ] Write API Reference (core endpoints).
    - [ ] Write guides for specific features (MFA setup, Passkeys, Custom User Stores).
    - [ ] Write Architecture overview.
    - [ ] Write Contribution guide.
    - [ ] Set up deployment for docs site (e.g., GitHub Pages, Netlify).
*   **Test Case (Manual):**
    - [ ] Documentation is clear, accurate, and easy to navigate.
    - [ ] Getting Started guide allows a new user to set up a basic instance successfully.

---

### Feature: `dotnet new` Templates

*   **Component:** Template Projects (`coreident-server`, `coreident-api`)
    - [ ] Create template project structures.
    - [ ] Create `.template.config/template.json` files.
    - [ ] Implement template logic (e.g., conditional package inclusion based on options).
    - [ ] Package templates as a NuGet package.
*   **Test Case:**
    - [ ] `dotnet new coreident-server` creates a runnable project 
          with CoreIdent and default EF Core storage.
    - [ ] `dotnet new coreident-api` creates a runnable API project secured by CoreIdent 
          (requiring a running CoreIdent instance).

---

### Feature: Example Applications

*   **Component:** Sample Projects (e.g., SPA, Web API)
    - [ ] Create sample ASP.NET Core API project 
          demonstrating how to protect endpoints using CoreIdent tokens.
    - [ ] Create sample SPA (e.g., React, Vue, Blazor WASM) 
          demonstrating Authorization Code Flow + PKCE login against CoreIdent.
    - [ ] Add samples to main repository or separate repository.
*   **Test Case (Manual):**
    - [ ] Example API can be run and endpoints accessed with valid tokens from CoreIdent.
    - [ ] Example SPA can successfully log in via CoreIdent 
          and make authenticated calls to the example API.

---

### Feature: CI/CD Pipeline & Publishing

*   **Component:** CI/CD Workflow (e.g., GitHub Actions)
    - [ ] Set up workflow to trigger on pushes/PRs.
    - [ ] Add steps to restore dependencies, build the solution.
    - [ ] Add step to run unit tests.
    - [ ] Add step to run integration tests (potentially using test containers for DBs).
    - [ ] Add step to pack NuGet packages.
    - [ ] Add step to publish NuGet packages (on tag/release).
    - [ ] Add step to deploy documentation site.
*   **Test Case:**
    - [ ] CI pipeline runs successfully on PRs.
    - [ ] NuGet packages are published correctly on release.

---

### Feature: Community Setup

*   **Component:** GitHub Repository Settings
    - [ ] Set up issue templates.
    - [ ] Set up PR template.
    - [ ] Create `CONTRIBUTING.md` guidelines.
    - [ ] Create `CODE_OF_CONDUCT.md`.
    - [ ] Enable GitHub Discussions.
*   **Test Case (N/A):**
    - [ ] Community resources are in place.