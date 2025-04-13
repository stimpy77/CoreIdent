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
- [ ] **Update README.md** with registration endpoint details and usage examples.
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
- [ ] **Update README.md** with login endpoint details, token structure, and configuration notes.
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
    - [x] Refresh token flow works correctly with EF Core persistence. (Requires DI Setup & Migrations)
    - [x] Using a refresh token successfully invalidates it and issues a new one (rotation). (Requires DI Setup & Migrations)
    - [x] Attempting to use a refresh token twice fails. (Requires DI Setup & Migrations)
    - [x] Refresh tokens expire correctly based on stored lifetime. (Requires DI Setup & Migrations)
- [x] **Update README.md** with details on persistent refresh token handling.
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
- [ ] Review and finalize README.md for Phase 1 completeness.

### Feature: Developer Training Guide (Phase 1)

*   **Goal:** Provide foundational learning material for developers using CoreIdent.
*   **Component:** Training Document
    - [ ] Create initial Developer Training Guide covering Phase 1 concepts (Core setup, Registration, Login, Token basics - JWTs, Hashing, In-Memory stores, Security fundamentals).

---

## Phase 2: Storage & Core Extensibility

**Goal:** Enable persistent user storage, refine core interfaces for extensibility, implement robust refresh tokens, and define client/scope storage.

**Estimated Duration:** 3-5 weeks / 30-45 hours

---

### Feature: Refined Core Interfaces

*   **Component:** `IUserStore` Interface
    - [x] Review and refine `IUserStore`.
        *   *Guidance:* 
            * Add methods needed for 
              * password management (`SetPasswordHashAsync`, `GetPasswordHashAsync`), 
              * claim management (`GetClaimsAsync`, `AddClaimsAsync`, `ReplaceClaimAsync`, `RemoveClaimsAsync`), 
              * potentially lockout (`GetLockoutEndDateAsync`, `IncrementAccessFailedCountAsync`, `ResetAccessFailedCountAsync`). 
            * Ensure methods are suitable for both integrated (EF Core) and delegated implementations. 
            * Update `CoreIdentUser` model if needed (e.g., add `Claims` collection, lockout properties).
*   **Component:** `IRefreshTokenStore` Interface
    - [x] Define `IRefreshTokenStore` interface.
        *   *Guidance:* 
            * Methods: `StoreRefreshTokenAsync(CoreIdentRefreshToken token)`, `GetRefreshTokenAsync(string tokenHandle)`, `RemoveRefreshTokenAsync(string tokenHandle)`. 
            * Define `CoreIdentRefreshToken` model 
              (e.g., Handle (hashed), SubjectId, ClientId, CreationTime, ExpirationTime, ConsumedTime?).
*   **Component:** `IClientStore` Interface
    - [x] Define `IClientStore` interface.
        *   *Guidance:* 
            * Methods: `FindClientByIdAsync(string clientId)`. 
            * Define `CoreIdentClient` model 
              (e.g., ClientId, ClientSecrets (hashed), AllowedGrantTypes, RedirectUris, AllowedScopes, RequirePkce, AllowOfflineAccess).
*   **Component:** `IScopeStore` Interface
    - [x] Define `IScopeStore` interface.
        *   *Guidance:* 
            * Methods: `FindScopesByNameAsync(IEnumerable<string> scopeNames)`, `GetAllScopesAsync()`. 
            * Define `CoreIdentScope` model 
              (e.g., Name, DisplayName, Description, Required, Emphasize, UserClaims). 
            * Include standard OIDC scopes (`openid`, `profile`, `email`, `offline_access`).

---

### Feature: Entity Framework Core Storage Provider

*   **Component:** `CoreIdent.Storage.EntityFrameworkCore` NuGet Package
    - [x] Create `.csproj` file. Add dependencies (`Microsoft.EntityFrameworkCore`, `Microsoft.EntityFrameworkCore.Relational`, `Microsoft.EntityFrameworkCore.Sqlite`).
*   **Component:** EF Core DbContext (`CoreIdentDbContext`)
    - [x] Define `CoreIdentDbContext`.
        *   *Guidance:* Include `DbSet` properties for `CoreIdentUser`, `CoreIdentRefreshToken`, `CoreIdentClient`, `CoreIdentScope`, and related entities (`UserClaim`, `ClientSecret`, `ScopeClaim`). Define entity configurations (keys, relationships, indexing, value converters for collections). Hash client secrets and refresh token handles before storing (Hashing to be implemented in store logic where appropriate, not directly in DbContext).
*   **Component:** EF Core Store Implementations
    - [x] Implement `EfUserStore` : `IUserStore`.
    - [x] Implement `EfRefreshTokenStore` : `IRefreshTokenStore`.
    - [x] Implement `EfClientStore` : `IClientStore`.
    - [x] Implement `EfScopeStore` : `IScopeStore`.
*   **Component:** EF Core Setup Extensions
    - [x] Create `IServiceCollection` extension: `AddCoreIdentEntityFrameworkStores<TContext>()`.
        *   *Guidance:* Registers the `DbContext` (assuming registered by caller) and the EF Core store implementations (`EfUserStore`, etc.) replacing the `InMemory` versions.
*   **Test Case (Integration):**
    - [x] Configure CoreIdent with EF Core (using InMemory provider or SQLite for tests). Verify user registration persists data.
    - [x] Verify login retrieves user from DB.
    - [x] Verify client and scope data can be added and retrieved via EF Core stores.
*   **Test Case (Unit):**
    - [x] Unit test EF Core store implementations using `Mock<DbSet<T>>` or InMemory provider.
*   **Test Case (Integration):**
    - [x] **Fix Unit Tests** for EF Core Store implementations (Scope, Client, RefreshToken, User).
    - [x] Register EF Core services (`AddDbContext`, Store implementations) in DI.
    - [x] Add EF Core Migrations and update database.
- [x] **Update README.md** with EF Core setup instructions and configuration.
    *   *Decision:* Use **SQLite** as the initial database provider (`Microsoft.EntityFrameworkCore.Sqlite`) for ease of development and testing.

---

### Feature: Robust Refresh Token Implementation

*   **Component:** Refresh Token Service Logic
    - [x] Update `/token/refresh` endpoint logic.
        *   *Guidance:* 
            * Hash the incoming refresh token handle before lookup in `IRefreshTokenStore`. (Note: Hashing is handled within the store implementation, not the endpoint itself)
        *   *Guidance:* 
            * Implement refresh token rotation: 
              * When a refresh token is used successfully, consume/remove the old one 
              * and issue a *new* refresh token alongside the new access token. 
            * Store the new refresh token handle (hashed) in `IRefreshTokenStore`. (Done)
        *   *Guidance:* 
            * Handle potential race conditions or replay attacks 
              (if a consumed token is presented, potentially revoke the entire token family/session). (Basic validation added, advanced revocation is future work)
    - [x] Update `/login` ~~and `/token` (Client Credentials)~~ 
          to store issued refresh tokens using `IRefreshTokenStore`. (`/login` done, `/token` endpoint for client credentials not yet implemented)
*   **Test Case (Integration):**
    - [x] Refresh token flow works correctly with EF Core persistence. (Requires DI Setup & Migrations)
    - [x] Using a refresh token successfully invalidates it and issues a new one (rotation). (Requires DI Setup & Migrations)
    - [x] Attempting to use a refresh token twice fails. (Requires DI Setup & Migrations)
    - [x] Refresh tokens expire correctly based on stored lifetime. (Requires DI Setup & Migrations)
- [x] **Update README.md** with details on persistent refresh token handling.

---

### Feature: Delegated User Store Adapter (Optional Integration Path)

*   **Component:** `CoreIdent.Adapters.DelegatedUserStore` NuGet Package
    - [x] Create `.csproj` file.
*   **Component:** `DelegatedUserStore` Implementation
    - [x] Implement `DelegatedUserStore` : `IUserStore`.
        *   *Guidance:* 
            * Constructor accepts configuration (`DelegatedUserStoreOptions`) containing delegates 
              (e.g., `Func<string, Task<CoreIdentUser>> findUserByIdDelegate`, 
                     `Func<string, string, Task<bool>> validateCredentialsDelegate`).
        *   *Guidance:* 
            * Implementation calls the provided delegates to interact with the external user system. 
            * Handles cases where delegates are not provided.
*   **Component:** Configuration (`DelegatedUserStoreOptions`)
    - [x] Define `DelegatedUserStoreOptions` class 
          to hold delegates for finding users, validating credentials, getting claims, etc.
*   **Component:** Setup Extension
    - [x] Create `IServiceCollection` extension: 
          `AddCoreIdentDelegatedUserStore(Action<DelegatedUserStoreOptions> configure)`.
        *   *Guidance:* 
            * Registers `DelegatedUserStore` as the `IUserStore`. 
            * Requires essential delegates (like finding user) to be configured.
*   **Test Case (Integration):**
    - [x] Configure CoreIdent with `DelegatedUserStore` and mock delegates. 
          Verify login flow calls the `validateCredentialsDelegate`.
    - [x] Verify token issuance uses user data returned by the 
          `findUserByIdDelegate` or `findUserByUsernameDelegate`.
- [x] **Update README.md** with Delegated User Store setup instructions and configuration.

### Feature: Developer Training Guide (Phase 2 Update)

*   **Goal:** Expand training materials to cover persistence and extensibility.
*   **Component:** Training Document
    - [x] Update Developer Training Guide with Phase 2 concepts (Storage interfaces - `IUserStore`, `IRefreshTokenStore`, `IClientStore`, `IScopeStore`; EF Core integration; Delegated storage patterns; Refresh token persistence and rotation strategies).

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
- [ ] **Update README.md** with details on `/authorize` endpoint, PKCE, and related configuration.

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
- [ ] **Update README.md** with details on `/token` endpoint for `client_credentials` grant type.

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
- [ ] **Update README.md** with details on discovery and JWKS endpoints.

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
- [ ] **Update README.md** with information on ID Tokens and relevant claims.

### Feature: Developer Training Guide (Phase 3 Update)

*   **Goal:** Explain core OAuth/OIDC concepts as implemented in CoreIdent.
*   **Component:** Training Document
    - [ ] Update Developer Training Guide with Phase 3 concepts (OAuth 2.0 flows - Auth Code+PKCE, Client Credentials; OIDC concepts - ID Tokens, Discovery, JWKS; Client/Scope management basics).

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
- [ ] **Update README.md** with details on the consent mechanism and related UI.

---

### Feature: Basic Web UI (`CoreIdent.UI.Web`)

*   **Component:** `CoreIdent.UI.Web` NuGet Package Project
    - [ ] Create `.csproj` file. Choose UI technology 
          (Razor Pages recommended for simplicity, Blazor optional). 
          Add necessary ASP.NET Core dependencies.
*   **Component:** UI Pages/Components
    - [ ] Implement Login Page (`/Account/Login`).
    - [ ] Implement Registration Page (`