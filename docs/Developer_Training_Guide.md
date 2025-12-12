# CoreIdent: Developer Training Guide (Legacy 0.3.x)

> **Legacy notice:** This guide describes the archived **0.3.x** implementation (which remains on the `main` branch and is tagged `legacy-0.3.x-main`).
>
> CoreIdent **0.4 is a clean-slate rewrite on .NET 10 (`net10.0`)**. For the current plan/specs, use:
> - `docs/0.4/Project_Overview.md`
> - `docs/0.4/Technical_Plan.md`
> - `docs/0.4/DEVPLAN.md`

Welcome to the CoreIdent Developer Training Guide. This document aims to provide developers with the foundational knowledge required to understand, use, and potentially contribute to the CoreIdent project.

## Phase 1: Core Concepts & MVP

This section covers the fundamentals implemented in the initial Minimum Viable Product (MVP) phase.

### 1. Core Setup & Configuration

*   **Overview:** Understanding the core package (`CoreIdent.Core`) and its purpose.
*   **Configuration (`CoreIdentOptions`):**
    *   Key options (`Issuer`, `Audience`, `SigningKeySecret`, Lifetimes).
    *   How to configure these in your application (e.g., `appsettings.json`).
    *   Configuration validation.
*   **Dependency Injection:**
    *   Using `AddCoreIdent()` in `Program.cs` or `Startup.cs`.
    *   What services are registered by default.
    *   (Important: When using persistent storage like EF Core, the Dependency Injection registration order is critical. See details below.)
*   **Endpoint Mapping:**
    *   Using `MapCoreIdentEndpoints()`. Accepts an optional `basePath` parameter (defaults to `/`, but the test host uses `/auth`).
    *   Default endpoints exposed (relative to base path): `/register`, `/login`, `/token/refresh`.
The foundation of CoreIdent lies within the `CoreIdent.Core` NuGet package. This package contains the essential interfaces, services, and extension methods needed to integrate CoreIdent's authentication and authorization features into your ASP.NET Core application.

**Core Package Overview:**

*   **`CoreIdent.Core`:** This is the main library you'll reference. It provides the building blocks like `IUserStore`, `ITokenService`, `IPasswordHasher`, configuration options (`CoreIdentOptions`), and the necessary setup extensions. It aims to be platform-agnostic regarding storage and UI, focusing purely on the core identity logic.

**Configuration (`CoreIdentOptions`):**

Proper configuration is crucial for security and functionality. CoreIdent uses the standard ASP.NET Core options pattern. You configure `CoreIdentOptions`, typically in your `appsettings.json` file or other configuration providers.

*   **Key Options:**
    *   `Issuer` (string): The identifier for the token issuer (your application/service). This will appear in the `iss` claim of JWTs. Example: `"https://auth.yourapp.com"`
    *   `Audience` (string): The identifier for the intended recipient(s) of the tokens (your APIs). This will appear in the `aud` claim. Example: `"https://api.yourapp.com"`
    *   `SigningKeySecret` (string): **CRITICAL:** The secret key used to sign JWTs (using symmetric HS256 algorithm by default in Phase 1). This key (and any client secrets for confidential clients) MUST be kept confidential, unique, and cryptographically strong (minimum 32 bytes / 256 bits for HS256). **Never** hardcode secrets in source control. Use secure management practices (User Secrets, Environment Variables, Azure Key Vault, AWS Secrets Manager, etc.).
    *   `AccessTokenLifetime` (TimeSpan): How long an access token is valid. Keep this relatively short (e.g., `"00:15:00"` for 15 minutes).
    *   `RefreshTokenLifetime` (TimeSpan): How long a refresh token is valid. This is typically much longer than the access token (e.g., `"7.00:00:00"` for 7 days).

*   **Example `appsettings.json`:**
    ```json
    {
      "CoreIdent": {
        "Issuer": "https://localhost:7123", // Change in production
        "Audience": "https://localhost:7123", // Change in production
        "SigningKeySecret": "YOUR_VERY_STRONG_AND_SECRET_SIGNING_KEY_HERE_MIN_32_BYTES", // CHANGE THIS! Use User Secrets or other secure provider
        "AccessTokenLifetime": "00:15:00",
        "RefreshTokenLifetime": "7.00:00:00"
      }
      // ... other settings
    }
    ```
    **⚠️ Security Note:** The `SigningKeySecret` and any client secrets for confidential clients are critical and must **never** be stored in source control. Use secure management practices such as Environment Variables, User Secrets, Azure Key Vault, or AWS Secrets Manager.
*   **Validation:** CoreIdent includes validation for these options. If required settings like `Issuer`, `Audience`, or a sufficiently long `SigningKeySecret` are missing, the application will fail to start, preventing insecure configurations.

**Dependency Injection (`AddCoreIdent`):**

CoreIdent integrates seamlessly with ASP.NET Core's dependency injection system.

*   **Usage:** In your application's `Program.cs` (or `Startup.cs` for older templates), you call the `AddCoreIdent()` extension method on `IServiceCollection`.
    ```csharp
    // Example in Program.cs (Minimal API template)
    var builder = WebApplication.CreateBuilder(args);

    // Configure CoreIdent options from appsettings.json section "CoreIdent"
    builder.Services.AddOptions<CoreIdentOptions>()
        .Bind(builder.Configuration.GetSection("CoreIdent"))
        .ValidateDataAnnotations() // Basic validation
        .ValidateOnStart();       // Run validation on startup

    // Add CoreIdent services (Register this FIRST)
    builder.Services.AddCoreIdent(); // Options are automatically picked up

    // Add standard ASP.NET Core AuthN/AuthZ if needed for token validation
    builder.Services.AddAuthentication().AddJwtBearer(); // Example for JWT validation
    builder.Services.AddAuthorization();

    // ... other services (e.g., AddDbContext comes AFTER AddCoreIdent)

    // ... Register EF Core Stores AFTER AddDbContext
    // builder.Services.AddCoreIdentEntityFrameworkStores<YourDbContext>();

    var app = builder.Build();
    ```
*   **Registered Services:** `AddCoreIdent()` registers the default implementations for core services:
    *   `CoreIdentOptions` (configured via `AddOptions`)
    *   `ITokenService` -> `JwtTokenService`
    *   `IPasswordHasher` -> `DefaultPasswordHasher`
    *   `IUserStore` -> `InMemoryUserStore` (Phase 1 default)
    *   Validation services for `CoreIdentOptions`.
*   **Registration Order:** When using persistent storage (like EF Core), ensure the registration order is correct:
    1.  `builder.Services.AddCoreIdent(...);`
    2.  `builder.Services.AddDbContext<YourDbContext>(...);`
    3.  `builder.Services.AddCoreIdentEntityFrameworkStores<YourDbContext>();`

**Endpoint Mapping (`MapCoreIdentEndpoints`):**

To expose the built-in authentication endpoints, CoreIdent provides an extension method for `IEndpointRouteBuilder`.

*   **Usage:** In `Program.cs` (after `app.Build()`), call `MapCoreIdentEndpoints()`. You can optionally provide a `basePath` argument.
    ```csharp
    // Example in Program.cs
    var app = builder.Build();

    // ... other middleware (HTTPS redirection, routing, etc.)

    app.UseAuthentication(); // Important: Before UseAuthorization and MapCoreIdentEndpoints
    app.UseAuthorization();

    // Map CoreIdent's built-in endpoints under the /auth prefix
    // Use the basePath parameter to change the prefix if needed.
    app.MapCoreIdentEndpoints("/auth");

    // Map your other application endpoints
    app.MapGet("/", () => "Hello World!");

    app.Run();
    ```
*   **Default Endpoints Exposed:** Assuming the base path is `/auth`, this maps:
    *   `POST /auth/register`: Handles new user registration.
    *   `POST /auth/login`: Handles user login and issues tokens.
    *   `POST /auth/token/refresh`: Handles refreshing access tokens using a refresh token.
    *   (Phase 3) `GET /auth/authorize`: Initiates authorization code flow.
    *   (Phase 3) `POST /auth/token`: Handles token exchange (e.g., for authorization code).

### 2. User Registration (`/auth/register`)

The `POST /auth/register` endpoint is the entry point for new users to create an account within your application using CoreIdent.

**Registration Flow:**

1.  **Client Request:** A client application (web frontend, mobile app, etc.) sends an HTTP POST request to the `/auth/register` endpoint. The request body must contain the necessary user information, typically email and password, formatted as JSON.
2.  **Input Validation:** CoreIdent first validates the incoming request data (DTO - Data Transfer Object). It checks for required fields (e.g., email, password) and potentially applies validation rules (e.g., valid email format, minimum password complexity - though basic complexity is handled by hashing). If validation fails, a `400 Bad Request` response is returned with details about the validation errors.
3.  **Check for Existing User:** The endpoint uses the injected `IUserStore` service to check if a user with the provided email (or username) already exists. If a user is found, a `409 Conflict` response is returned to indicate that the email is already taken.
4.  **Password Hashing:** If the user does not exist, the endpoint uses the injected `IPasswordHasher` service to securely hash the provided plain-text password. This generates a strong, salted hash suitable for storage.
5.  **Create User:** A new `CoreIdentUser` object is created with the provided details (e.g., email as username) and the generated password hash.
6.  **Store User:** The new user object is passed to the `IUserStore`'s `CreateAsync` method (or similar) to persist the user account. In Phase 1, this uses the `InMemoryUserStore`, meaning the user exists only for the lifetime of the application process.
7.  **Success Response:** If the user is successfully created and stored, a `201 Created` response is returned to the client. Typically, the response body is empty, but the location header might point to the newly created resource (though often not implemented for user registration).

**Request/Response:**

*   **Request (`POST /auth/register`):**
    *   Method: `POST`
    *   Content-Type: `application/json`
    *   Body (Example DTO - `RegisterRequest`):
        ```json
        {
          "email": "test@example.com",
          "password": "YourStrongPassword123!"
        }
        ```
        *(Note: The exact structure depends on the `RegisterRequest` DTO defined in the `CoreIdent.Core` endpoints implementation.)*

*   **Responses:**
    *   `201 Created`: User successfully registered. Body is typically empty.
    *   `400 Bad Request`: Invalid input (missing fields, invalid email format, weak password if validated before hashing). Body usually contains validation error details.
    *   `409 Conflict`: A user with the provided email already exists. Body might be empty or contain a simple error message.
    *   `500 Internal Server Error`: An unexpected error occurred during processing (e.g., failure interacting with the store, hashing error).

**Key Components:**

*   **`IPasswordHasher`:** This service is responsible **only** for hashing the password securely before storage and verifying a provided password against a stored hash during login. It ensures that plain-text passwords are never stored. See Section 5 for more details.
*   **`IUserStore`:** This service acts as an abstraction layer for user persistence. The `/register` endpoint uses it to check for existing users (`FindByUsernameAsync` or similar) and to save the new user (`CreateAsync`). In Phase 1, the default `InMemoryUserStore` provides this functionality without needing a database. See Section 6 for more details.

### 3. User Login (`/auth/login`)

The `POST /auth/login` endpoint allows registered users to authenticate themselves and receive access and refresh tokens, enabling them to access protected resources.

**Login Flow:**

1.  **Client Request:** The client sends an HTTP POST request to the `/auth/login` endpoint with the user's credentials (typically email and password) in the JSON request body.
2.  **Input Validation:** The incoming `LoginRequest` DTO is validated. Checks ensure required fields (email, password) are present. If validation fails, a `400 Bad Request` is returned.
3.  **Find User:** The endpoint uses the injected `IUserStore` service, calling a method like `FindByUsernameAsync` (using the provided email), to retrieve the corresponding user account. If no user is found with that email, a `401 Unauthorized` response is returned. It's crucial *not* to indicate whether the username was wrong or the password was wrong to prevent user enumeration attacks.
4.  **Verify Password:** If a user *is* found, the endpoint retrieves the stored password hash for that user via the `IUserStore`. It then uses the injected `IPasswordHasher` service's `VerifyHashedPassword` method, passing the stored hash and the plain-text password provided in the request. This method securely compares the provided password against the stored hash.
5.  **Handle Incorrect Password:** If `VerifyHashedPassword` indicates the password does not match, a `401 Unauthorized` response is returned. Again, the specific reason (user not found vs. wrong password) should not be distinguishable by the client response. *(Optional: Implementations might increment an access failed count here for lockout policies, planned for Phase 2 interface refinements)*.
6.  **Generate Tokens:** If the password verification is successful, the user is authenticated. The endpoint now calls the injected `ITokenService` (specifically, the `GenerateAccessTokenAsync` and `GenerateAndStoreRefreshTokenAsync` methods), passing the authenticated `CoreIdentUser` object.
7.  **Token Service Logic:** The `JwtTokenService` (default) generates a signed JWT access token containing standard claims (`iss`, `aud`, `sub`, `exp`, etc.) and potentially user-specific claims fetched from the user object. It also generates a refresh token handle.
8.  **Store Refresh Token:** The `JwtTokenService` calls the injected `IRefreshTokenStore`'s `StoreRefreshTokenAsync` method to persist the refresh token details (including its *hashed* handle). See Section 7 and 8 for details on persistence.
9.  **Success Response:** A `200 OK` response is returned to the client. The response body contains the generated `AccessToken`, the **raw** `RefreshToken` handle, and the `ExpiresIn` value (lifetime of the access token in seconds) for the client's convenience.

**Request/Response:**

*   **Request (`POST /auth/login`):**
    *   Method: `POST`
    *   Content-Type: `application/json`
    *   Body (Example DTO - `LoginRequest`):
        ```json
        {
          "email": "test@example.com",
          "password": "YourStrongPassword123!"
        }
        ```
*   **Responses:**
    *   `200 OK`: Login successful. Body contains tokens.
        ```json
        {
          "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
          "refresh_token": "aBcDeFgHiJkLmNoPqRsTuVwXyZ123456...", // Raw Handle
          "expires_in": 900, // Access token lifetime in seconds (e.g., 15 minutes)
          "token_type": "Bearer"
        }
        ```
        *(Note: The exact structure depends on the `TokenResponse` DTO defined.)*
    *   `400 Bad Request`: Invalid input (missing fields).
    *   `401 Unauthorized`: Authentication failed (user not found OR password incorrect). Body should ideally be empty or contain a generic error message.
    *   `500 Internal Server Error`: An unexpected error occurred during processing (e.g., failure storing refresh token).

**Key Components:**

*   **`IUserStore`:** Used to find the user by their identifier (email/username) and retrieve their details, including the stored password hash.
*   **`IPasswordHasher`:** Crucial for securely verifying the user-provided password against the stored hash without ever exposing the hash or the original password.
*   **`ITokenService`:** Responsible for generating the access (JWT) and refresh tokens once the user has been successfully authenticated. It encapsulates the logic for claims, signing, and lifetimes based on `CoreIdentOptions`. It also coordinates storing the refresh token details via `IRefreshTokenStore`.
*   **`IRefreshTokenStore`:** Responsible for persisting refresh token data securely.

### 4. Token Basics (JWTs & Refresh Tokens)

Tokens are central to how CoreIdent manages authenticated sessions and authorizes access to resources. Phase 1 introduces JWT Access Tokens and a basic implementation of Refresh Tokens.

**Access Tokens (JWT - JSON Web Token):**

An Access Token is a credential that proves the user has successfully authenticated and grants them permission (authorization) to access specific resources (like your API endpoints) for a limited time. CoreIdent uses the industry-standard JWT format for access tokens.

*   **What is a JWT?** A JWT is a compact, URL-safe means of representing claims between two parties. It's essentially a self-contained JSON object that is digitally signed (and optionally encrypted, though CoreIdent uses signed tokens by default). Because it's signed, the recipient (your API) can verify its authenticity and integrity without needing to call back to the authentication server (CoreIdent) on every request.
*   **Structure:** A JWT consists of three parts separated by dots (`.`):
    1.  **Header:** Contains metadata about the token, such as the token type (`typ`: "JWT") and the signing algorithm used (`alg`: e.g., "HS256" - HMAC SHA-256, the default in Phase 1). Encoded in Base64Url.
        ```json
        { "alg": "HS256", "typ": "JWT" }
        ```
    2.  **Payload:** Contains the "claims" – statements about the user (the "subject") and metadata about the token itself. Encoded in Base64Url.
        ```json
        {
          "sub": "user-guid-or-id", // Subject (the user ID)
          "iss": "https://localhost:7123", // Issuer (from CoreIdentOptions)
          "aud": "https://localhost:7123", // Audience (from CoreIdentOptions)
          "exp": 1678886400, // Expiration Time (Unix timestamp)
          "iat": 1678885500, // Issued At Time (Unix timestamp)
          "jti": "guid-unique-token-id", // JWT ID (unique identifier for the token)
          // -- Optional user-specific claims --
          "name": "Test User", // Example user name claim
          "email": "test@example.com" // Example email claim
        }
        ```
        *   **Standard Claims:** CoreIdent includes standard registered claims like `iss` (Issuer), `sub` (Subject), `aud` (Audience), `exp` (Expiration Time), `iat` (Issued At), and `jti` (JWT ID).
        *   **Custom Claims:** It can also include user-specific claims based on the user's profile stored in the `IUserStore`.
    3.  **Signature:** Created by taking the encoded header, the encoded payload, the secret (`SigningKeySecret` from `CoreIdentOptions`), and signing them with the algorithm specified in the header (`HS256`). This signature verifies that the sender is who they say they are and that the message wasn't changed along the way.
        `HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), secret)`
*   **Generation (`JwtTokenService`):** The default `ITokenService` implementation, `JwtTokenService`, uses the `System.IdentityModel.Tokens.Jwt` library. It reads the `Issuer`, `Audience`, `SigningKeySecret`, and `AccessTokenLifetime` from the configured `CoreIdentOptions` to construct and sign the JWT.
*   **Usage:** Clients should send the Access Token in the `Authorization` header of HTTP requests to protected resources, using the `Bearer` scheme:
    ```
    Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
    ```
    ASP.NET Core middleware (like `AddJwtBearer()`) can then automatically validate this token (check signature, expiry, issuer, audience) and populate the `User` principal for the request.

**Refresh Tokens:**

Access tokens are intentionally short-lived for security. When an access token expires, the user would need to log in again, which is inconvenient. Refresh tokens solve this problem.

*   **Purpose:** A refresh token is a special, longer-lived credential that clients can use to obtain a *new* access token (and potentially a new refresh token) without requiring the user to re-enter their password.
*   **Generation:** The `JwtTokenService` generates a refresh token handle (a cryptographically secure random string).
*   **Storage:** The *details* of the refresh token (including a **hashed version** of the handle, user ID, client ID, expiry, etc.) are persisted using the `IRefreshTokenStore`. The **raw handle** is returned to the client.
*   **The `/auth/token/refresh` Endpoint:**
    1.  **Client Request:** When an access token expires, the client sends a POST request to `/auth/token/refresh` with the *raw refresh token handle* it previously received.
        ```json
        { "refreshToken": "aBcDeFgHiJkLmNoPqRsTuVwXyZ123456..." }
        ```
    2.  **Validation:** The endpoint calls `IRefreshTokenStore.GetRefreshTokenAsync(rawHandle)` to retrieve the token details by its **raw handle** (looking it up via the `Handle` primary key column).
    3.  The store checks if the token exists, if it has expired (`ExpirationTime`), and if it has already been used (`ConsumedTime`). If any check fails, it returns `401 Unauthorized`.
    4.  **Consumption:** If the token is valid and not consumed, it **must** be marked as consumed to prevent replay attacks. The store implementation sets the `ConsumedTime` via `IRefreshTokenStore.RemoveRefreshTokenAsync(rawHandle)`.
    5.  **Rotation:** A **new** `CoreIdentRefreshToken` is generated by the `ITokenService` (including generating a new raw handle and hashing it). If token family tracking is enabled (default), the new token is linked to the previous token's family.
    6.  **Store New Token:** The *new* refresh token (with its raw handle in `Handle` and hash in `HashedHandle`) is stored in the database via `StoreRefreshTokenAsync`.
    7.  **Response:** The new access token *and* the new *raw* refresh token handle are returned to the client.
*   **Security:** Refresh tokens are powerful credentials and must be stored securely by the client. They are rotated on each use (the old one is consumed, a new one is issued) to mitigate risks if a token is compromised. The **token theft detection** features (Phase 3) provide further security by monitoring for reuse of consumed tokens. See Section 7 for details on refresh token storage and handling.

### 5. Password Hashing (`IPasswordHasher`)

Storing user passwords securely is non-negotiable. CoreIdent leverages established best practices for password hashing to protect user credentials even if the underlying user data store is compromised.

**Why Hash Passwords?**

*   **Never Store Plain Text:** Storing passwords as plain text is extremely insecure. If your database is breached, attackers gain immediate access to all user passwords.
*   **Basic Hashing is Not Enough:** Simply using basic hashing algorithms like MD5 or SHA-1 is also insufficient. These algorithms are fast, making them vulnerable to "rainbow table" attacks (precomputed tables of hashes) and brute-force attacks.
*   **The Need for Strong Hashing:** Modern secure password hashing requires algorithms that are:
    *   **Slow:** Computationally expensive to slow down brute-force attempts.
    *   **Salted:** Use a unique random value (the "salt") for each password before hashing. This ensures that identical passwords result in different hashes, defeating rainbow tables.
    *   **Adaptive:** Often involve multiple rounds (iterations) of hashing, further increasing the computational cost.

**CoreIdent's Approach: `Microsoft.AspNetCore.Identity.PasswordHasher`**

CoreIdent, by default, utilizes the battle-tested `PasswordHasher<TUser>` implementation provided by ASP.NET Core Identity. This is a well-regarded and secure approach.

*   **Algorithm:** It uses the PBKDF2 (Password-Based Key Derivation Function 2) algorithm with HMAC-SHA256.
*   **Salting:** Automatically generates a unique, cryptographically secure 128-bit salt for each password when it's first hashed. This salt is then stored alongside the hash.
*   **Iterations:** Uses a configurable number of iterations (defaulting to 10,000 in .NET Core 3.x / .NET 5, and 100,000 in .NET 6+), making it computationally expensive for attackers.
*   **Format:** The final stored hash includes information about the format version, iteration count, salt, and the derived key (the actual hash), allowing the system to verify passwords even if algorithm parameters change over time.

**Interface: `IPasswordHasher`**

CoreIdent abstracts the hashing mechanism behind the `IPasswordHasher` interface. The default implementation (`DefaultPasswordHasher`) wraps the ASP.NET Core Identity hasher.

*   **`string HashPassword(CoreIdentUser user, string password)`:**
    *   Takes a `CoreIdentUser` object (though often not strictly needed by the default hasher, it's included for potential extensibility) and the plain-text `password`.
    *   Generates a salt, hashes the password using PBKDF2 with the salt and configured iterations.
    *   Returns a single string containing the format marker, iteration count, salt, and hash, ready for storage in the `IUserStore`.
*   **`PasswordVerificationResult VerifyHashedPassword(CoreIdentUser user, string hashedPassword, string providedPassword)`:**
    *   Takes the `CoreIdentUser`, the `hashedPassword` string retrieved from the `IUserStore`, and the plain-text `providedPassword` entered by the user during login.
    *   Parses the `hashedPassword` string to extract the format marker, iteration count, salt, and stored hash.
    *   Hashes the `providedPassword` using the *same* salt and iteration count retrieved from the stored hash.
    *   Compares the newly generated hash with the stored hash.
    *   Returns a `PasswordVerificationResult` enum:
        *   `Success`: The passwords match.
        *   `Failed`: The passwords do not match.
        *   `SuccessRehashNeeded`: The passwords match, but the stored hash used older parameters (e.g., lower iteration count). This signals that the hash should ideally be updated using the latest parameters for better security (though CoreIdent's Phase 1 doesn't automatically handle rehashing).

**Key Takeaway:** CoreIdent relies on a strong, standard password hashing implementation out-of-the-box, ensuring passwords are not stored in a recoverable format. The `IPasswordHasher` interface provides the necessary abstraction for this critical security component.

### 6. Storage Abstraction (`IUserStore`, `IRefreshTokenStore`, etc.)

To facilitate rapid development, testing, and provide a functional Minimum Viable Product (MVP) without external dependencies like databases, CoreIdent includes default in-memory storage implementations for Phase 1.

**Purpose:**

*   **Quick Start:** Allows developers to get CoreIdent running quickly without setting up a database.
*   **Testing:** Useful for integration tests where a persistent state between test runs isn't required or desired.
*   **MVP:** Provides the basic functionality needed for the initial core features (`/register`, `/login`, `/token/refresh`) to work end-to-end.

**The `InMemoryUserStore`:**

*   **Implementation:** This is the default implementation registered for the `IUserStore` interface when you call `AddCoreIdent()`. Internally, it typically uses a `ConcurrentDictionary<string, CoreIdentUser>` (or similar thread-safe collection) to store `CoreIdentUser` objects, keyed by the user's ID or normalized username.
*   **Functionality:** It implements the essential methods of the `IUserStore` interface required for Phase 1 flows:
    *   `CreateAsync(CoreIdentUser user)`: Adds a new user to the dictionary.
    *   `FindByUsernameAsync(string normalizedUsername)`: Looks up a user by their normalized username (usually email).
    *   `FindByIdAsync(string userId)`: Looks up a user by their ID.
    *   `GetPasswordHashAsync(CoreIdentUser user)`: Retrieves the stored password hash for a given user object.
    *   `SetPasswordHashAsync(CoreIdentUser user, string passwordHash)`: Updates the password hash for a given user object (primarily used during registration).
    *   *(Note: Methods like `UpdateUserAsync` and `DeleteUserAsync` also exist in the interface and are implemented, allowing user updates/deletions within the in-memory store, as reflected in recent test refactoring).*
*   **Interface:** By implementing `IUserStore`, the rest of the CoreIdent system (like the endpoints) interacts with user storage through this abstraction, unaware of the specific in-memory implementation details.

**Limitations:**

*   **VOLATILITY:** This is the most significant limitation. **All data stored in `InMemoryUserStore` is lost when the application process stops or restarts.** It's purely transient storage residing in the application's memory.
*   **Scalability:** Not suitable for multi-instance deployments, as each instance would have its own separate, inconsistent user store.
*   **No Refresh Token Persistence:** Similarly, Phase 1 lacks a dedicated, persistent `IRefreshTokenStore`. While the `/token/refresh` endpoint exists, validating and managing refresh tokens reliably requires persistent storage (introduced in Phase 2). The simple refresh tokens generated in Phase 1 have limited practical use without a proper backing store.

**Key Takeaway:** The in-memory stores provide a convenient starting point but are **unsuitable for production environments** due to their volatility. They serve to demonstrate the core authentication flows and facilitate testing. Replacing the `InMemoryUserStore` with a persistent implementation (like the EF Core store in Phase 2) is a crucial step for real-world applications.

CoreIdent defines several storage interfaces to abstract persistence concerns:

*   **`IUserStore`:** Handles CRUD operations for `CoreIdentUser` objects, including finding users by ID or username, managing claims, and password hash storage/retrieval.
*   **`IRefreshTokenStore`:** Handles CRUD operations for `CoreIdentRefreshToken` objects. This becomes critical in Phase 2 for managing refresh token lifecycles, consumption, and rotation.
*   **`IClientStore`:** (Introduced conceptually for Phase 3+) Handles CRUD operations for OAuth 2.0/OIDC client applications (`CoreIdentClient`). Clients are applications (web apps, mobile apps, SPAs, APIs) that request tokens from CoreIdent.
*   **`IScopeStore`:** (Introduced conceptually for Phase 3+) Handles CRUD operations for OAuth 2.0/OIDC scopes (`CoreIdentScope`). Scopes represent permissions or resources that clients can request access to (e.g., `profile`, `email`, `api.read`).

**Key Takeaway:** The store interfaces define the contract for how CoreIdent interacts with persisted data. Phase 1 provided a simple in-memory implementation primarily for `IUserStore`. Phase 2 introduces robust EF Core implementations for `IUserStore` and `IRefreshTokenStore`.

## Phase 2: Persistence & Extensibility

This section delves into the significant enhancements introduced in Phase 2, moving beyond volatile in-memory storage to persistent solutions and providing adaptable integration paths.

### 7. Persistence with Entity Framework Core

While the in-memory stores are useful for getting started, real-world applications require data to persist across restarts and scale effectively. Phase 2 introduces first-class support for persistence using **Entity Framework Core (EF Core)**, Microsoft's recommended object-relational mapper (ORM) for .NET.

**Why EF Core?**

*   **Database Agnostic:** EF Core supports various database providers (SQL Server, PostgreSQL, SQLite, MySQL, Cosmos DB, etc.), allowing you to choose the backend that best suits your needs.
*   **Developer Productivity:** It simplifies data access by allowing developers to work with .NET objects instead of writing raw SQL, handling mapping, change tracking, and migrations.
*   **Integration:** It integrates deeply with ASP.NET Core dependency injection and configuration.

**Key Components (`CoreIdent.Storage.EntityFrameworkCore`):**

To keep the core library lean, all EF Core-specific code resides in a separate NuGet package: `CoreIdent.Storage.EntityFrameworkCore`.

1.  **`CoreIdentDbContext`:**
    *   This is the heart of the EF Core integration. It inherits from `Microsoft.EntityFrameworkCore.DbContext`.
    *   It defines `DbSet<>` properties for each CoreIdent entity that needs to be persisted (e.g., `public DbSet<CoreIdentUser> Users { get; set; }`, `public DbSet<CoreIdentRefreshToken> RefreshTokens { get; set; }`).
    *   The `OnModelCreating(ModelBuilder modelBuilder)` method is overridden to configure the database schema using EF Core's Fluent API. This includes defining primary keys (e.g., `refreshToken.HasKey(rt => rt.Handle)`), relationships, indexes, and constraints.
    *   **Important:** Your application's main `DbContext` should either **inherit from `CoreIdentDbContext`** or **call its configuration logic** within its own `OnModelCreating` to ensure the CoreIdent tables are correctly set up. There are two primary ways to achieve this:

        1.  **Inheritance (Simplest):** Your `DbContext` inherits directly from `CoreIdentDbContext`.
            ```csharp
            // In YourApplicationDbContext.cs
            using CoreIdent.Storage.EntityFrameworkCore;
            using Microsoft.EntityFrameworkCore;
            
            public class YourApplicationDbContext : CoreIdentDbContext // Inherit here
            {
                // Your application's specific DbSets
                public DbSet<YourAppEntity> YourAppEntities { get; set; }
            
                public YourApplicationDbContext(DbContextOptions<YourApplicationDbContext> options)
                    : base(options) // Pass options to base constructor
                {
                }
            
                protected override void OnModelCreating(ModelBuilder modelBuilder)
                {
                    // IMPORTANT: Call base implementation FIRST to apply CoreIdent configs
                    base.OnModelCreating(modelBuilder);
            
                    // Your application's specific entity configurations below
                    modelBuilder.Entity<YourAppEntity>().HasKey(e => e.Id);
                    // ... other configurations ...
                }
            }
            ```

        2.  **Applying Configurations (More Flexible):** Your `DbContext` inherits from the standard `Microsoft.EntityFrameworkCore.DbContext` and explicitly applies CoreIdent's configurations within its `OnModelCreating` method.
            ```csharp
            // In YourApplicationDbContext.cs
            using CoreIdent.Storage.EntityFrameworkCore; // Needed for CoreIdentDbContext type
            using Microsoft.EntityFrameworkCore;
            
            public class YourApplicationDbContext : DbContext // Inherit from standard DbContext
            {
                // Your application's specific DbSets
                public DbSet<YourAppEntity> YourAppEntities { get; set; }
            
                // CoreIdent DbSets are optional here unless you need direct access
                // public DbSet<CoreIdentUser> Users { get; set; }
            
                public YourApplicationDbContext(DbContextOptions<YourApplicationDbContext> options)
                    : base(options)
                {
                }
            
                protected override void OnModelCreating(ModelBuilder modelBuilder)
                {
                    base.OnModelCreating(modelBuilder); 
            
                    // Apply CoreIdent's configurations from its assembly
                    modelBuilder.ApplyConfigurationsFromAssembly(typeof(CoreIdentDbContext).Assembly);
            
                    // Your application's specific entity configurations below
                    modelBuilder.Entity<YourAppEntity>().HasKey(e => e.Id);
                    // ... other configurations ...
                }
            }
            ```

2.  **EF Core Store Implementations:**
    *   This package provides concrete implementations of the store interfaces from `CoreIdent.Core`:
        *   `EfUserStore`: Implements `IUserStore`. Uses the injected `CoreIdentDbContext` to perform LINQ queries (e.g., `_context.Users.FirstOrDefaultAsync(...)`) and save changes (`_context.SaveChangesAsync()`).
        *   `EfRefreshTokenStore`: Implements `IRefreshTokenStore`. Similarly uses the `DbContext` to manage `CoreIdentRefreshToken` entities.
        *   `EfClientStore`: Implements `IClientStore`.
        *   `EfScopeStore`: Implements `IScopeStore`.
        *   **`EfAuthorizationCodeStore`: Implements `IAuthorizationCodeStore` for persistent storage of authorization codes.**
            *   Authorization codes issued during OAuth flows are stored in the `AuthorizationCodes` table.
            *   The store implementation includes robust concurrency handling to prevent race conditions during code redemption and cleanup.
            *   **Expired codes are automatically cleaned up** by a background service (`AuthorizationCodeCleanupService`) that runs periodically (by default, every hour).
            *   This service is registered automatically when you use `AddCoreIdentEntityFrameworkStores` (can be disabled via parameter if needed).
            *   You do not need to manually remove expired codes; the service handles this for you.

3.  **DI Registration Extension (`AddCoreIdentEntityFrameworkStores<TContext>`):**
    *   To switch from the default in-memory stores to EF Core, you use the `AddCoreIdentEntityFrameworkStores<TContext>()` extension method provided in this package.
    *   **Usage:**
        ```csharp
        var builder = WebApplication.CreateBuilder(args);

        // 1. Register CoreIdent Core services (AFTER configuring options)
        builder.Services.AddCoreIdent(options => /* ... configure options ... */);

        // 2. Register YOUR application's DbContext (using your chosen provider)
        var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
        builder.Services.AddDbContext<YourApplicationDbContext>(options =>
            options.UseSqlite(connectionString)); // Or UseSqlServer, UseNpgsql, etc.

        // 3. Register the CoreIdent EF Core stores, pointing to YOUR DbContext
        //    (YourApplicationDbContext MUST incorporate CoreIdentDbContext's configuration)
        builder.Services.AddCoreIdentEntityFrameworkStores<YourApplicationDbContext>();

        var app = builder.Build();
        // ... rest of Program.cs
        ```
    *   **How it works:** This extension method removes any existing registrations for `IUserStore`, `IRefreshTokenStore`, etc., and registers the EF Core implementations (`EfUserStore`, `EfRefreshTokenStore`) with a **Scoped** lifetime. It relies on the `TContext` (your `DbContext`) already being registered in the DI container.

**Migrations:**

Once you configure EF Core, you need to manage your database schema using **EF Core Migrations**.

1.  **Install Tools:** Ensure you have the EF Core command-line tools installed (`dotnet tool install --global dotnet-ef`).
2.  **Add Migration:** From your terminal, navigate to the directory containing your *startup project's* `.csproj` file (usually your web application). Then, run the migration command, specifying the project containing your `DbContext` and the project containing `CoreIdentDbContext` configuration (if they are different).

    *   **If your `DbContext` is in your startup project (e.g., `MyWebApp.csproj`):**
        ```bash
        # -p: Points to the project containing CoreIdent's EF Core configuration
        # -s: Points to the startup project (implicitly the current directory if run from there)
        # --context: Specifies YOUR DbContext class name
        dotnet ef migrations add InitialCoreIdentSchema --context YourApplicationDbContext -p ../path/to/src/CoreIdent.Storage.EntityFrameworkCore
        ```
    *   **If your `DbContext` is in a separate project (e.g., `MyDataAccess.csproj`):**
        ```bash
        # Assume you are running this from the root solution directory or the startup project directory
        # -p: Points to the project containing YOUR DbContext
        # -s: Points to the startup project (e.g., your web app)
        # --context: Specifies YOUR DbContext class name
        # The command needs access to both YourDbContext and CoreIdentDbContext configurations.
        # Ensure your DbContext project references CoreIdent.Storage.EntityFrameworkCore
        # Ensure your Startup project references your DbContext project.
        dotnet ef migrations add InitialCoreIdentSchema --project src/MyDataAccess/MyDataAccess.csproj --startup-project src/MyWebApp/MyWebApp.csproj --context YourApplicationDbContext
        ```
    *   Replace `InitialCoreIdentSchema` with a descriptive name.
    *   Replace `YourApplicationDbContext` with the name of *your* `DbContext`.
    *   Replace the paths (`../path/to/src/CoreIdent.Storage.EntityFrameworkCore`, `src/MyDataAccess/MyDataAccess.csproj`, `src/MyWebApp/MyWebApp.csproj`) with the actual relative paths from where you are running the command.
    *   This command generates C# migration files in a `Migrations` folder within the project specified by `-p` (or the startup project if `-p` isn't used and the context is there).

3.  **Apply Migration:** To apply the changes to your database, run (usually from the startup project directory):
    ```bash
    # Ensure the --context matches the one used for adding the migration
    # The --startup-project (-s) and --project (-p) might be needed if running from a different directory,
    # similar to the 'add' command, to ensure the correct configuration and connection string are found.
    dotnet ef database update --context YourApplicationDbContext
    ```
    This connects to the database specified in your startup project's configuration (e.g., `appsettings.json`) and executes the necessary SQL.

**Refresh Token Handling with Persistence:**

1.  **Handle Hashing & Storage:** When a user logs in, the `JwtTokenService` generates a raw, random handle. It hashes this handle (using `TokenHasher` with user ID and client ID as salt) and creates a `CoreIdentRefreshToken` entity. The **raw handle** is stored in the `Handle` property (used as the primary key) and the **hashed handle** is stored in the `HashedHandle` property. This entity is saved via `IRefreshTokenStore.StoreRefreshTokenAsync`. The **raw handle** is returned to the client.
2.  **Validation (`/auth/token/refresh`):**
    *   The endpoint receives the **raw** refresh token handle from the client.
    *   It calls `IRefreshTokenStore.GetRefreshTokenAsync(rawHandle)` to retrieve the token details by its **raw handle** (looking it up via the `Handle` primary key column).
    *   The store checks if the token exists, if it has expired (`ExpirationTime`), and if it has already been used (`ConsumedTime`). If any check fails, it returns `401 Unauthorized`.
    *   **Token Theft Detection (Enabled by Default):** By default (`EnableTokenFamilyTracking = true`), if a *consumed* token is presented (`ConsumedTime != null`), the system triggers a security response (e.g., `RevokeFamily` to invalidate all related tokens) based on the configured `TokenTheftDetectionMode`. This behavior can be disabled by setting `EnableTokenFamilyTracking = false` in the configuration. Note that because the `RevokeFamily` strategy revokes all *active* tokens in the family upon detection, attempting to use a new token immediately after deliberately reusing an old one (as done in some tests) will result in an Unauthorized response for the new token as well.
3.  **Consumption:** If the token is valid and not consumed, it **must** be marked as consumed to prevent replay attacks. The store implementation sets the `ConsumedTime` via `IRefreshTokenStore.RemoveRefreshTokenAsync(rawHandle)`.
4.  **Rotation:** A **new** `CoreIdentRefreshToken` is generated by the `ITokenService` (including generating a new raw handle and hashing it). If token family tracking is enabled (default), the new token is linked to the previous token's family.
5.  **Store New Token:** The *new* refresh token (with its raw handle in `Handle` and hash in `HashedHandle`) is stored in the database via `StoreRefreshTokenAsync`.
6.  **Response:** The new access token *and* the new *raw* refresh token handle are returned to the client.

This **Refresh Token Rotation** strategy is crucial for security. Each refresh token can only be used once. The default enabled **token family tracking** provides additional protection by invalidating an entire chain of tokens if one is compromised and reused.

### 8. Delegated User Store: Integrating Existing Systems

What if you already have an existing user database or identity system and don't want to migrate users into CoreIdent's storage?

The `CoreIdent.Adapters.DelegatedUserStore` package provides a solution.

**Concept:**

Instead of implementing `IUserStore` to directly interact with a database, the `DelegatedUserStore` takes **functions (delegates)** as configuration. These functions contain *your* logic to interact with *your* existing user system.

**How it Works:**

1.  **Install:** `dotnet add package CoreIdent.Adapters.DelegatedUserStore`
2.  **Configure:** Instead of calling `AddCoreIdentEntityFrameworkStores`, you call `AddCoreIdentDelegatedUserStore` after `AddCoreIdent`:

    ```csharp
    builder.Services.AddCoreIdentDelegatedUserStore(options =>
    {
        // REQUIRED: Provide a function to find a user by ID
        options.FindUserByIdAsync = async (userId, ct) => {
            // Your logic using your service/repository to find the user
            var externalUser = await myExternalUserService.FindByIdAsync(userId);
            if (externalUser == null) return null;
            // Map YOUR user model to CoreIdentUser (excluding password hash)
            return new CoreIdentUser { Id = externalUser.Id, UserName = externalUser.Email, ... };
        };

        // REQUIRED: Provide a function to find a user by username
        options.FindUserByUsernameAsync = async (normalizedUsername, ct) => {
            var externalUser = await myExternalUserService.FindByUsernameAsync(normalizedUsername);
            if (externalUser == null) return null;
            return new CoreIdentUser { Id = externalUser.Id, UserName = externalUser.Email, ... };
        };

        // REQUIRED: Provide a function to validate credentials
        // !! IMPORTANT: This delegate receives the PLAIN TEXT password submitted by the user.
        // !! Your external service MUST handle the secure validation against its stored credentials.
        options.ValidateCredentialsAsync = async (username, password, ct) => {
             // Your logic: Call your service to check the password
             return await myExternalUserService.CheckPasswordAsync(username, password);
        };

        // OPTIONAL: Provide a function to get user claims
        options.GetClaimsAsync = async (coreIdentUser, ct) => {
            // Your logic: Get claims for the user ID from your system
            var externalClaims = await myExternalUserService.GetUserClaimsAsync(coreIdentUser.Id);
            // Map to System.Security.Claims.Claim
            return externalClaims.Select(c => new Claim(c.Type, c.Value)).ToList();
        };
    });
    ```
3.  **CoreIdent Interaction:** When CoreIdent needs user information (e.g., during login), it calls the appropriate method on the registered `IUserStore`. Since `DelegatedUserStore` is registered, it executes the corresponding delegate function you provided, effectively bridging CoreIdent to your existing system.

**Important Considerations:**

*   **Password Validation:** 
    > [!WARNING]
    > **CRITICAL SECURITY RESPONSIBILITY**: The `ValidateCredentialsAsync` delegate receives the user's **plain text password** entered during login. 
    > 
    > *   Your implementation of this delegate **MUST** securely validate this plain text password against your existing credential store.
    > *   Your external system **MUST** store passwords securely using a strong, salted hashing algorithm (like Argon2id or PBKDF2).
    > *   **CoreIdent's `IPasswordHasher` is completely bypassed** in this flow. The security of password checking rests entirely on your delegate's implementation.
    > *   Failure to handle this correctly represents a major security vulnerability.
*
*   **Mapping:** You are responsible for mapping your external user model to the `CoreIdentUser` model within the `FindUser...` delegates. Only map necessary properties like `Id` and `UserName`. **Do not map password hashes.**
*   **Write Operations:** The `DelegatedUserStore` intentionally does **not** implement user creation, update, or deletion methods (`CreateAsync`, `UpdateAsync`, `DeleteAsync`). These operations should be handled directly within your existing user management system.

This adapter allows you to leverage CoreIdent's token generation and endpoint features while keeping your user source-of-truth separate.

**Configuration Deep Dive (`AddCoreIdentDelegatedUserStore`):**

Let's break down the configuration process further:

```csharp
    builder.Services.AddCoreIdentDelegatedUserStore(options =>
    {
        // REQUIRED Delegates:
        options.FindUserByIdAsync = ... // Your logic here
        options.FindUserByUsernameAsync = ... // Your logic here
        options.ValidateCredentialsAsync = ... // Your logic here

        // OPTIONAL Delegates:
        options.GetClaimsAsync = ... // Optional: Your logic here
        // Other IUserStore methods like GetUserIdAsync, GetUsernameAsync,
        // GetNormalizedUserNameAsync have default implementations in DelegatedUserStore
        // that work directly off the CoreIdentUser object returned by FindUser... methods.
        // You generally don't need to override these unless you have specific needs.
    });
```
*   **Registration:** This extension method registers `DelegatedUserStore` as the implementation for `IUserStore` with a **Scoped** lifetime, replacing any previously registered `IUserStore` (like `InMemoryUserStore` or `EfUserStore`).
*   **Options Validation:** The options object includes validation (`IValidateOptions<DelegatedUserStoreOptions>`) that runs on startup. It checks if the *required* delegates (`FindUserByIdAsync`, `FindUserByUsernameAsync`, `ValidateCredentialsAsync`) have been provided. If any are missing, the application will fail to start, ensuring the adapter is configured correctly.
*   **Delegate Execution:** When an endpoint (like `/login`) needs to interact with the `IUserStore`, the dependency injection system provides the registered `DelegatedUserStore` instance. When a method like `FindByUsernameAsync` is called on this instance, it internally invokes the specific `Func<>` delegate that you assigned to `options.FindUserByUsernameAsync` during configuration.

**Mapping `CoreIdentUser`:**

It's crucial to correctly map your external user object to `CoreIdentUser` within the `FindUserByIdAsync` and `FindUserByUsernameAsync` delegates. CoreIdent relies on properties of this object later in the pipeline (e.g., the `ITokenService` uses `user.Id` and `user.UserName` for default claims).

```csharp
options.FindUserByUsernameAsync = async (normalizedUsername, ct) => {
    var externalUser = await myExternalUserService.FindByUsernameAsync(normalizedUsername);
    if (externalUser == null) return null;

    // Create and populate the CoreIdentUser
    return new CoreIdentUser {
        Id = externalUser.ExternalSystemId, // Map your unique ID
        UserName = externalUser.PrimaryEmail, // Map the username/email used for login
        NormalizedUserName = externalUser.PrimaryEmail?.ToUpperInvariant(), // Provide the normalized version if possible
        // Other properties like LockoutEnabled, AccessFailedCount could be mapped if relevant
        // --- DO NOT MAP A PASSWORD HASH --- CoreIdent relies on ValidateCredentialsAsync
    };
};
```

**Workflow Example (`/auth/login`):**

1.  User POSTs to `/auth/login` with email and password.
2.  CoreIdent endpoint receives the request.
3.  It requests `IUserStore` from DI, receiving the `DelegatedUserStore` instance.
4.  It calls `userStore.FindByUsernameAsync(normalizedEmail)`.
5.  `DelegatedUserStore` executes *your* `options.FindUserByUsernameAsync` delegate.
6.  Your delegate queries your external system and returns a mapped `CoreIdentUser` (or null).
7.  If a user is found, the endpoint calls `userStore.ValidateCredentialsAsync(normalizedEmail, password)`.
8.  `DelegatedUserStore` executes *your* `options.ValidateCredentialsAsync` delegate.
9.  Your delegate validates the plain-text password against your external system and returns `true` or `false`.
10. If `true`, the endpoint requests `ITokenService`.
11. It calls `tokenService.GenerateAccessTokenAsync(coreIdentUser)`.
12. `JwtTokenService` calls `userStore.GetClaimsAsync(coreIdentUser)`.
13. `DelegatedUserStore` executes *your* optional `options.GetClaimsAsync` delegate (or uses default claims).
14. `JwtTokenService` generates the token with claims.
15. Tokens are returned to the user.

This flow clearly shows how the adapter acts as a bridge, invoking your custom logic at the appropriate points.

**Testing Setup Note:** When writing integration tests involving database interactions (like testing refresh token storage or EF Core stores), it's crucial to ensure the database is correctly configured and migrations are applied *before* the test logic runs. A common pattern using `WebApplicationFactory` is to configure the `DbContext` (often with an in-memory provider like SQLite with `cache=shared`) and run `dbContext.Database.Migrate()` within the `ConfigureServices` block of a custom `WebApplicationFactory` or using `WithWebHostBuilder` within the test class itself. This ensures the database schema is ready for the test execution.

## Troubleshooting & FAQ: Dependency Injection, EF Core Migrations, and Real-World Pitfalls

Setting up CoreIdent with EF Core is straightforward, but real-world projects and development environments can introduce subtle issues. This section provides a thorough, readable guide to help you avoid and resolve common problems.

### Why Does DI Registration Order Matter?

**Dependency Injection (DI) in ASP.NET Core is order-sensitive.**

- `AddCoreIdent()` registers the core services and default (in-memory) stores.
- `AddDbContext<YourDbContext>()` registers your EF Core context in the DI container.
- `AddCoreIdentEntityFrameworkStores<YourDbContext>()` replaces the in-memory stores with EF Core-backed implementations, which depend on your DbContext being registered first.

If you call `AddCoreIdentEntityFrameworkStores` before `AddDbContext`, the EF Core stores will not be able to resolve the context and will fail at runtime.

> **Tip:** Always follow this order in your `Program.cs`:
> 1. `AddCoreIdent()`
> 2. `AddDbContext<YourDbContext>()`
> 3. `AddCoreIdentEntityFrameworkStores<YourDbContext>()`

### Common Errors and Solutions

| Error Message or Symptom | Likely Cause | Solution |
|-------------------------|--------------|----------|
| `No service for type 'YourDbContext' has been registered.` | `AddDbContext` was not called before `AddCoreIdentEntityFrameworkStores`. | Register your DbContext *before* the EF Core stores. |
| `Table 'Users'/'RefreshTokens' does not exist` or similar DB errors | EF Core migrations have not been applied. | Run the migration commands (see below). |
| `Cannot access a disposed object` (with SQLite in-memory) | SQLite connection was closed/disposed before test completed. | Keep the SQLite connection open for the test host's lifetime. |
| `The entity type 'X' requires a primary key` | Your DbContext does not inherit from `CoreIdentDbContext` or does not apply its configurations. | Inherit from `CoreIdentDbContext` or call `ApplyConfigurationsFromAssembly(typeof(CoreIdentDbContext).Assembly)` in `OnModelCreating`. |
| `The model backing the 'YourDbContext' context has changed since the database was created` | Database schema is out of sync with your model. | Re-run migrations or delete/recreate the dev/test database. |
| `Migrations are not applied in production` | Database was not updated after deployment. | Ensure `dotnet ef database update` is run as part of your deployment process. |

### Step-by-Step EF Core Migration Checklist

1. **Install EF Core CLI tools (if not already):**
   ```bash
   dotnet tool install --global dotnet-ef
   ```
2. **Add a migration:**
   ```bash
   dotnet ef migrations add InitialCoreIdentSchema --context YourApplicationDbContext --project src/CoreIdent.Storage.EntityFrameworkCore --startup-project src/YourWebAppProject -o Data/Migrations
   ```
   - Replace `YourApplicationDbContext` with your DbContext class name.
   - Adjust `--project` and `--startup-project` paths as needed.
   - The `-o` parameter specifies the output directory for migration files.
3. **Apply the migration:**
   ```bash
   dotnet ef database update --context YourApplicationDbContext --project src/CoreIdent.Storage.EntityFrameworkCore --startup-project src/YourWebAppProject
   ```
   - This updates your database schema to match your model.
4. **Verify the database:**
   - Check that tables like `Users`, `RefreshTokens`, `Clients`, and `Scopes` exist in your database.
   - If using SQLite, you can use tools like [DB Browser for SQLite](https://sqlitebrowser.org/) to inspect the file.
5. **Automate for CI/CD:**
   - Add migration and update steps to your deployment pipeline to avoid production drift.

### Sample Migration Output

When you run `dotnet ef migrations add InitialCoreIdentSchema`, you should see output similar to:
```
Build started...
Build succeeded.
To undo this action, use 'ef migrations remove'
Done. To undo this action, use 'ef migrations remove'
```
And after `dotnet ef database update`:
```
Build started...
Build succeeded.
Applying migration '20250413033857_InitialCoreIdentSchema'.
Done.
```

If you see errors, double-check your DI registration order and that your DbContext is correctly configured and referenced.

### Official Documentation and Further Reading

- [EF Core Migrations Guide (Microsoft Docs)](https://learn.microsoft.com/en-us/ef/core/managing-schemas/migrations/?tabs=dotnet-core-cli)
- [ASP.NET Core Dependency Injection Fundamentals](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/dependency-injection)
- [EF Core Design-Time DbContext Creation](https://learn.microsoft.com/en-us/ef/core/cli/dbcontext-creation)

### Real-World Tips and Scenarios

- **Multi-Project Solutions:**
  - If your `DbContext` is in a different project than your web app, use the `--project` and `--startup-project` flags to point to the correct locations.
  - Ensure all projects reference each other as needed (web app → storage project, storage project → CoreIdent.Core).

- **Test Setup with SQLite In-Memory:**
  - Keep the SQLite connection open for the entire test run (see integration test examples).
  - Always run `dbContext.Database.Migrate()` before executing tests to ensure the schema is present.

- **Production Deployments:**
  - Never use SQLite in-memory for production.
  - Always use a persistent, production-grade database (SQL Server, PostgreSQL, etc.).
  - Automate migrations as part of your deployment process.

- **DbContext Configuration:**
  - If you want to use your own `DbContext`, either inherit from `CoreIdentDbContext` or call `modelBuilder.ApplyConfigurationsFromAssembly(typeof(CoreIdentDbContext).Assembly)` in your `OnModelCreating` method. This ensures all CoreIdent tables and relationships are created.

- **Seeding Data:**
  - For development, you may want to seed default clients, scopes, or users. Do this after applying migrations, typically in a `using (var scope = app.Services.CreateScope())` block in your startup logic.

- **Debugging Migrations:**
  - If migrations fail, check for typos in class names, missing references, or misconfigured connection strings.
  - Use `dotnet ef migrations list` to see all applied and pending migrations.

- **Security Reminder:**
  - Never check secrets (like `SigningKeySecret`) or production connection strings into source control.
  - Use environment variables or a secret manager for production secrets.

---

## Phase 3: Core OAuth 2.0 / OIDC Server Mechanics

Phase 3 introduces the foundational server-side logic for standard OAuth 2.0 and OpenID Connect (OIDC) flows, enabling secure delegated authorization for various client applications (web apps, Single Page Applications (SPAs), mobile apps).

### 1. Introduction to OAuth 2.0 / OIDC in CoreIdent

OAuth 2.0 is the industry-standard framework for delegated authorization. It allows users to grant third-party applications limited access to their resources (e.g., profile information, APIs) without sharing their credentials directly. OpenID Connect (OIDC) is a simple identity layer built on top of OAuth 2.0, providing a standard way for clients to verify the identity of the end-user based on the authentication performed by an Authorization Server (like CoreIdent) and obtain basic profile information.

CoreIdent aims to provide robust, spec-compliant implementations of these protocols. Phase 3 focuses on the backend mechanics for the most common and secure flows.

### 2. Authorization Code Flow (with PKCE)

The Authorization Code Flow is the primary and most secure OAuth 2.0 flow, suitable for both traditional web applications (which can keep a client secret confidential) and public clients like SPAs and mobile apps (which cannot). CoreIdent implements this flow with **Proof Key for Code Exchange (PKCE)** enforced, which is mandatory for public clients and recommended for all clients today.

**Conceptual Flow:**

1.  **Initiation:** The user clicks a "Login with CoreIdent" button in the Client Application.
2.  **Redirect to Authorize:** The Client App redirects the user's browser to CoreIdent's `/authorize` endpoint, including parameters like its `client_id`, requested `scope`s, a `redirect_uri`, and PKCE parameters (`code_challenge`, `code_challenge_method`).
3.  **User Authentication & Consent:** CoreIdent authenticates the user (if not already logged in) and potentially prompts for consent to grant the Client App the requested permissions (`scope`s). (Consent is handled in Phase 4).
4.  **Code Issuance:** Upon successful authentication and consent, CoreIdent generates a short-lived, single-use **authorization code**. The code details (client ID, user ID, scopes, PKCE challenge, etc.) are persisted using `IAuthorizationCodeStore`. CoreIdent then redirects the user's browser back to the Client App's registered `redirect_uri`, including the `code` handle and the original `state` parameter.
5.  **Token Exchange:** The Client App's backend receives the authorization code handle. It then makes a direct, backend POST request to CoreIdent's `/token` endpoint, sending the `code` handle, its `client_id`, its `client_secret` (for confidential clients), the `redirect_uri`, and the PKCE `code_verifier`.
6.  **Token Issuance:** CoreIdent retrieves the code details using `IAuthorizationCodeStore`, validates the request (including the code handle, client credentials/PKCE verifier, redirect URI). If valid, it consumes the code (removes it from the store) and issues an `access_token`, a `refresh_token` (if `offline_access` scope was granted), and an `id_token` (if `openid` scope was granted).
7.  **Client Usage:** The Client App receives the tokens and can now use the `access_token` to make requests to protected APIs on behalf of the user. It uses the `id_token` to get user identity information.

**CoreIdent Endpoints Involved:**

*   **`GET /auth/authorize`**
    *   **Purpose:** Initiates the flow, handles user authentication/consent, persists authorization code details, and issues the code handle.
    *   **Key Request Parameters:** `client_id`, `response_type=code`, `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge`, `code_challenge_method=S256`.
    *   **Validation:** CoreIdent validates the `client_id`, checks if the `redirect_uri` is registered, verifies `scope`s, and ensures PKCE parameters are present and valid.
    *   **Response:** Redirects to the client's `redirect_uri` with `code` (handle) and `state` (or `error` parameters).

*   **`POST /auth/token` (Grant Type: `authorization_code`)**
    *   **Purpose:** Exchanges the authorization code handle for tokens.
    *   **Request Body (Form-encoded):** `grant_type=authorization_code`, `code` (handle), `redirect_uri`, `client_id`, `code_verifier`, and `client_secret` (for confidential clients).
    *   **Validation:** Retrieves code details via `IAuthorizationCodeStore`, validates `client_id`, `redirect_uri`, checks code expiry, performs PKCE verification by hashing the `code_verifier` and comparing it to the stored `code_challenge`.
    *   **Action:** Consumes the code (removes from `IAuthorizationCodeStore`), generates tokens using `ITokenService`.
    *   **Response:** JSON containing `access_token`, `refresh_token`, `id_token`, `expires_in`, `token_type`. Returns `invalid_grant` error if code is invalid/expired/consumed or PKCE fails.

**Persistence and Cleanup (`IAuthorizationCodeStore`, `EfAuthorizationCodeStore`, `AuthorizationCodeCleanupService`):**

*   Authorization codes are persisted to allow validation during the `/token` exchange.
*   The `EfAuthorizationCodeStore` uses the `CoreIdentDbContext`.
*   A background service (`AuthorizationCodeCleanupService`) automatically removes expired codes from the database, preventing the store from growing indefinitely. This service is registered by default when using `AddCoreIdentEntityFrameworkStores`.
*   The store implementation includes robust concurrency handling.

**Testing:**

*   `AuthorizationCodeFlowTests.cs` provides comprehensive integration tests covering the happy path, various error conditions (invalid code, PKCE failure, client validation), and interaction with the persistence layer.

### 3. Client Credentials Flow

This flow is designed for machine-to-machine (M2M) communication where a client application (e.g., a backend service, a CLI tool) needs to access protected resources on its own behalf, without a user being involved.

**Conceptual Flow:**

1.  **Client Request:** The client application makes a direct POST request to the `/token` endpoint.
2.  **Authentication:** The client authenticates itself using its `client_id` and `client_secret` (either via HTTP Basic Authentication header or in the request body).
3.  **Token Issuance:** CoreIdent validates the client credentials using `IClientStore` and `IPasswordHasher`. If valid, it checks the requested `scope`s against the client's allowed scopes. It then issues an `access_token` representing the client itself (typically, the `sub` claim is the `client_id`). Refresh tokens are usually not issued for this flow.

**CoreIdent Endpoint Involved:**

*   **`POST /auth/token` (Grant Type: `client_credentials`)**
    *   **Purpose:** Issues an access token directly to a confidential client.
    *   **Request Body (Form-encoded):**
        *   `grant_type=client_credentials`
        *   `scope` (optional): Space-separated list of scopes requested.
    *   **Authentication:** Requires client authentication via `Authorization: Basic` header OR `client_id` & `client_secret` in the request body.
    *   **Validation:** Uses `IClientStore` to find the client, `IPasswordHasher` to verify the secret, and `IScopeStore` to validate requested scopes against `client.AllowedScopes`.
    *   **Response:** JSON containing `access_token`, `expires_in`, `token_type`. Returns `invalid_client` if authentication fails or `invalid_scope` if scopes are not allowed.

**Client Authentication:**

*   CoreIdent supports standard client authentication methods for the `/token` endpoint:
    1.  **HTTP Basic Authentication Header:** `Authorization: Basic base64(client_id:client_secret)` (Preferred for confidential clients).
    2.  **Request Body Parameters:** Including `client_id` and `client_secret` in the form-encoded body.
*   Client secrets are hashed before being stored via `IClientStore`.

**Testing:**

*   Integration tests verify token issuance with valid credentials, client authentication failures, and scope validation errors for the Client Credentials flow.

### 4. OpenID Connect ID Token

When the `openid` scope is included in an authorization request (like the Authorization Code Flow), CoreIdent issues an **ID Token** alongside the access token. This JWT provides verifiable information about the user's authentication event.

**Purpose:** Allows the client application to confirm the identity of the user who logged in without needing to call a separate `/userinfo` endpoint (though that endpoint might be added later).

**Claims:** The ID Token includes standard OIDC claims:

| Claim      | Description                                      | Source                                          |
| :--------- | :----------------------------------------------- | :---------------------------------------------- |
| `iss`      | Issuer Identifier (CoreIdent server)             | `CoreIdentOptions.Issuer`                       |
| `sub`      | Subject Identifier (End-User's unique ID)        | `CoreIdentUser.Id`                              |
| `aud`      | Audience (Client ID of the relying party)        | `client_id` from the request                    |
| `exp`      | Expiration Time (Unix timestamp)                 | Based on Access Token Lifetime + current time   |
| `iat`      | Issued At Time (Unix timestamp)                  | Current time when token is generated            |
| `nonce`    | Value passed in `/authorize` request (if any)    | Original `nonce` parameter                      |
| `name`     | User's display name (if `profile` scope requested) | `CoreIdentUser.UserName` (or custom claim)    |
| `email`    | User's email (if `email` scope requested)      | `CoreIdentUser.Email` (or custom claim)       |
| *custom* | Other claims based on scopes/`ICustomClaimsProvider` | `IUserStore` or `ICustomClaimsProvider`       |

**Generation (`JwtTokenService`):**

*   The `JwtTokenService` includes logic to generate the ID Token when the `openid` scope is present.
*   It populates claims based on the authenticated user, the client ID, the nonce provided in the original authorization request, and other requested scopes.
*   The ID Token is signed using the same signing key as the access token.

**Validation (Client-Side):**

*   Client applications receiving an ID Token **MUST** validate it:
    1.  Verify the signature using CoreIdent's public key (obtained via the JWKS endpoint).
    2.  Validate the `iss` (issuer) claim matches CoreIdent's issuer identifier.
    3.  Validate the `aud` (audience) claim contains the client's own `client_id`.
    4.  Validate the `exp` (expiration) claim to ensure the token is not expired.
    5.  Validate the `iat` (issued at) claim (optional, check against clock skew).
    6.  Validate the `nonce` claim against the value the client originally sent in the `/authorize` request to prevent replay attacks.
*   Libraries like `Microsoft.AspNetCore.Authentication.OpenIdConnect` (for server-side web apps) or `oidc-client-ts` (for SPAs) handle this validation automatically.

**Testing:**

*   Unit tests in `JwtTokenServiceTests.cs` verify the correct generation of ID Tokens and claims.
*   Integration tests in `AuthorizationCodeFlowTests.cs` confirm that an ID Token is returned in the `/token` response when `openid` scope is requested and that the `nonce` value is correctly included.

### 5. OIDC Discovery & JWKS Endpoints

To allow clients and APIs to dynamically configure themselves and validate tokens, OIDC defines standard discovery endpoints.

*   **Discovery Endpoint (`/.well-known/openid-configuration`)**
    *   **Purpose:** Provides metadata about the CoreIdent server configuration.
    *   **Implementation:** CoreIdent maps this endpoint automatically via `MapCoreIdentEndpoints`. It dynamically generates the JSON response based on configured `CoreIdentOptions` and `CoreIdentRouteOptions`.
    *   **Contents:** Includes URLs for authorization (`authorization_endpoint`), token (`token_endpoint`), JWKS (`jwks_uri`), supported scopes (`scopes_supported`), response types (`response_types_supported`), grant types (`grant_types_supported`), signing algorithms (`id_token_signing_alg_values_supported`), etc.
    *   **Example Snippet:**
        ```json
        {
          "issuer": "https://localhost:7100",
          "authorization_endpoint": "https://localhost:7100/auth/authorize",
          "token_endpoint": "https://localhost:7100/auth/token",
          "jwks_uri": "https://localhost:7100/.well-known/jwks.json",
          "scopes_supported": ["openid", "profile", "email", "offline_access"],
          "response_types_supported": ["code"],
          "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
          "id_token_signing_alg_values_supported": ["HS256"],
          ...
        }
        ```

*   **JWKS Endpoint (`/.well-known/jwks.json`)**
    *   **Purpose:** Publishes the public key(s) used by CoreIdent to sign JWTs (Access Tokens and ID Tokens). Clients and APIs use this endpoint to retrieve the key needed to verify token signatures.
    *   **Implementation:** Mapped automatically by `MapCoreIdentEndpoints`. The `JwtTokenService` (specifically its internal `ISigningKeyService`) generates the JSON Web Key Set (JWKS) based on the configured `SigningKeySecret` (for symmetric keys like HS256) or key material (for asymmetric keys like RS256, planned later).
    *   **Contents:** A JSON object containing an array of keys (`keys`). For HS256, the key itself is not exposed (as it's symmetric), but the endpoint still exists for spec compliance and future asymmetric key support.
    *   **Example (Conceptual - for HS256, the key value `k` is usually omitted):**
        ```json
        {
          "keys": [
            {
              "kty": "oct", // Key Type: Octet sequence (Symmetric)
              "use": "sig", // Usage: Signature
              "kid": "default-hs256-key", // Key ID
              "alg": "HS256"
              // "k": "..." // The actual secret is NOT exposed here
            }
          ]
        }
        ```

**Setup:**

*   These endpoints require no special configuration beyond calling `AddCoreIdent()` and `MapCoreIdentEndpoints()`.
*   Ensure the `Issuer` in `CoreIdentOptions` is correctly set to the publicly accessible base URL of your CoreIdent instance, as this is used to construct the URLs advertised in the discovery document.

**Testing:**

*   Integration tests verify that both endpoints are accessible and return valid, well-formed JSON documents matching the expected configuration.

--- 

## Phase 4: User Consent & Scope Management

Phase 4 introduces user-facing interactions, starting with the crucial User Consent mechanism.

### 1. Consent Flow Overview

When a client application requests access to resources protected by CoreIdent (represented by specific `scope`s), the user needs to be informed and provide explicit permission. This is the User Consent flow.

**Purpose:** Ensures users understand and control what data or functionality third-party applications can access on their behalf, aligning with privacy principles and regulations.

**Key Steps & Logic:**

1.  **Trigger:** During the `GET /auth/authorize` request processing:
    *   CoreIdent retrieves the client details using `IClientStore`.
    *   It checks the `RequireConsent` flag on the `CoreIdentClient` registration. If `false`, consent is skipped entirely for this client.
    *   If `true`, CoreIdent retrieves the user's authentication details from the current session (e.g., cookie).
    *   It uses the `IUserGrantStore` to check if a valid, existing grant for this `user_id`, `client_id`, and *all* the requested `scope`s already exists.
2.  **Redirect to Consent:** If `RequireConsent` is `true` AND no sufficient existing grant is found, the `/authorize` endpoint stops processing and redirects the user's browser to the configured `ConsentPath` (default: `/auth/consent`). The original query string parameters (`client_id`, `scope`, `state`, etc.) are appended to this redirect URL.
3.  **Consent UI Interaction (`GET /auth/consent`):**
    *   The endpoint configured at `ConsentPath` is responsible for displaying the consent screen to the user.
    *   *CoreIdent Default Behaviour:* By default, `MapCoreIdentEndpoints` maps a simple handler that generates basic HTML with Allow/Deny buttons and hidden fields containing the necessary parameters (ClientId, RedirectUri, Scope, State, ReturnUrl, Antiforgery Token). It's **highly recommended** to replace this with a proper UI implementation (e.g., using Razor Pages, MVC, or Blazor) by configuring `CoreIdentRouteOptions.ConsentPath` to point to your custom UI page/endpoint.
    *   *Sample UI:* The `samples/CoreIdent.Samples.UI.Web` project provides an example `Consent.cshtml` Razor Page that reads the parameters from the query string, displays the client name (optional fetch) and scopes, and presents Allow/Deny buttons within a form that POSTs back to `/auth/consent`.
4.  **Handling User Decision (`POST /auth/consent`):**
    *   The user clicks "Allow" or "Deny" on the consent UI, submitting a form POST to `/auth/consent`.
    *   CoreIdent's handler for this endpoint receives the submitted form data (`ConsentRequest` DTO).
    *   It validates the antiforgery token to prevent CSRF attacks.
    *   **If Denied (`Allow=false`):** It constructs a redirect URL back to the client's original `redirect_uri`, appending `error=access_denied` and the original `state` parameter.
    *   **If Allowed (`Allow=true`):**
        *   It extracts the `user_id`, `client_id`, and granted `scope`s from the request.
        *   It creates a `UserGrant` object containing this information.
        *   It saves this grant using `IUserGrantStore.SaveAsync()`. The `EfUserGrantStore` persists this to the database.
        *   It redirects the user's browser back to the original `/authorize` endpoint URL (which was passed along in the hidden `ReturnUrl` field during the consent redirect).
5.  **Completing Authorization:** The browser follows the redirect back to `/authorize`. This time, the check in step 1 finds the newly created grant in `IUserGrantStore`, the consent check passes, and the `/authorize` endpoint proceeds to issue the authorization code and redirect back to the client's `redirect_uri`.

**Configuration:**

*   **Client:** Set `RequireConsent = true` when registering a `CoreIdentClient` that should prompt for user consent.
*   **Routes:** The `ConsentPath` can be configured via `CoreIdentRouteOptions` if you want to override the default `/auth/consent` path or point to a custom UI endpoint.
*   **Storage:** Ensure `IUserGrantStore` is correctly registered (either `InMemoryUserGrantStore` by default or `EfUserGrantStore` via `AddCoreIdentEntityFrameworkStores`).

**Storage (`IUserGrantStore`, `EfUserGrantStore`):**

*   The `UserGrant` model stores the `SubjectId`, `ClientId`, a list of `GrantedScopes`, and potentially `ExpirationTime`.
*   `IUserGrantStore` defines methods like `FindAsync`, `SaveAsync`, `HasUserGrantedConsentAsync`.
*   `EfUserGrantStore` implements this using EF Core, storing grants in the `UserGrants` table.
*   *(Future Consideration):* A background service could be added to clean up expired grants, similar to the token/code cleanup services.

**Testing:**

*   `ConsentFlowTests.cs` contains integration tests covering:
    *   Redirect to consent when required and no grant exists.
    *   Correct redirect back to client with `error=access_denied` on deny.
    *   Correct redirect back to `/authorize` on allow, followed by successful code issuance.
    *   Skipping consent on subsequent requests once a grant exists.
    *   Skipping consent when `RequireConsent=false` on the client.

For further details, see the [README.md](../README.md) and the `DEVPLAN.md` for implementation status.

### 4. Routing Rules (Summary)

CoreIdent follows specific routing conventions:

*   **Base Path (`CoreIdentRouteOptions.BasePath`, default `/auth`):** Most standard endpoints (`/register`, `/login`, `/authorize`, `/token`, `/consent`) are relative to this path.
*   **Token Management Path (`CoreIdentRouteOptions.TokenPath`, default `token`):** The token *issuance* endpoint (`/token`) uses this path relative to `BasePath`. The token *management* endpoints (`/introspect`, `/revoke`) are appended to this path. For example, defaults result in `/auth/token/introspect`. Changing `TokenPath` to `oauth2` results in `/auth/oauth2/introspect`.
*   **User Profile Path (`CoreIdentRouteOptions.UserProfilePath`, default `/me`):**
    *   If the configured path **starts with `/`**, it's mapped relative to the **application root**, ignoring `BasePath` (e.g., `/me`).
    *   If the configured path **does not start with `/`**, it's mapped relative to the **`BasePath`** (e.g., `me` results in `/auth/me` by default).
*   **Root Paths (`DiscoveryPath`, `JwksPath`):** The OIDC Discovery (`/.well-known/openid-configuration`) and JWKS (`/.well-known/jwks.json`) endpoints are **always relative to the application root** and ignore `BasePath`. This is required by the OpenID Connect specification.
    *   See [OIDC Discovery Spec, Section 4](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig).
    *   The paths used are configurable via `CoreIdentRouteOptions.DiscoveryPath` and `CoreIdentRouteOptions.JwksPath` but will always be treated as root-relative, ensuring a single leading slash (`/`) regardless of the input value.

Understanding these rules is key to configuring and consuming CoreIdent endpoints correctly.