# CoreIdent: Developer Training Guide

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
3.  **User Authentication & Consent:** CoreIdent authenticates the user (if not already logged in) and potentially prompts for consent to grant the Client App the requested permissions (`scope`s). (Consent UI is planned for Phase 4).
4.  **Code Issuance:** Upon successful authentication and consent, CoreIdent generates a short-lived, single-use **authorization code** and redirects the user's browser back to the Client App's registered `redirect_uri`, including the `code` and the original `state` parameter (if provided).
5.  **Token Exchange:** The Client App's backend receives the authorization code. It then makes a direct, backend POST request to CoreIdent's `/token` endpoint, sending the `code`, its `client_id`, its `client_secret` (for confidential clients), the `redirect_uri`, and the PKCE `code_verifier`.
6.  **Token Issuance:** CoreIdent validates the request (including the code, client credentials/PKCE verifier, redirect URI). If valid, it consumes the code and issues an `access_token`, a `refresh_token` (if `offline_access` scope was granted), and an `id_token` (if `openid` scope was granted).
7.  **Client Usage:** The Client App receives the tokens and can now use the `access_token` to make requests to protected APIs on behalf of the user. It uses the `id_token` to get user identity information.

**CoreIdent Endpoints Involved:**

*   **`GET /auth/authorize` (Example Base Path: `/auth`)**
    *   **Purpose:** Initiates the flow, handles user authentication/consent, and issues the authorization code.
    *   **Key Request Parameters:**
        *   `client_id`: Identifier of the client application requesting authorization.
        *   `response_type=code`: Specifies the Authorization Code flow.
        *   `redirect_uri`: Where CoreIdent redirects the user back after authorization. Must match one of the URIs registered for the client.
        *   `scope`: Space-separated list of permissions requested (e.g., `openid profile email offline_access`). `openid` is required for OIDC flows and ID Tokens.
        *   `state`: An opaque value used by the client to maintain state between the request and callback. CoreIdent echoes it back in the redirect. (Recommended for CSRF protection).
        *   `nonce`: String value used to associate a client session with an ID Token and mitigate replay attacks. Required for OIDC implicit flow, optional but recommended for code flow ID Tokens.
        *   `code_challenge`: The PKCE code challenge (Base64Url-encoded SHA256 hash of the `code_verifier`).
        *   `code_challenge_method=S256`: Specifies the hashing method used for the PKCE challenge (CoreIdent supports `S256`).
    *   **Validation:** CoreIdent validates the `client_id`, checks if the `redirect_uri` is registered for that client, and verifies requested `scope`s are allowed.
    *   **Response:** Redirects to the client's `redirect_uri` with `code` and `state` (and potentially `error` parameters if something goes wrong).

*   **`POST /auth/token` (Grant Type: `authorization_code`)**
    *   **Purpose:** Exchanges the authorization code for tokens. This request MUST come from the client's backend (or securely handled in the frontend for public clients using PKCE).
    *   **Request Body (Form-encoded):**
        *   `grant_type=authorization_code`: Specifies the grant type.
        *   `code`: The authorization code received from the `/authorize` redirect.
        *   `redirect_uri`: Must match the `redirect_uri` used in the initial `/authorize` request.
        *   `client_id`: The client application's identifier.
        *   `code_verifier`: The PKCE code verifier (the original secret that was hashed to create the `code_challenge`).
        *   *(Confidential Clients Only):* `

### Authorization Code Flow: Persistence and Cleanup

When using EF Core storage, authorization codes issued by the `/auth/authorize` endpoint are persisted in the database via `EfAuthorizationCodeStore`. This ensures:
- Codes are durable and can be validated/redeemed even if the server restarts.
- Expired codes are automatically removed by the `AuthorizationCodeCleanupService` background service.
- The store implementation is concurrency-safe, so multiple simultaneous attempts to redeem or clean up a code are handled correctly.

**Troubleshooting:**
- If you receive an error that an authorization code is invalid or expired, it may have already been redeemed or cleaned up by the background service. Codes are single-use and short-lived by design.

## Client Authentication at the /token Endpoint

The `/token` endpoint supports two standard methods for client authentication, as recommended by OAuth 2.0 (RFC 6749 Section 2.3.1):

1. **HTTP Basic Authentication Header**
   - The client sends its `client_id` and `client_secret` in the `Authorization` header using the `Basic` scheme.
   - Example header: `Authorization: Basic base64(client_id:client_secret)`
   - This is the most secure method for confidential clients (e.g., server-side web apps).

2. **Request Body Parameters**
   - The client includes `client_id` and `client_secret` as form fields in the POST body (content type: `application/x-www-form-urlencoded`).
   - Example fields: `client_id=my-client&client_secret=supersecret`
   - This method is supported for compatibility, but Basic Auth is preferred for confidential clients.

**How Confidential vs. Public Clients Are Determined**
- If a client has one or more registered secrets (`ClientSecrets`), it is treated as a confidential client and must authenticate using one of the above methods.
- Public clients (e.g., SPAs, mobile apps) must not use secrets and are authenticated only by their `client_id`.

**Secret Verification and Security**
- Client secrets are securely hashed and stored in the database. Verification uses the same password hasher as user passwords.
- Only confidential clients should use secrets. Never embed secrets in public client code.
- If authentication fails (missing or invalid secret), the endpoint returns an `invalid_client` error.

**Example: Basic Auth**
```
POST /auth/token
Authorization: Basic base64(my-client:supersecret)
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=...&redirect_uri=...
```

**Example: Request Body**
```
POST /auth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=...&redirect_uri=...&client_id=my-client&client_secret=supersecret
```

**Error Responses**
- If client authentication fails, the response will be:
  ```json
  { "error": "invalid_client", "error_description": "Client authentication failed (client_id missing)." }
  ```
- Or for invalid secret:
  ```json
  { "error": "invalid_client", "error_description": "Invalid client secret." }
  ```
### OpenID Connect: ID Token

- The **ID Token** is a JWT issued as part of the OIDC flow (e.g., Authorization Code).
- Contains claims about the authenticated user and session:
    - `iss`: Issuer
    - `sub`: User ID (subject)
    - `aud`: Audience (client ID)
    - `exp`: Expiration
    - `iat`: Issued-at
    - `nonce`: Nonce from the original request (prevents replay)
    - `name`, `email`: User claims if requested via scopes
- Returned in the `id_token` property of the `/token` endpoint response.
- Signed using the server's signing key (see [README.md](../README.md)).
- **Testing:**
    - Unit tests verify claim presence and signature.
    - Integration tests verify issuance during the Authorization Code flow and round-trip of the nonce value.
```

## Phase 4: User Consent & Scope Management

### 1. Consent Flow Overview

CoreIdent implements a user consent flow for OAuth 2.0 and OIDC authorization. When a client requests access to user resources, the user is prompted to approve or deny the requested scopes via a consent UI.

**Key Steps:**
1. **Authorization Request:** Client initiates `/auth/authorize` with required scopes.
2. **Consent Check:** CoreIdent checks if the user has already granted consent for this client and scopes.
3. **Consent UI:** If not, the user is redirected to a consent page listing the client and requested permissions.
4. **User Decision:** The user can allow or deny. On allow, the grant is stored. On deny, the client is redirected with `error=access_denied`.
5. **Subsequent Requests:** Consent is not required again for the same client/scopes unless revoked.

### 2. Endpoints and Storage
- `GET /auth/authorize`: Triggers consent check and redirect.
- `GET /auth/consent`: Shows the consent UI (Razor page).
- `POST /auth/consent`: Handles user decision and updates grants.
- **Storage:** Grants are stored via the `IUserGrantStore` interface. The default implementation is in-memory; an EF Core store is available for persistence.

### 3. Customizing Consent
- Replace the Razor page in the sample UI for custom branding or UX.
- Implement a custom `IUserGrantStore` for advanced grant management (e.g., expiration, auditing).

### 4. Sample UI Integration
The sample project demonstrates the consent flow with a simple Razor UI. It can be extended for production scenarios.

### 5. Testing Consent Flows
- Integration tests cover all consent scenarios: redirect, allow, deny, and repeated requests.
- See `ConsentFlowTests` in the integration test project for examples.

### 6. Troubleshooting
If consent is not prompted as expected, verify:
- The client is configured to require consent.
- The requested scopes are registered and enabled.
- The grant store is properly registered (in-memory or EF Core).

For further details, see the [README.md](../README.md) and the `DEVPLAN.md` for implementation status.