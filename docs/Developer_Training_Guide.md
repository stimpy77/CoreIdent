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
*   **Endpoint Mapping:**
    *   Using `MapCoreIdentEndpoints()`.
    *   Default endpoints exposed (`/register`, `/login`, `/token/refresh`).
The foundation of CoreIdent lies within the `CoreIdent.Core` NuGet package. This package contains the essential interfaces, services, and extension methods needed to integrate CoreIdent's authentication and authorization features into your ASP.NET Core application.

**Core Package Overview:**

*   **`CoreIdent.Core`:** This is the main library you'll reference. It provides the building blocks like `IUserStore`, `ITokenService`, `IPasswordHasher`, configuration options (`CoreIdentOptions`), and the necessary setup extensions. It aims to be platform-agnostic regarding storage and UI, focusing purely on the core identity logic.

**Configuration (`CoreIdentOptions`):**

Proper configuration is crucial for security and functionality. CoreIdent uses the standard ASP.NET Core options pattern. You configure `CoreIdentOptions`, typically in your `appsettings.json` file or other configuration providers.

*   **Key Options:**
    *   `Issuer` (string): The identifier for the token issuer (your application/service). This will appear in the `iss` claim of JWTs. Example: `"https://auth.yourapp.com"`
    *   `Audience` (string): The identifier for the intended recipient(s) of the tokens (your APIs). This will appear in the `aud` claim. Example: `"https://api.yourapp.com"`
    *   `SigningKeySecret` (string): **CRITICAL:** The secret key used to sign JWTs (using symmetric HS256 algorithm by default in Phase 1). This key MUST be kept confidential and should be strong (long, random). **Never hardcode this in source control.** Use user secrets, environment variables, or Azure Key Vault in production. The key length must meet the requirements for HS256 (minimum 32 bytes / 256 bits recommended).
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

    // Add CoreIdent services
    builder.Services.AddCoreIdent(); // Options are automatically picked up

    // Add standard ASP.NET Core AuthN/AuthZ if needed for token validation
    builder.Services.AddAuthentication().AddJwtBearer(); // Example for JWT validation
    builder.Services.AddAuthorization();

    // ... other services

    var app = builder.Build();
    ```
*   **Registered Services:** `AddCoreIdent()` registers the default implementations for core services:
    *   `CoreIdentOptions` (configured via `AddOptions`)
    *   `ITokenService` -> `JwtTokenService`
    *   `IPasswordHasher` -> `DefaultPasswordHasher`
    *   `IUserStore` -> `InMemoryUserStore` (Phase 1 default)
    *   Validation services for `CoreIdentOptions`.

**Endpoint Mapping (`MapCoreIdentEndpoints`):**

To expose the built-in authentication endpoints, CoreIdent provides an extension method for `IEndpointRouteBuilder`.

*   **Usage:** In `Program.cs` (after `app.Build()`), call `MapCoreIdentEndpoints()`.
    ```csharp
    // Example in Program.cs
    var app = builder.Build();

    // ... other middleware (HTTPS redirection, routing, etc.)

    app.UseAuthentication(); // Important: Before UseAuthorization and MapCoreIdentEndpoints
    app.UseAuthorization();

    // Map CoreIdent's built-in endpoints
    app.MapCoreIdentEndpoints();

    // Map your other application endpoints
    app.MapGet("/", () => "Hello World!");

    app.Run();
    ```
*   **Default Endpoints Exposed:** This maps the following HTTP endpoints by default:
    *   `POST /register`: Handles new user registration.
    *   `POST /login`: Handles user login and issues tokens.
    *   `POST /token/refresh`: Handles refreshing access tokens using a refresh token.

### 2. User Registration (`/register`)

The `POST /register` endpoint is the entry point for new users to create an account within your application using CoreIdent.

**Registration Flow:**

1.  **Client Request:** A client application (web frontend, mobile app, etc.) sends an HTTP POST request to the `/register` endpoint. The request body must contain the necessary user information, typically email and password, formatted as JSON.
2.  **Input Validation:** CoreIdent first validates the incoming request data (DTO - Data Transfer Object). It checks for required fields (e.g., email, password) and potentially applies validation rules (e.g., valid email format, minimum password complexity - though basic complexity is handled by hashing). If validation fails, a `400 Bad Request` response is returned with details about the validation errors.
3.  **Check for Existing User:** The endpoint uses the injected `IUserStore` service to check if a user with the provided email (or username) already exists. If a user is found, a `409 Conflict` response is returned to indicate that the email is already taken.
4.  **Password Hashing:** If the user does not exist, the endpoint uses the injected `IPasswordHasher` service to securely hash the provided plain-text password. This generates a strong, salted hash suitable for storage.
5.  **Create User:** A new `CoreIdentUser` object is created with the provided details (e.g., email as username) and the generated password hash.
6.  **Store User:** The new user object is passed to the `IUserStore`'s `CreateAsync` method (or similar) to persist the user account. In Phase 1, this uses the `InMemoryUserStore`, meaning the user exists only for the lifetime of the application process.
7.  **Success Response:** If the user is successfully created and stored, a `201 Created` response is returned to the client. Typically, the response body is empty, but the location header might point to the newly created resource (though often not implemented for user registration).

**Request/Response:**

*   **Request (`POST /register`):**
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

### 3. User Login (`/login`)

The `POST /login` endpoint allows registered users to authenticate themselves and receive access and refresh tokens, enabling them to access protected resources.

**Login Flow:**

1.  **Client Request:** The client sends an HTTP POST request to the `/login` endpoint with the user's credentials (typically email and password) in the JSON request body.
2.  **Input Validation:** The incoming `LoginRequest` DTO is validated. Checks ensure required fields (email, password) are present. If validation fails, a `400 Bad Request` is returned.
3.  **Find User:** The endpoint uses the injected `IUserStore` service, calling a method like `FindByUsernameAsync` (using the provided email), to retrieve the corresponding user account. If no user is found with that email, a `401 Unauthorized` response is returned. It's crucial *not* to indicate whether the username was wrong or the password was wrong to prevent user enumeration attacks.
4.  **Verify Password:** If a user *is* found, the endpoint retrieves the stored password hash for that user via the `IUserStore`. It then uses the injected `IPasswordHasher` service's `VerifyHashedPassword` method, passing the stored hash and the plain-text password provided in the request. This method securely compares the provided password against the stored hash.
5.  **Handle Incorrect Password:** If `VerifyHashedPassword` indicates the password does not match, a `401 Unauthorized` response is returned. Again, the specific reason (user not found vs. wrong password) should not be distinguishable by the client response. *(Optional: Implementations might increment an access failed count here for lockout policies, planned for Phase 2 interface refinements)*.
6.  **Generate Tokens:** If the password verification is successful, the user is authenticated. The endpoint now calls the injected `ITokenService` (specifically, the `GenerateAccessTokenAsync` and `GenerateRefreshTokenAsync` methods), passing the authenticated `CoreIdentUser` object.
7.  **Token Service Logic:** The `JwtTokenService` (default in Phase 1) generates a signed JWT access token containing standard claims (`iss`, `aud`, `sub`, `exp`, etc.) and potentially user-specific claims fetched from the user object. It also generates a refresh token (a simple secure random string in Phase 1).
8.  **Store Refresh Token (Phase 1 - Basic):** *Important Note:* In the basic Phase 1 `InMemoryUserStore`, the refresh token isn't explicitly stored or linked to the user in a persistent way. It's simply generated and returned. The `/token/refresh` endpoint relies on an in-memory lookup (if implemented simply). Robust refresh token storage is a key feature of Phase 2.
9.  **Success Response:** A `200 OK` response is returned to the client. The response body contains the generated `AccessToken`, `RefreshToken`, and the `ExpiresIn` value (lifetime of the access token in seconds) for the client's convenience.

**Request/Response:**

*   **Request (`POST /login`):**
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
          "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
          "refreshToken": "aBcDeFgHiJkLmNoPqRsTuVwXyZ123456...",
          "expiresIn": 900 // Access token lifetime in seconds (e.g., 15 minutes)
        }
        ```
        *(Note: The exact structure depends on the `LoginResponse` DTO defined.)*
    *   `400 Bad Request`: Invalid input (missing fields).
    *   `401 Unauthorized`: Authentication failed (user not found OR password incorrect). Body should ideally be empty or contain a generic error message.
    *   `500 Internal Server Error`: An unexpected error occurred during processing.

**Key Components:**

*   **`IUserStore`:** Used to find the user by their identifier (email/username) and retrieve their details, including the stored password hash.
*   **`IPasswordHasher`:** Crucial for securely verifying the user-provided password against the stored hash without ever exposing the hash or the original password.
*   **`ITokenService`:** Responsible for generating the access (JWT) and refresh tokens once the user has been successfully authenticated. It encapsulates the logic for claims, signing, and lifetimes based on `CoreIdentOptions`.

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

**Refresh Tokens (Phase 1 - Simple Implementation):**

Access tokens are intentionally short-lived for security. When an access token expires, the user would need to log in again, which is inconvenient. Refresh tokens solve this problem.

*   **Purpose:** A refresh token is a special, longer-lived credential that clients can use to obtain a *new* access token (and potentially a new refresh token) without requiring the user to re-enter their password.
*   **Generation (Phase 1):** In Phase 1, the `JwtTokenService` generates a refresh token simply as a cryptographically secure random string. It doesn't contain claims or have a complex structure like a JWT.
*   **Storage (Phase 1 Limitation):** Crucially, in the Phase 1 default `InMemoryUserStore`, these refresh tokens are **not robustly stored or tracked**. A very basic implementation might just keep a temporary mapping in memory, but this is fragile and lost on restart. Proper, persistent storage and validation (e.g., associating tokens with users/clients, tracking usage, revocation) is introduced in Phase 2 with the `IRefreshTokenStore`.
*   **The `/token/refresh` Endpoint:**
    1.  **Client Request:** When an access token expires, the client sends a POST request to `/token/refresh` with the *refresh token* in the request body.
        ```json
        { "refreshToken": "aBcDeFgHiJkLmNoPqRsTuVwXyZ123456..." }
        ```
    2.  **Validation (Phase 1 - Basic):** The endpoint needs a way to validate the refresh token. In the simplest Phase 1 in-memory setup, this might involve checking if the token exists in a temporary list associated with a user session (which is not ideal). A slightly better basic approach might involve embedding *minimal* information in the refresh token itself or looking it up in a simple in-memory dictionary, but without persistence, it's limited. **The Phase 1 implementation is primarily a placeholder for the flow.** It typically *cannot* securely verify the token against a user or check for expiry/revocation without proper storage.
    3.  **Issue New Tokens:** If the basic validation passes, the endpoint uses the `ITokenService` to generate a *new* access token and potentially a *new* refresh token (token rotation).
    4.  **Response:** A `200 OK` response is sent with the new tokens, similar to the `/login` response. If validation fails (token not found, expired in a more advanced setup, etc.), a `401 Unauthorized` or `400 Bad Request` is returned.

*   **Security:** Refresh tokens are powerful credentials and must be stored securely by the client (e.g., secure storage on mobile, `HttpOnly`, `Secure` cookies for web). They should generally only be sent to the dedicated refresh endpoint (`/token/refresh`).

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
    *   The `OnModelCreating(ModelBuilder modelBuilder)` method is overridden to configure the database schema using EF Core's Fluent API. This includes defining primary keys, relationships (e.g., one-to-many between `CoreIdentUser` and `CoreIdentUserClaim`), indexes, and constraints (e.g., unique usernames).
    *   **Important:** Your application's main `DbContext` should either **inherit from `CoreIdentDbContext`** or **call its configuration logic** within its own `OnModelCreating` to ensure the CoreIdent tables are correctly set up.

2.  **EF Core Store Implementations:**
    *   This package provides concrete implementations of the store interfaces from `CoreIdent.Core`:
        *   `EfUserStore`: Implements `IUserStore`. Uses the injected `CoreIdentDbContext` to perform LINQ queries (e.g., `_context.Users.FirstOrDefaultAsync(...)`) and save changes (`_context.SaveChangesAsync()`).
        *   `EfRefreshTokenStore`: Implements `IRefreshTokenStore`. Similarly uses the `DbContext` to manage `CoreIdentRefreshToken` entities.
        *   *(Implementations for `IClientStore` and `IScopeStore` using EF Core will reside here when needed for Phase 3+)*

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
2.  **Add Migration:** From your terminal, in the directory containing your *web application project* (`.csproj`), run:
    ```bash
    dotnet ef migrations add InitialCoreIdentSchema --context YourApplicationDbContext -p ../path/to/src/CoreIdent.Storage.EntityFrameworkCore
    ```
    *   Replace `InitialCoreIdentSchema` with a descriptive name for the migration.
    *   Replace `YourApplicationDbContext` with the name of *your* application's `DbContext` class.
    *   The `-p` argument points to the project containing the `CoreIdentDbContext` configuration (our storage project).
    *   The `-s` argument (optional if run from the web project directory) points to the startup project.
    This command generates C# code files in a `Migrations` folder within the storage project, describing the schema changes needed.
3.  **Apply Migration:** To apply the changes to your database, run:
    ```bash
    dotnet ef database update --context YourApplicationDbContext
    ```
    This connects to the database specified in your connection string and executes the necessary SQL to create/update tables.

**Refresh Token Handling with Persistence:**

1.  **Handle Hashing (New):** Before storing, the raw refresh token handle is securely hashed using a salted SHA-256 algorithm (`TokenHasher`). The salt incorporates the user ID and client ID to prevent precomputation attacks. This ensures the raw token handle is never stored directly.
2.  **Storage:** When a user logs in, the generated `CoreIdentRefreshToken` (containing the *hashed* handle, user ID, client ID, expiry, family ID, etc.) is saved to the database table via `IRefreshTokenStore.StoreRefreshTokenAsync`.
3.  **Validation (`/token/refresh`):**
    *   The endpoint receives a *raw* refresh token handle from the client.
    *   The store implementation (`EfRefreshTokenStore`) hashes the received raw handle using the same salt (user ID and client ID, which need to be retrieved or inferred). *Correction: The current `GetRefreshTokenAsync` implementation expects the *hashed* handle to be passed in. The endpoint logic needs adjustment to perform hashing before calling the store.* 
    *   It calls `IRefreshTokenStore.GetRefreshTokenAsync(hashedHandle)` to retrieve the full token object from the database using the hash.
    *   It checks if the token exists, if it has expired (`ExpirationTime`), and if it has already been used (`ConsumedTime`). If any check fails, it returns `401 Unauthorized`.
    *   **Token Theft Detection (Enabled by Default):** By default (`EnableTokenFamilyTracking = true`), if a *consumed* token is presented, the system triggers a security response (e.g., `RevokeFamily` to invalidate all related tokens) based on the configured `TokenTheftDetectionMode`. This behavior can be disabled by setting `EnableTokenFamilyTracking = false` in the configuration.
4.  **Consumption:** If the token is valid, it **must** be marked as consumed to prevent replay attacks. The store implementation sets the `ConsumedTime` via `IRefreshTokenStore.RemoveRefreshTokenAsync(hashedHandle)`.
5.  **Rotation:** A **new** `CoreIdentRefreshToken` is generated by the `ITokenService` (including generating and hashing a new handle). If token family tracking is enabled (default), the new token is linked to the previous token's family.
6.  **Store New Token:** The *new* refresh token (with its hashed handle) is stored in the database via `StoreRefreshTokenAsync`.
7.  **Response:** The new access token *and* the new *raw* refresh token handle are returned to the client.

This **Refresh Token Rotation** strategy is crucial for security. Each refresh token can only be used once. The default enabled **token family tracking** provides additional protection by invalidating an entire chain of tokens if one is compromised and reused. If this enhanced security is not desired, it can be disabled via configuration.

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

*   **Password Validation:** The `ValidateCredentialsAsync` delegate is critical. It receives the plain-text password entered by the user. Your implementation *must* securely validate this against your existing system's credential store (which should be storing hashed passwords). **CoreIdent's `IPasswordHasher` is NOT used in this flow.**
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

**Workflow Example (`/login`):**

1.  User POSTs to `/login` with email and password.
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

---
 
*(Further Phases will add sections on Storage, OAuth/OIDC Flows, UI, MFA, Providers, etc.)*
