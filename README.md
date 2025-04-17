# CoreIdent: Modern .NET Identity & Authentication

![image](https://github.com/user-attachments/assets/96ac08ce-d88e-4d78-af98-101bb95aa317)

[![Build Status](https://github.com/stimpy77/CoreIdent/actions/workflows/dotnet.yml/badge.svg?branch=main)](https://github.com/stimpy77/CoreIdent/actions/workflows/dotnet.yml)
[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![NuGet Version](https://img.shields.io/nuget/v/CoreIdent.Core.svg)](https://www.nuget.org/packages/CoreIdent.Core/)

**CoreIdent is building the foundation for a modern, open-source, developer-centric identity and authentication solution for .NET.** It aims to replace complex, often vendor-locked systems with a flexible, convention-driven alternative that empowers developers.

**Think: A spiritual successor to IdentityServer, built for today's .NET.**

**Current Status:** Phase 2 (Persistent Storage & Delegated Adapter) is complete. Phase 3 (Core OAuth/OIDC Flows, Token Theft Detection) development is underway.

**Development Phases:**
*   **Phase 1 (Completed):** MVP - Core Registration/Login/Tokens with In-Memory Storage.
*   **Phase 2 (Completed):** Persistent Storage (EF Core), Delegated Adapter & Interface Refinement.
*   **Phase 3 (Current):** Core OAuth 2.0 / OIDC Server Mechanics (Authorization Code Flow + PKCE, Token Theft Detection, Client Credentials, Discovery).
*   **Phase 4:** User Interaction & External Integrations (Consent, UI, MFA, Passwordless).
*   **Phase 5:** Advanced Features & Polish (More Flows, Extensibility, Templates).
*   **Phase 6:** Client Libraries for Mobile & Desktop Applications.

## Why CoreIdent?

Tired of wrestling with complex identity vendors or rolling your own auth from scratch? CoreIdent offers a different path:

*   🚀 **Developer Freedom & Experience:** Open-source (MIT) with a focus on minimizing boilerplate and maximizing productivity through conventions and clear APIs. Get secure auth running *fast*.
*   🧩 **Modularity & Extensibility:** A lean core with features (like storage, providers) added via separate NuGet packages. Use only what you need.
*   🔒 **Secure by Default:** Implements security best practices for token handling (JWTs, refresh token rotation, **token theft detection** using family tracking, **securely hashed token handle storage**), password storage, and endpoint protection.
*   🔧 **Flexible Storage:** Choose between integrated persistence (Entity Framework Core) or adapt to existing user systems with the Delegated User Store.
*   🌐 **Future-Ready:** Built on modern .NET (9+), designed to support traditional credentials, modern passwordless methods (Passkeys/WebAuthn), and decentralized approaches (Web3, LNURL) in future phases.
*   🚫 **No Vendor Lock-In:** Own your identity layer.

## Current State vs. Future Vision

**What CoreIdent provides *today* (Phase 3 In Progress):**

*   **Core Authentication API:** Secure `/auth/register`, `/auth/login`, and `/auth/token/refresh` endpoints (default prefix `/auth`).
*   **JWT Issuance:** Standard access tokens upon login.
*   **Refresh Token Management:** Secure refresh token generation, persistent storage (EF Core), rotation, **securely hashed token handle storage** (raw handle returned to client, hash stored in DB), and **token theft detection** with family revocation (enabled by default).
*   **OAuth/OIDC:** Authorization Code Flow with PKCE (`/auth/authorize`, `/auth/token`).
*   **Password Hashing:** Secure password handling using ASP.NET Core Identity's hasher.
*   **Pluggable Storage:**
    *   `CoreIdent.Storage.EntityFrameworkCore`: Store users, refresh tokens, clients, scopes, and auth codes in your database (SQL Server, PostgreSQL, SQLite, etc.).
    *   `CoreIdent.Adapters.DelegatedUserStore`: Integrate with your existing user database/authentication logic.
*   **Core Services:** `ITokenService`, `IPasswordHasher`, `IUserStore`, `IRefreshTokenStore`, `IClientStore`, `IScopeStore`, `IAuthorizationCodeStore` interfaces for customization.
*   **Configuration:** Easy setup via `AddCoreIdent()` and `appsettings.json`.

**Where CoreIdent is heading (Future Phases):**

*   **Full OAuth 2.0 / OIDC Server:** Implementing remaining standard flows (Client Credentials, Implicit, Hybrid) for web apps, SPAs, mobile apps, and APIs.
*   **OIDC Compliance:** Discovery (`/.well-known/openid-configuration`), JWKS (`/.well-known/jwks.json`), ID Tokens.
*   **User Interaction:** Consent screens, standard logout endpoints.
*   **Extensible Provider Model:**
    *   **MFA:** Pluggable Multi-Factor Authentication (TOTP, SMS, Email).
    *   **Passwordless:** Passkeys / WebAuthn / FIDO2.
    *   **Social Logins:** Google, Microsoft, etc.
    *   **Decentralized:** Web3 Wallet Login (MetaMask), LNURL-auth.
*   **UI Components:** Optional package (`CoreIdent.UI.Web`) providing basic, themeable UI (Razor Pages/Components) for login, registration, consent, etc.
*   **Administration:** Optional Admin UI for managing users, clients, scopes.
*   **Client Libraries:**
    *   Core client library (`CoreIdent.Client`) for mobile & desktop apps
    *   Platform-specific implementations (.NET MAUI, WPF)
    *   Secure token storage and management
    *   Offline authentication support
*   **Tooling:** `dotnet new` templates, comprehensive documentation.

**Is this a replacement for IdentityServer?**

**Not yet, but that's the goal.** We are building the foundational pieces first, focusing on a solid core and flexible storage. Phase 3 is actively adding the core OAuth/OIDC mechanics.

## Core Features by Phase

### Phase 1: MVP Core (Foundation)

The initial Phase 1 release established the fundamental authentication flow and core package structure:

*   **Core Package Structure**:
    *   `CoreIdent.Core` NuGet package targeting modern .NET
    *   Configuration via `CoreIdentOptions` (Issuer, Audience, SigningKeySecret, token lifetimes)
    *   Dependency injection via `AddCoreIdent()` and `MapCoreIdentEndpoints()` extension methods

*   **User Registration**:
    *   `POST /register` endpoint for creating new users
    *   Input validation (email format, password complexity)
    *   Secure password hashing with `IPasswordHasher`/`DefaultPasswordHasher`
    *   User storage with `IUserStore` interface

*   **User Authentication & Token Handling**:
    *   `POST /login` endpoint for authenticating users
    *   JWT access token generation via `ITokenService`/`JwtTokenService`
    *   Standard claims (`sub`, `iss`, `aud`, `exp`, `iat`, `jti`)
    *   Basic refresh token flow with `POST /token/refresh` endpoint

*   **In-Memory Storage**:
    *   `InMemoryUserStore` implementation for development/testing
    *   Thread-safe collections for storing users and refresh tokens
    *   Username normalization for case-insensitive lookups
    *   Simple token validation and invalidation

*   **Testing & Documentation**:
    *   Unit tests for core services and interfaces
    *   Integration tests for API endpoints
    *   Initial documentation in README.md and Developer Training Guide

Phase 1 provided a runnable, testable foundation focused on the core authentication flows, with in-memory storage suitable for development and testing.

### Phase 2: Storage & Core Extensibility (Completed)

Phase 2 built on the foundation by providing persistent storage options and enhancing extensibility:

*   **Refined Core Interfaces**: Enhanced `IUserStore`, defined `IRefreshTokenStore`, `IClientStore`, `IScopeStore`.
*   **Entity Framework Core Storage**: `CoreIdent.Storage.EntityFrameworkCore` for persisting users, refresh tokens, clients, scopes.
*   **Delegated User Store Adapter**: `CoreIdent.Adapters.DelegatedUserStore` for integrating with existing user systems.
*   **Robust Refresh Token Handling**: Implemented token rotation and persistence via `IRefreshTokenStore`.
*   **Client and Scope Models**: Defined initial models for OAuth 2.0 / OIDC functionality.

### Phase 3: Core OAuth 2.0 / OIDC Server Mechanics (Current)

Phase 3 implements the essential backend logic for standard authorization flows and discovery:

*   **Authorization Code Flow + PKCE**: Secure flow for web apps, SPAs, and mobile clients (`/auth/authorize`, `/auth/token`).
*   **ID Token Issuance**: Standard OIDC ID tokens generated alongside access tokens.
*   **Token Theft Detection**: Enhanced security for refresh tokens using family tracking and automatic revocation (enabled by default).
*   **(In Progress)** Client Credentials Flow.
*   **(In Progress)** OIDC Discovery & JWKS Endpoints.

For more details on these features, see the [Developer Training Guide](./docs/Developer_Training_Guide.md).

## Getting Started

This guide covers the setup for the core functionality available after Phase 3.

### 1. Installation

Install the core package and any desired storage adapters via NuGet:

```bash
dotnet add package CoreIdent.Core
dotnet add package CoreIdent.Storage.EntityFrameworkCore # For EF Core persistence
dotnet add package CoreIdent.Adapters.DelegatedUserStore # For delegating to existing systems
# Ensure you also add your EF Core Database Provider, e.g.:
dotnet add package Microsoft.EntityFrameworkCore.Sqlite
```

*(Note: If working directly from the source repository, add project references instead.)*

### 2. Configuration

Configure the core options in your `appsettings.json` (or another configuration source):

```json
{
  "ConnectionStrings": {
     // Add your DB connection string if using EF Core
    "DefaultConnection": "DataSource=coreident.db;Cache=Shared"
  },
  "CoreIdent": {
    "Issuer": "https://localhost:5001", // IMPORTANT: Replace with your actual issuer URI (HTTPS recommended)
    "Audience": "myapi",             // IMPORTANT: Replace with your API audience identifier
    "SigningKeySecret": "REPLACE_THIS_WITH_A_VERY_STRONG_AND_SECRET_KEY_32_BYTES_OR_LONGER", // MUST be strong, unique, >= 32 Bytes (256 bits) for HS256, and kept secret!
    "AccessTokenLifetime": "00:15:00",  // 15 minutes
    "RefreshTokenLifetime": "7.00:00:00", // 7 days
    "ConsumedTokenRetentionPeriod": "30.00:00:00", // Optional: How long to keep consumed tokens (for audit/theft detection) before cleanup. Default: 30 days.
    "TokenSecurity": { // Optional: Security settings
      "EnableTokenFamilyTracking": true, // Default=true (Recommended). Set to false to disable family tracking & revocation on theft detection.
      "TokenTheftDetectionMode": "RevokeFamily" // Default. Options: Silent, RevokeFamily, RevokeAllUserTokens. Only applies if EnableTokenFamilyTracking=true.
    }
  }
}
```

**⚠️ Important Security Note:** The `SigningKeySecret` is critical. **Never** hardcode it in source control for production. Use secure management practices (Environment Variables, Azure Key Vault, AWS Secrets Manager, etc.). It **must** be cryptographically strong and meet the length requirements for the chosen algorithm (at least 32 bytes for the default HS256).

### 3. Application Setup (`Program.cs`)

```csharp
using CoreIdent.Core.Configuration; // Contains CoreIdentOptions if needed directly
using CoreIdent.Core.Extensions;
using CoreIdent.Core.Models; // Contains CoreIdentUser if using Delegated adapter delegates
using CoreIdent.Storage.EntityFrameworkCore.Extensions; // For EF Core store
using CoreIdent.Storage.EntityFrameworkCore.Stores; // For explicit store registration (Delegated scenario)
using CoreIdent.Adapters.DelegatedUserStore.Extensions; // For Delegated adapter
using Microsoft.AspNetCore.Authentication.JwtBearer; // For API token validation
using Microsoft.EntityFrameworkCore; // If using EF Core
using Microsoft.IdentityModel.Tokens; // For TokenValidationParameters
using System.Security.Claims; // For Claims List example
using System.Text; // For Encoding

var builder = WebApplication.CreateBuilder(args);

// *** 1. Configure CoreIdent Core Services ***
builder.Services.AddCoreIdent(options =>
{
    // Bind options from configuration (e.g., appsettings.json section "CoreIdent")
    builder.Configuration.GetSection("CoreIdent").Bind(options);

    // You can also set options directly here if needed
    // options.Issuer = "https://my-issuer.com";
    // options.TokenSecurity.EnableTokenFamilyTracking = false; // Example: Opt-out of default
});

// *** 2. Configure API Authentication (Optional - If your API validates CoreIdent JWTs) ***
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme) // Set default scheme
    .AddJwtBearer(options =>
    {
        // Configure validation parameters based on CoreIdentOptions
        // It's often cleaner to bind options once and reuse
        var coreIdentOptions = builder.Configuration.GetSection("CoreIdent").Get<CoreIdentOptions>()!;
        if (coreIdentOptions == null || string.IsNullOrEmpty(coreIdentOptions.SigningKeySecret))
        {
            throw new InvalidOperationException("CoreIdent options (Issuer, Audience, SigningKeySecret) must be configured.");
        }

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(coreIdentOptions.SigningKeySecret)),

            ValidateIssuer = true,
            ValidIssuer = coreIdentOptions.Issuer,

            ValidateAudience = true,
            ValidAudience = coreIdentOptions.Audience,

            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(1) // Allow some clock skew
        };
        // options.Authority = coreIdentOptions.Issuer; // Usually needed if keys fetched from /.well-known/openid-configuration
    });

builder.Services.AddAuthorization(); // Needed for [Authorize] attributes


// *** 3. Configure Storage (Choose ONE strategy for IUserStore, IRefreshTokenStore etc.) ***

// --- Option A: Entity Framework Core (Recommended for new apps or full control) ---
// Prerequisite: Add NuGet packages CoreIdent.Storage.EntityFrameworkCore and a DB provider (e.g., Microsoft.EntityFrameworkCore.Sqlite)

// i. Register your DbContext (make sure it inherits from CoreIdent.Storage.EntityFrameworkCore.CoreIdentDbContext or includes its entity configurations)
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? "DataSource=coreident_readme.db;Cache=Shared";
// Replace YourAppDbContext with your actual DbContext class name if you have one
// If you don't have one, you can use CoreIdentDbContext directly for CoreIdent data
builder.Services.AddDbContext<CoreIdent.Storage.EntityFrameworkCore.CoreIdentDbContext>(options =>
    options.UseSqlite(connectionString)); // Use your desired provider (UseSqlServer, UseNpgsql, etc.)

// ii. Tell CoreIdent to use the EF Core stores mapped to your DbContext type
// This MUST be called AFTER AddCoreIdent() and AddDbContext()
// This registers EF Core implementations for: IUserStore, IRefreshTokenStore, IClientStore, IScopeStore, IAuthorizationCodeStore
// Replace YourAppDbContext if you used your own DbContext above
builder.Services.AddCoreIdentEntityFrameworkStores<CoreIdent.Storage.EntityFrameworkCore.CoreIdentDbContext>();

// iii. IMPORTANT: Remember to add and apply EF Core migrations:
//    1. dotnet ef migrations add InitialCreate --context CoreIdent.Storage.EntityFrameworkCore.CoreIdentDbContext -o Data/Migrations -p path/to/YourWebAppProject -s path/to/YourWebAppProject
//    2. dotnet ef database update --context CoreIdent.Storage.EntityFrameworkCore.CoreIdentDbContext -p path/to/YourWebAppProject -s path/to/YourWebAppProject
//    Adjust context name and paths as needed. The -o specifies output dir for migrations.

// --- Option B: Delegated User Store (For integrating with existing user systems) ---
/* // Uncomment to use Delegated Store
// Prerequisite: Add NuGet package CoreIdent.Adapters.DelegatedUserStore

// This replaces the default IUserStore registration (In-Memory or EF Core)
builder.Services.AddCoreIdentDelegatedUserStore(options =>
{
    // Provide delegates that call your existing user management logic
    // These are examples, implement your actual logic. Return null if user not found.

    // REQUIRED: Find user by their unique ID (adjust types as needed)
    options.FindUserByIdAsync = async (userId, ct) => {
        Console.WriteLine($"Delegate: Finding user by ID: {userId}");
        // Your logic to find user by ID in your system...
        // Example: var user = await myUserService.FindByIdAsync(userId);
        // Return a CoreIdentUser representation or null
        if (userId == "user1_id") return new CoreIdentUser { Id = "user1_id", UserName = "existing_user@example.com", NormalizedUserName = "EXISTING_USER@EXAMPLE.COM" };
        return null;
    };

    // REQUIRED: Find user by username/email (use normalized form for lookups)
    options.FindUserByUsernameAsync = async (normalizedUsername, ct) => {
        Console.WriteLine($"Delegate: Finding user by Normalized Username: {normalizedUsername}");
        // Your logic to find user by username/email in your system...
        // Example: var user = await myUserService.FindByEmailAsync(username); // Assuming username is email
        // Return a CoreIdentUser representation or null
         if (normalizedUsername == "EXISTING_USER@EXAMPLE.COM") return new CoreIdentUser { Id = "user1_id", UserName = "existing_user@example.com", NormalizedUserName = "EXISTING_USER@EXAMPLE.COM" };
        return null;
    };

    // REQUIRED: Validate user credentials
    options.ValidateCredentialsAsync = async (username, password, ct) => {
        Console.WriteLine($"Delegate: Validating credentials for: {username}");
        // Your logic to validate the password against your system...
        // Example: bool isValid = await myAuthService.CheckPasswordAsync(username, password);
        // Return true if valid, false otherwise
        return (username == "existing_user@example.com" && password == "password123"); // Example check
    };

    // OPTIONAL: Get user claims
    options.GetClaimsAsync = async (user, ct) => {
         Console.WriteLine($"Delegate: Getting claims for: {user.UserName}");
        // Your logic to get claims for the user...
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id!),
            new Claim(ClaimTypes.Name, user.UserName!),
            // Add other claims from your system
            new Claim("custom_claim", "custom_value")
        };
        return await Task.FromResult(claims);
    };

     // OPTIONAL: Create user (if you want /register to work with your system)
     options.CreateUserAsync = async (user, password, ct) => {
         Console.WriteLine($"Delegate: Creating user: {user.UserName}");
         // Your logic to create the user and hash/store the password in your system...
         // Example: var userId = await myUserService.CreateAsync(user.UserName, password);
         // Populate the user object with the ID generated by your system
         user.Id = Guid.NewGuid().ToString(); // Example ID generation
         // Return StoreResult.Success or StoreResult.Failure/Conflict
         return await Task.FromResult(CoreIdent.Core.Stores.StoreResult.Success);
     };
});

// NOTE: Delegated IUserStore only handles users. You STILL need persistent storage for
// Refresh Tokens, Authorization Codes, Clients, and Scopes.
// Register the EF Core stores separately in this case:
// i. Register DbContext (as shown in Option A)
// ii. Register the needed stores (EF Core stores are recommended)
builder.Services.AddScoped<CoreIdent.Core.Stores.IRefreshTokenStore, EfRefreshTokenStore>();
builder.Services.AddScoped<CoreIdent.Core.Stores.IAuthorizationCodeStore, EfAuthorizationCodeStore>(); // Requires EfAuthorizationCodeStore implementation
builder.Services.AddScoped<CoreIdent.Core.Stores.IClientStore, EfClientStore>();
builder.Services.AddScoped<CoreIdent.Core.Stores.IScopeStore, EfScopeStore>();
// Ensure migrations for Refresh Tokens, Auth Codes, Clients, Scopes tables are applied (as shown in Option A).
*/


// Add other services like Controllers, Razor Pages, Swagger, etc.
builder.Services.AddEndpointsApiExplorer(); // For Swagger
builder.Services.AddSwaggerGen();       // For Swagger

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    // Seed database or perform other dev-time actions
    // Example: Seed data if using EF Core
    /* // Uncomment to seed data
    using (var scope = app.Services.CreateScope())
    {
        var dbContext = scope.ServiceProvider.GetRequiredService<CoreIdent.Storage.EntityFrameworkCore.CoreIdentDbContext>(); // Use your DbContext type
        // Ensure DB is created
        // dbContext.Database.EnsureCreated(); // Alternatively use migrations
        // Add seeding logic here (e.g., add default clients/scopes for Phase 3+)
    }
    */
}

app.UseHttpsRedirection();

app.UseAuthentication(); // Must be called before UseAuthorization
app.UseAuthorization();

// Map CoreIdent endpoints (default prefix is /auth)
app.MapCoreIdentEndpoints("/auth"); // Use basePath parameter to change, e.g., app.MapCoreIdentEndpoints(basePath: "/identity");

// Map your application's endpoints/controllers
app.MapGet("/", () => "Hello World!");
// Example protected endpoint
app.MapGet("/protected", (ClaimsPrincipal user) => $"Hello {user.Identity?.Name}! You are authenticated.")
   .RequireAuthorization();


app.Run();

```

### 4. Core Functionality Available Now (Phase 3 In Progress)

With the setup above, the following CoreIdent endpoints are available (default prefix `/auth`):

*   `POST /auth/register`: Register a new user (requires non-delegated `IUserStore`, e.g., EF Core, or `CreateUserAsync` delegate).
    *   **Request Body**: `{ "email": "user@example.com", "password": "YourPassword123!" }`
    *   **Response Status Codes**: `201 Created`, `400 Bad Request`, `409 Conflict`
    *   **Usage Example (curl)**:
        ```bash
        curl -X POST "https://localhost:5001/auth/register" \
          -H "Content-Type: application/json" \
          -d '{"email": "user@example.com", "password": "YourSecurePassword123!"}'
        ```

*   `POST /auth/login`: Authenticates a user with email/password and issues JWT tokens.
    *   **Request Body**: `{ "email": "user@example.com", "password": "YourPassword123!" }`
    *   **Response Status Codes**: `200 OK`, `400 Bad Request`, `401 Unauthorized`, `500 Internal Server Error`
    *   **Response Body**:
        ```json
        {
          "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
          "token_type": "Bearer",
          "expires_in": 900, // Default Access Token Lifetime
          "refresh_token": "abcdef123456..." // Opaque handle (raw value)
        }
        ```
    *   **Token Structure**: JWT Access Token + Opaque Refresh Token handle.
    *   **Security Considerations**: Store tokens securely, use HTTPS. `SigningKeySecret` is critical.
    *   **Usage Example (curl)**:
        ```bash
        curl -X POST "https://localhost:5001/auth/login" \
          -H "Content-Type: application/json" \
          -d '{"email": "user@example.com", "password": "YourSecurePassword123!"}'
        ```

*   `POST /auth/token/refresh`: Exchange a valid refresh token for new tokens (uses `IRefreshTokenStore`).
    *   **Request Body**: `{ "refreshToken": "abcdef123456..." }`
    *   **Response Body**: (Same as login)
    *   **Security**: Implements refresh token rotation and **token theft detection** (family tracking & revocation) by default. You can opt-out via `CoreIdentOptions.TokenSecurity.EnableTokenFamilyTracking = false`.

**OAuth 2.0 / OIDC Endpoints (Phase 3):**

*   `GET /auth/authorize`: Initiates the Authorization Code flow. Validates the request, authenticates the user, and redirects back with an authorization code.
    *   Required parameters: `client_id`, `redirect_uri`, `response_type=code`, `scope`
    *   Recommended parameters: `state`, `nonce`
    *   PKCE parameters: `code_challenge`, `code_challenge_method=S256`
    *   Example: `/auth/authorize?client_id=my-client&response_type=code&redirect_uri=https://my-app.com/callback&scope=openid%20profile&state=abc123&code_challenge=<challenge>&code_challenge_method=S256`
*   `POST /auth/token` (grant_type=authorization_code): Exchanges an authorization code for tokens.
    *   Required parameters (form-encoded): `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier` (for PKCE)
    *   Confidential clients also require authentication.
    *   Returns: `{ "access_token": "...", "token_type": "Bearer", "expires_in": 900, "refresh_token": "...", "id_token": "..." }`

**Storage:**
*   **EF Core:** Provides persistence for users, refresh tokens, clients, scopes, and auth codes. Requires `CoreIdent.Storage.EntityFrameworkCore` and DB migrations.
*   **Delegated:** Adapts user operations (`IUserStore`) to your existing system via `CoreIdent.Adapters.DelegatedUserStore`. **Requires** separate persistent stores (like EF Core) for refresh tokens, auth codes, clients, and scopes.
*   **Refresh Tokens:** Persisted (usually via EF Core) with the raw handle stored as the primary key and a **securely hashed handle (salted SHA-256)** stored separately. Tokens are rotated upon use, and token theft detection is enabled by default (`EnableTokenFamilyTracking: true`).

## Running / Testing

1.  Ensure you have the .NET SDK (9+) installed.
2.  Clone the repository: `git clone https://github.com/stimpy77/CoreIdent.git`
3.  Navigate to the test directory: `cd CoreIdent/tests`
4.  Run tests: `dotnet test`
    *   *(Note: Integration tests require database setup/migrations. The test projects typically configure their own in-memory SQLite databases.)*

## License

CoreIdent is licensed under the [MIT License](LICENSE).

## Contributing

⭐ **Star this repo if you believe in the mission!** ⭐

Contributions, feedback, and ideas are highly welcome! Please refer to the (upcoming) contribution guidelines or open an issue to discuss. Let's build the future of .NET identity together.
