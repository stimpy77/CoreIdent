# CoreIdent: Modern .NET Identity & Authentication

![image](https://github.com/user-attachments/assets/96ac08ce-d88e-4d78-af98-101bb95aa317)

[![Build Status](https://github.com/stimpy77/CoreIdent/actions/workflows/dotnet.yml/badge.svg?branch=main)](https://github.com/stimpy77/CoreIdent/actions/workflows/dotnet.yml)
[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![NuGet Version](https://img.shields.io/nuget/v/CoreIdent.Core.svg)](https://www.nuget.org/packages/CoreIdent.Core/)

**CoreIdent is building the foundation for a modern, open-source, developer-centric identity and authentication solution for .NET.** It aims to replace complex, often vendor-locked systems with a flexible, convention-driven alternative that empowers developers.

**Think: A spiritual successor to IdentityServer, built for today's .NET.**

**Current Status:** Phase 2 (Persistent Storage & Delegated Adapter) is complete. Phase 3 (Core OAuth/OIDC Flows, Token Theft Detection) development is complete, with **Authorization Code Flow + PKCE, ID Token issuance, Token Theft Detection, OIDC Discovery & JWKS Endpoints, and Client Credentials Flow now complete**.

**Development Phases:**
*   **Phase 1 (Completed):** MVP - Core Registration/Login/Tokens with In-Memory Storage.
*   **Phase 2 (Completed):** Persistent Storage (EF Core), Delegated Adapter & Interface Refinement.
*   **Phase 3 (Completed):** Core OAuth 2.0 / OIDC Server Mechanics
    *   **Completed:** Authorization Code Flow with PKCE, ID Token Issuance, Token Theft Detection, OIDC Discovery & JWKS Endpoints, Client Credentials Flow.
*   **Phase 4:** User Interaction & External Integrations (Consent, UI, MFA, Passwordless).
*   **Phase 5:** Advanced Features & Polish (More Flows, Extensibility, Templates).
*   **Phase 6:** Client Libraries for Mobile & Desktop Applications.

## Why CoreIdent?

Tired of wrestling with complex identity vendors or rolling your own auth from scratch? CoreIdent offers a different path:

*   **Developer Freedom & Experience:** Open-source (MIT) with a focus on minimizing boilerplate and maximizing productivity through conventions and clear APIs. Get secure auth running *fast*.
*   **Modularity & Extensibility:** A lean core with features (like storage, providers) added via separate NuGet packages. Use only what you need.
*   **Secure by Default:** Implements security best practices for token handling (JWTs, refresh token rotation, **token theft detection** using family tracking, **securely hashed token handle storage**), password storage, and endpoint protection.
*   **Flexible Storage:** Choose between integrated persistence (Entity Framework Core) or adapt to existing user systems with the Delegated User Store.
*   **OIDC Discovery & JWKS Endpoints:** Standards-compliant `/.well-known/openid-configuration` and `/.well-known/jwks.json` endpoints for OIDC metadata and public key discovery. Convention-based, robust error handling, and automatic DI for `JwtTokenService`—no manual registration needed.
*   **Future-Ready:** Built on modern .NET (9+), designed to support traditional credentials, modern passwordless methods (Passkeys/WebAuthn), and decentralized approaches (Web3, LNURL) in future phases.
*   **No Vendor Lock-In:** Own your identity layer.

## Current State vs. Future Vision

**What CoreIdent provides *today* (Phase 3 Complete):**

*   **Core Authentication API:** Secure `/auth/register`, `/auth/login`, and `/auth/token/refresh` endpoints (default prefix `/auth`).
*   **JWT Issuance:** Standard access tokens upon login.
*   **Refresh Token Management:** Secure refresh token generation, persistent storage (EF Core), rotation, **securely hashed token handle storage** (raw handle returned to client, hash stored in DB), and **token theft detection** with family revocation (enabled by default).
*   **OAuth/OIDC:**
    *   **Authorization Code Flow with PKCE:** Secure flow for web apps, SPAs, and mobile clients via `/auth/authorize` and `/auth/token` (grant type `authorization_code`). PKCE is enforced.
    *   **ID Token Issuance:** Standard OIDC ID tokens are generated alongside access tokens for the Authorization Code flow.
*   **Password Hashing:** Secure password handling using ASP.NET Core Identity's hasher.
*   **Pluggable Storage:**
    *   `CoreIdent.Storage.EntityFrameworkCore`: Store users, refresh tokens, clients, scopes, **and authorization codes** in your database (SQL Server, PostgreSQL, SQLite, etc.).
    *   `CoreIdent.Adapters.DelegatedUserStore`: Integrate with your existing user database/authentication logic.
*   **Core Services:** `ITokenService`, `IPasswordHasher`, `IUserStore`, `IRefreshTokenStore`, `IClientStore`, `IScopeStore`, `IAuthorizationCodeStore` interfaces for customization. **EF Core implementations** (e.g., `EfAuthorizationCodeStore`) are registered automatically when using `AddCoreIdentEntityFrameworkStores`.
*   **Authorization Code Storage & Cleanup:** Authorization codes issued during OAuth flows are persisted in the database via EF Core (`EfAuthorizationCodeStore`). Expired codes are automatically cleaned up by a background service (`AuthorizationCodeCleanupService`) registered by default. The store implementation includes robust concurrency handling to prevent race conditions during code redemption and cleanup.
*   **Configuration:** Easy setup via `AddCoreIdent()` and `appsettings.json`.

## OpenID Connect ID Token Issuance

CoreIdent issues an **ID Token** as part of the OpenID Connect Authorization Code flow. The ID Token is a signed JWT and contains the following claims:

| Claim      | Description                                           |
|------------|-------------------------------------------------------|
| iss        | Issuer identifier for the authorization server        |
| sub        | Subject identifier (user ID)                         |
| aud        | Audience (client ID or resource)                     |
| exp        | Expiration time (epoch seconds)                      |
| iat        | Issued-at time (epoch seconds)                       |
| nonce      | Value to associate a client session with the token    |
| name       | User's display name (if profile scope requested)      |
| email      | User's email (if email scope requested)               |

**Example ID Token Payload:**
```json
{
  "iss": "https://your-issuer.com",
  "sub": "user-guid-or-id",
  "aud": "client-id",
  "exp": 1713559200,
  "iat": 1713555600,
  "nonce": "random-nonce-value",
  "name": "Jane Doe",
  "email": "jane@example.com"
}
```

- The ID Token is returned in the `id_token` property of the `/token` endpoint response when the `openid` scope is requested.
- Claims included depend on the requested scopes and user data.
- The token is signed using the configured signing key.

See the [DEVPLAN.md](./DEVPLAN.md) for test coverage and implementation status.

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
    "Audience": "https://localhost:5001",             // IMPORTANT: Replace with your API audience identifier
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

**⚠️ Important Security Note:** The `SigningKeySecret` (and any ClientSecrets for confidential clients) are critical. **Never** store them in source control for production. Use secure management practices (Environment Variables, Azure Key Vault, AWS Secrets Manager, etc.). They **must** be cryptographically strong, unique, and kept confidential.

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

// i. Register your DbContext.
//    Ensure your DbContext class (e.g., YourAppDbContext) either:
//      a) Inherits from CoreIdent.Storage.EntityFrameworkCore.CoreIdentDbContext, OR
//      b) Includes CoreIdent's entity configurations by calling 
//         `modelBuilder.ApplyConfigurationsFromAssembly(typeof(CoreIdentDbContext).Assembly);` 
//         within its own `OnModelCreating` method.
//
//    Example a) Inheritance:
//    ```csharp
//    // In YourApplicationDbContext.cs
//    using CoreIdent.Storage.EntityFrameworkCore;
//    using Microsoft.EntityFrameworkCore;
//    
//    public class YourApplicationDbContext : CoreIdentDbContext // Inherit here
//    {
//        // Your application's specific DbSets
//        public DbSet<YourAppEntity> YourAppEntities { get; set; }
//
//        public YourApplicationDbContext(DbContextOptions<YourApplicationDbContext> options)
//            : base(options) // Pass options to base constructor
//        {
//        }
//
//        protected override void OnModelCreating(ModelBuilder modelBuilder)
//        {
//            base.OnModelCreating(modelBuilder); // IMPORTANT: Call base implementation FIRST
//
//            // Your application's specific entity configurations
//            modelBuilder.Entity<YourAppEntity>().HasKey(e => e.Id);
//            // ... other configurations ...
//        }
//    }
//    ```
//
//    Example b) ApplyConfigurationsFromAssembly:
//    ```csharp
//    // In YourApplicationDbContext.cs
//    using CoreIdent.Storage.EntityFrameworkCore; // Needed for CoreIdentDbContext type
//    using Microsoft.EntityFrameworkCore;
//    
//    public class YourApplicationDbContext : DbContext // Inherit from standard DbContext
//    {
//        // Your application's specific DbSets
//        public DbSet<YourAppEntity> YourAppEntities { get; set; }
//
//        // CoreIdent's DbSets (if you need to access them directly, otherwise optional)
//        // public DbSet<CoreIdentUser> Users { get; set; }
//        // public DbSet<CoreIdentRefreshToken> RefreshTokens { get; set; }
//        // ... etc ...
//
//        public YourApplicationDbContext(DbContextOptions<YourApplicationDbContext> options)
//            : base(options)
//        {
//        }
//
//        protected override void OnModelCreating(ModelBuilder modelBuilder)
//        {
//            base.OnModelCreating(modelBuilder); 
//
//            // Apply CoreIdent's configurations
//            modelBuilder.ApplyConfigurationsFromAssembly(typeof(CoreIdentDbContext).Assembly); // Apply CoreIdent configurations
//
//            // Your application's specific entity configurations
//            modelBuilder.Entity<YourAppEntity>().HasKey(e => e.Id);
//            // ... other configurations ...
//        }
//    }
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? "DataSource=coreident_readme.db;Cache=Shared";
builder.Services.AddDbContext<YourApplicationDbContext>(options => // Replace YourApplicationDbContext with your actual DbContext class name
    options.UseSqlite(connectionString)); // Use your desired provider (UseSqlServer, UseNpgsql, etc.)

// ii. Register CoreIdent services and THEN the EF Core stores.
//    DI Registration Order is IMPORTANT:
//    1. AddCoreIdent()
//    2. AddDbContext<YourDbContext>()
//    3. AddCoreIdentEntityFrameworkStores<YourDbContext>()
builder.Services.AddCoreIdentEntityFrameworkStores<YourApplicationDbContext>(); // Registers EfUserStore, EfRefreshTokenStore, EfClientStore, EfScopeStore, EfAuthorizationCodeStore, and background cleanup services (including AuthorizationCodeCleanupService) by default.

// iii. IMPORTANT: Add and apply EF Core migrations.
//     Run these commands from the directory containing your solution file (.sln) or adjust paths accordingly.
//    1. Add Migration (generates migration code in the storage project):
//       dotnet ef migrations add InitialCoreIdentSchema --context YourApplicationDbContext --project src/CoreIdent.Storage.EntityFrameworkCore --startup-project src/YourWebAppProject -o Data/Migrations
//       - Replace YourApplicationDbContext with your DbContext class name.
//       - Replace src/CoreIdent.Storage.EntityFrameworkCore with the path to the CoreIdent storage project.
//       - Replace src/YourWebAppProject with the path to your web application project.
//       - The -o parameter specifies the output directory within the storage project.
//    2. Update Database (applies the migration to your database):
//       dotnet ef database update --context YourApplicationDbContext --startup-project src/YourWebAppProject
//       - Ensure the --startup-project points to your web application.

// --- Option B: Delegated User Store (For integrating with existing user systems) ---
/* // Uncomment to use Delegated Store
// ... existing code ...
// NOTE: Delegated IUserStore only handles users. You STILL need persistent storage for
// Refresh Tokens, Authorization Codes, Clients, and Scopes.
// Register the EF Core stores separately in this case following the same DI order principles:
// 1. AddCoreIdent()
// 2. AddDbContext<YourDbContext>()
// 3. AddCoreIdentDelegatedUserStore() // Registers Delegated IUserStore
// 4. Manually register the other EF Core stores you need:
//    builder.Services.AddScoped<CoreIdent.Core.Stores.IRefreshTokenStore, EfRefreshTokenStore>();
//    builder.Services.AddScoped<CoreIdent.Core.Stores.IAuthorizationCodeStore, EfAuthorizationCodeStore>(); // TODO: Create EfAuthorizationCodeStore 
//    builder.Services.AddScoped<CoreIdent.Core.Stores.IClientStore, EfClientStore>();
//    builder.Services.AddScoped<CoreIdent.Core.Stores.IScopeStore, EfScopeStore>();
// Ensure migrations for the required tables (RefreshTokens, Auth Codes, Clients, Scopes) are applied (see Option A).

builder.Services.AddCoreIdentDelegatedUserStore(options =>
{
    // REQUIRED: Provide functions to find users and validate credentials
    // These delegates bridge CoreIdent to YOUR existing user system.

    options.FindUserByIdAsync = async (userId, ct) => {
        // Example: Replace with your actual user service call
        // var externalUser = await myExternalUserService.FindByIdAsync(userId);
        // if (externalUser == null) return null;
        // return new CoreIdentUser { Id = externalUser.Id, UserName = externalUser.Email, ... };
        await Task.Delay(10); // Placeholder
        Console.WriteLine($"Delegated: Finding user by ID: {userId}");
        return new CoreIdentUser { Id = userId, UserName = $"{userId}@delegated.com", Email = $"{userId}@delegated.com", NormalizedUserName = $"{userId}@delegated.com".ToUpperInvariant() }; // Example mapping
    };

    options.FindUserByUsernameAsync = async (normalizedUsername, ct) => {
        // Example: Replace with your actual user service call
        // var externalUser = await myExternalUserService.FindByUsernameAsync(normalizedUsername);
        // if (externalUser == null) return null;
        // return new CoreIdentUser { Id = externalUser.Id, UserName = externalUser.Email, ... };
         await Task.Delay(10); // Placeholder
         Console.WriteLine($"Delegated: Finding user by Username: {normalizedUsername}");
         // Simulate finding a user for the example
         if (normalizedUsername == "DELEGATED@EXAMPLE.COM") {
             return new CoreIdentUser { Id = "delegated-user-123", UserName = "delegated@example.com", Email = "delegated@example.com", NormalizedUserName = "DELEGATED@EXAMPLE.COM" };
         }
         return null;
    };

    // ⚠️ CRITICAL SECURITY WARNING ⚠️
    // The 'ValidateCredentialsAsync' delegate receives the user's PLAIN TEXT password.
    // YOUR implementation of this delegate MUST securely validate this password against
    // YOUR existing credential store (which MUST store hashed passwords).
    // CoreIdent's IPasswordHasher is BYPASSED in this flow.
    // YOU ARE RESPONSIBLE for the security of this validation process.
    options.ValidateCredentialsAsync = async (username, password, ct) => {
        // Example: Replace with your actual validation logic calling your service
        // return await myExternalUserService.CheckPasswordAsync(username, password);
         await Task.Delay(10); // Placeholder
         Console.WriteLine($"Delegated: Validating credentials for: {username}");
         // Simulate password check for the example user
         return username == "delegated@example.com" && password == "Password123!";
    };

    // Optional: Provide a function to get user claims if needed
    options.GetClaimsAsync = async (user, ct) => {
         await Task.Delay(10); // Placeholder
         Console.WriteLine($"Delegated: Getting claims for: {user.UserName}");
         return new List<Claim> { new Claim(ClaimTypes.GivenName, "Delegated"), new Claim(ClaimTypes.Role, "User") };
    };
});
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

// Map CoreIdent endpoints
app.MapCoreIdentEndpoints(options =>
{
    // Example: Customize the base path or specific endpoints
    // options.BasePath = "/identity";
    // options.RegisterPath = "signup";
});

// Map your application's endpoints/controllers
app.MapGet("/", () => "Hello World!");
// Example protected endpoint
app.MapGet("/protected", (ClaimsPrincipal user) => $"Hello {user.Identity?.Name}! You are authenticated.")
   .RequireAuthorization();


app.Run();