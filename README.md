# CoreIdent: Modern .NET Identity & Authentication

![image](https://github.com/user-attachments/assets/96ac08ce-d88e-4d78-af98-101bb95aa317)

[![Build Status](https://github.com/stimpy77/CoreIdent/actions/workflows/dotnet.yml/badge.svg)](https://github.com/stimpy77/CoreIdent/actions/workflows/dotnet.yml)
[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![NuGet Version](https://img.shields.io/nuget/v/CoreIdent.Core.svg)](https://www.nuget.org/packages/CoreIdent.Core/)

**CoreIdent is building the foundation for a modern, open-source, developer-centric identity and authentication solution for .NET.** It aims to replace complex, often vendor-locked systems with a flexible, convention-driven alternative that empowers developers.

**Think: A spiritual successor to IdentityServer, built for today's .NET.**

**Current Status:** Phase 2 (Persistent Storage & Delegated Adapter) is complete. Phase 3 (Core OAuth/OIDC Flows) development is underway.

**Development Phases:**
*   **Phase 1 (Completed):** MVP - Core Registration/Login/Tokens with In-Memory Storage.
*   **Phase 2 (Completed):** Persistent Storage (EF Core), Delegated Adapter & Interface Refinement.
*   **Phase 3 (Current):** Core OAuth 2.0 / OIDC Server Mechanics (Authorization Code Flow + PKCE, Client Credentials, Discovery).
*   **Phase 4:** User Interaction & External Integrations (Consent, UI, MFA, Passwordless).
*   **Phase 5:** Advanced Features & Polish (More Flows, Extensibility, Templates).

## Why CoreIdent?

Tired of wrestling with complex identity vendors or rolling your own auth from scratch? CoreIdent offers a different path:

*   🚀 **Developer Freedom & Experience:** Open-source (MIT) with a focus on minimizing boilerplate and maximizing productivity through conventions and clear APIs. Get secure auth running *fast*.
*   🧩 **Modularity & Extensibility:** A lean core with features (like storage, providers) added via separate NuGet packages. Use only what you need.
*   🔒 **Secure by Default:** Implements security best practices for token handling (JWTs, refresh token rotation), password storage, and endpoint protection.
*   🔧 **Flexible Storage:** Choose between integrated persistence (Entity Framework Core) or adapt to existing user systems with the Delegated User Store.
*   🌐 **Future-Ready:** Built on modern .NET (9+), designed to support traditional credentials, modern passwordless methods (Passkeys/WebAuthn), and decentralized approaches (Web3, LNURL) in future phases.
*   🚫 **No Vendor Lock-In:** Own your identity layer.

## Current State vs. Future Vision

**What CoreIdent provides *today* (Phase 2 Complete):**

*   **Core Authentication API:** Secure `/register`, `/login`, and `/token/refresh` endpoints.
*   **JWT Issuance:** Standard access tokens upon login.
*   **Refresh Token Management:** Secure refresh token generation, persistent storage (EF Core), and rotation.
*   **Password Hashing:** Secure password handling using ASP.NET Core Identity's hasher.
*   **Pluggable Storage:**
    *   `CoreIdent.Storage.EntityFrameworkCore`: Store users and refresh tokens in your database (SQL Server, PostgreSQL, SQLite, etc.).
    *   `CoreIdent.Adapters.DelegatedUserStore`: Integrate with your existing user database/authentication logic.
*   **Core Services:** `ITokenService`, `IPasswordHasher`, `IUserStore`, `IRefreshTokenStore` interfaces for customization.
*   **Configuration:** Easy setup via `AddCoreIdent()` and `appsettings.json`.

**Where CoreIdent is heading (Future Phases):**

*   **Full OAuth 2.0 / OIDC Server:** Implementing standard flows (Authorization Code + PKCE, Client Credentials, Implicit, Hybrid) for web apps, SPAs, mobile apps, and APIs.
*   **OIDC Compliance:** Discovery (`/.well-known/openid-configuration`), JWKS (`/.well-known/jwks.json`), ID Tokens.
*   **User Interaction:** Consent screens, standard logout endpoints.
*   **Extensible Provider Model:**
    *   **MFA:** Pluggable Multi-Factor Authentication (TOTP, SMS, Email).
    *   **Passwordless:** Passkeys / WebAuthn / FIDO2.
    *   **Social Logins:** Google, Microsoft, etc.
    *   **Decentralized:** Web3 Wallet Login (MetaMask), LNURL-auth.
*   **UI Components:** Optional package (`CoreIdent.UI.Web`) providing basic, themeable UI (Razor Pages/Components) for login, registration, consent, etc.
*   **Administration:** Optional Admin UI for managing users, clients, scopes.
*   **Tooling:** `dotnet new` templates, comprehensive documentation.

**Is this a replacement for IdentityServer?**

**Not yet, but that's the goal.** We are building the foundational pieces first, focusing on a solid core and flexible storage. Phase 3 is actively adding the core OAuth/OIDC mechanics.

## Developer Guide

For a detailed walkthrough of the architecture, setup, and features through Phase 2, please refer to the **[Developer Training Guide](./docs/Developer_Training_Guide.md)**.

## Getting Started

This guide covers the setup for the core functionality available after Phase 2.

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
    "RefreshTokenLifetime": "7.00:00:00" // 7 days
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


// *** 3. Configure Storage (Choose ONE strategy for IUserStore) ***

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
    options.ValidateCredentialsAsync = async (user, password, ct) => {
        Console.WriteLine($"Delegate: Validating credentials for: {user.UserName}");
        // Your logic to validate the password against your system...
        // Example: bool isValid = await myAuthService.CheckPasswordAsync(user.UserName, password);
        // Return true if valid, false otherwise
        return (user.UserName == "existing_user@example.com" && password == "password123"); // Example check
    };

    // OPTIONAL: Get user claims
    options.GetClaimsAsync = async (user, ct) => {
         Console.WriteLine($"Delegate: Getting claims for: {user.UserName}");
        // Your logic to get claims for the user...
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Name, user.UserName),
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

// NOTE: Delegated IUserStore only handles users. You STILL need persistent storage for Refresh Tokens.
// Register the EF Core Refresh Token Store separately in this case:
// i. Register DbContext (as shown in Option A)
// ii. Register ONLY the refresh token store
builder.Services.AddScoped<CoreIdent.Core.Stores.IRefreshTokenStore, EfRefreshTokenStore>();
// Ensure migrations for Refresh Tokens table are applied (as shown in Option A).
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
app.MapCoreIdentEndpoints(); // Use basePath parameter to change, e.g., app.MapCoreIdentEndpoints(basePath: "/identity");

// Map your application's endpoints/controllers
app.MapGet("/", () => "Hello World!");
// Example protected endpoint
app.MapGet("/protected", (ClaimsPrincipal user) => $"Hello {user.Identity?.Name}! You are authenticated.")
   .RequireAuthorization();


app.Run();

```

### 4. Core Functionality Available Now (Phase 2)

With the setup above, the following CoreIdent endpoints are available (default prefix `/auth`):

*   `POST /auth/register`: Register a new user (requires non-delegated `IUserStore`, e.g., EF Core, or `CreateUserAsync` delegate). Request body: `{ "email": "user@example.com", "password": "YourPassword123!" }`
*   `POST /auth/login`: Log in with email/password. Returns JWT access and refresh tokens. Request body: `{ "email": "user@example.com", "password": "YourPassword123!" }` Response body: `{ "accessToken": "...", "refreshToken": "...", "expiresIn": 900 }`
*   `POST /auth/token/refresh`: Exchange a valid refresh token for new tokens (uses `IRefreshTokenStore`). Request body: `{ "refreshToken": "..." }` Response body: (Same as login)

**Storage:**
*   **EF Core:** Provides persistence for users and refresh tokens. (Client/Scope storage coming in Phase 3). Requires `CoreIdent.Storage.EntityFrameworkCore` and DB migrations.
*   **Delegated:** Adapts user operations (`IUserStore`) to your existing system via `CoreIdent.Adapters.DelegatedUserStore`. **Requires** a separate persistent store (like EF Core's `EfRefreshTokenStore`) for refresh tokens.
*   **Refresh Tokens:** Persisted (usually via EF Core) and rotated upon use for security.

## Running / Testing

1.  Ensure you have the .NET SDK (9+) installed.
2.  Clone the repository: `git clone https://github.com/stimpy77/CoreIdent.git`
3.  Navigate to the test directory: `cd CoreIdent/tests`
4.  Run tests: `dotnet test`
    *   *(Note: Integration tests might require database setup/migrations depending on the test configuration).*

## License

CoreIdent is licensed under the [MIT License](LICENSE).

## Contributing

⭐ **Star this repo if you believe in the mission!** ⭐

Contributions, feedback, and ideas are highly welcome! Please refer to the (upcoming) contribution guidelines or open an issue to discuss. Let's build the future of .NET identity together.
