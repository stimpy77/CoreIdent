# CoreIdent: Modern .NET Identity & Authentication

![image](https://github.com/user-attachments/assets/96ac08ce-d88e-4d78-af98-101bb95aa317)

[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A simple, extensible core identity system for .NET apps, designed for flexibility, not vendor lock-in.

**Current Status:** Phase 2 (Persistent Storage & Delegated Adapter) is complete. Phase 3 (Core OAuth/OIDC Flows) development is underway.

**Development Phases:**
*   **Phase 1 (Completed):** MVP - Core Registration/Login/Tokens with In-Memory Storage.
*   **Phase 2 (Completed):** Persistent Storage (EF Core), Delegated Adapter & Interface Refinement.
*   **Phase 3 (Current):** Core OAuth 2.0 / OIDC Server Mechanics (Authorization Code Flow + PKCE, Client Credentials, Discovery).
*   **Phase 4:** User Interaction & External Integrations (Consent, UI, MFA, Passwordless).
*   **Phase 5:** Advanced Features & Polish (More Flows, Extensibility, Templates).

**CoreIdent** aims to be the modern, open-source, developer-friendly identity and authentication solution for the .NET ecosystem. It prioritizes convention over configuration, modularity, and ease of integration.

## Why CoreIdent?

In a world where authentication solutions are often complex or tied to specific vendors, CoreIdent stands out by offering:
*   **Developer Freedom:** Open-source (MIT) with no vendor lock-in. Build authentication your way.
*   **Convention Over Configuration:** Spend less time on setup. Our streamlined `AddCoreIdent()` method and sensible defaults get you started quickly with minimal code.
*   **Ease of Use:** Minimize boilerplate with sensible defaults and clear APIs. Get secure auth up and running fast.
*   **Modularity:** Core is lean; add only the features you need via separate NuGet packages (e.g., EF Core storage, Delegated adapter).
*   **Future-Proof:** Built on modern .NET (9+), supporting traditional logins, passwordless methods (Passkeys/WebAuthn), and even decentralized identity (Web3, LNURL).
*   **Security First:** Best practices baked in for token handling (including rotation), password storage, and endpoint protection.

## Future Vision

CoreIdent has established its core authentication and storage capabilities. Beyond Phase 2, we're building towards:

*   Full OAuth 2.0 / OIDC support for standard web and mobile app flows.
*   Pluggable providers for social logins, MFA, and cutting-edge auth (Passkeys, Web3 wallets).
*   User-friendly UI components and admin portals.
*   Comprehensive docs and `dotnet new` templates for effortless integration.

Join us in shaping the future of .NET identity! Contributions and feedback are welcome.

## Vision

Empower .NET developers to quickly implement secure authentication and authorization without vendor lock-in, embracing both traditional and emerging identity paradigms. Provide a clear path for extending functionality through a pluggable provider model.

## Core Principles

*   **Open Source (MIT):** Permissive and free to use.
*   **Developer Experience:** Minimize boilerplate, maximize productivity.
*   **Modular & Extensible:** Core is lean; features are add-ons.
*   **.NET Native:** Built on modern .NET (9+).
*   **Secure by Default:** Best practices for tokens, passwords, endpoints.
*   **Protocol Support:** Designed for modern web communication (HTTP/1.1, HTTP/2, HTTP/3, WebSocket-ready).
*   **Future-Ready Authentication:** Traditional credentials, Passkeys, Web3, LNURL.

## Developer Guide

For a detailed walkthrough of the architecture, setup, and features through Phase 2, please refer to the **[Developer Training Guide](./docs/Developer_Training_Guide.md)**.

## Getting Started

This guide covers the setup for the core functionality, including persistent storage options.

### 1. Installation

Install the core package and any desired storage adapters via NuGet:

```bash
dotnet add package CoreIdent.Core
dotnet add package CoreIdent.Storage.EntityFrameworkCore # For EF Core persistence
dotnet add package CoreIdent.Adapters.DelegatedUserStore # For delegating to existing systems
```

*(Note: If working directly from the source repository, add project references instead.)*

### 2. Configuration

Configure the core options in your `appsettings.json` (or another configuration source):

```json
{
  "CoreIdent": {
    "Issuer": "https://localhost:5001", // Replace with your actual issuer URI
    "Audience": "myapi",             // Replace with your API audience identifier
    "SigningKeySecret": "YOUR_SUPER_SECRET_KEY_REPLACE_THIS_LONGER_THAN_32_BYTES", // MUST be strong and kept secret!
    "AccessTokenLifetime": "00:15:00",  // 15 minutes
    "RefreshTokenLifetime": "7.00:00:00" // 7 days (relevant for later phases)
  }
}
```

**Important Security Note:** The `SigningKeySecret` MUST be a strong, unique secret, securely managed (e.g., environment variables, Azure Key Vault, AWS Secrets Manager), and **at least 32 bytes (256 bits)** long for HMAC-SHA256.

### 3. Application Setup

In your ASP.NET Core application's `Program.cs` (or `Startup.cs`):

```csharp
using CoreIdent.Core.Extensions;
// Add using statements for the storage adapters you choose:
// using CoreIdent.Storage.EntityFrameworkCore.Extensions;
// using CoreIdent.Adapters.DelegatedUserStore.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// ... other services

// 1. Configure CoreIdent Core Options
builder.Services.AddCoreIdent(options =>
{
    // Bind options from configuration (e.g., appsettings.json)
    builder.Configuration.GetSection("CoreIdent").Bind(options);
});

// 2. Configure Authentication/Authorization (for API token validation)
// If your API needs to validate CoreIdent JWTs:
builder.Services.AddAuthentication()
    .AddJwtBearer(options =>
    {
        // Configure validation parameters based on CoreIdentOptions
        var coreIdentOptions = builder.Configuration.GetSection("CoreIdent").Get<CoreIdent.Core.Configuration.CoreIdentOptions>()!;
        options.Authority = coreIdentOptions.Issuer; // Or configure manually
        options.Audience = coreIdentOptions.Audience;
        options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(coreIdentOptions.SigningKeySecret!)),
            ValidateIssuer = true, // Default: true
            ValidateAudience = true, // Default: true
            ClockSkew = TimeSpan.FromMinutes(1) // Allow some clock skew
        };
        // Additional validation parameters as needed...
    });

builder.Services.AddAuthorization();

// --- 3. Configure Storage --- 
// Choose ONE of the following storage options:

// Option A: Default In-Memory Store (NOT Recommended for Production)
// If you don't configure anything else after AddCoreIdent(), it uses transient in-memory stores.
// Suitable only for quick demos or certain testing scenarios.

// Option B: Entity Framework Core (Recommended for new databases)
/* // Uncomment to use EF Core Store
// Prerequisite: Add NuGet packages CoreIdent.Storage.EntityFrameworkCore and a DB provider (e.g., Microsoft.EntityFrameworkCore.Sqlite)

// Register your application's DbContext (ensure it includes CoreIdent entity configurations)
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? "DataSource=coreident.db;Cache=Shared";
builder.Services.AddDbContext<YourApplicationDbContext>(options => // Replace YourApplicationDbContext with your actual DbContext
    options.UseSqlite(connectionString));

// Tell CoreIdent to use the EF Core stores with your DbContext
// This MUST be called AFTER AddCoreIdent() and AddDbContext()
builder.Services.AddCoreIdentEntityFrameworkStores<YourApplicationDbContext>(); // Replace YourApplicationDbContext

// IMPORTANT: Remember to add and apply EF Core migrations:
// 1. dotnet ef migrations add InitialCoreIdentSchema --context YourApplicationDbContext -p path/to/CoreIdent.Storage.EntityFrameworkCore -s path/to/YourWebApp
// 2. dotnet ef database update --context YourApplicationDbContext -s path/to/YourWebApp
*/

// Option C: Delegated User Store (For existing user systems)
/* // Uncomment to use Delegated Store
// Prerequisite: Add NuGet package CoreIdent.Adapters.DelegatedUserStore

// This replaces the IUserStore registration (either In-Memory or EF Core)
builder.Services.AddCoreIdentDelegatedUserStore(options =>
{
    // REQUIRED: Provide a function to find a user by their unique ID
    options.FindUserByIdAsync = async (userId, ct) => { /* ... Your Logic ... */ return new CoreIdentUser { ... }; };

    // REQUIRED: Provide a function to find a user by username/email
    options.FindUserByUsernameAsync = async (normalizedUsername, ct) => { /* ... Your Logic ... */ return new CoreIdentUser { ... }; };

    // REQUIRED: Provide a function to validate credentials
    options.ValidateCredentialsAsync = async (username, password, ct) => { /* ... Your Logic ... */ return true; };

    // OPTIONAL: Provide a function to get user claims
    options.GetClaimsAsync = async (coreIdentUser, ct) => { /* ... Your Logic ... */ return new List<System.Security.Claims.Claim>(); };
});

// NOTE: You still need a persistent store for Refresh Tokens if using the Delegated adapter.
// Register the EF Core Refresh Token Store separately in this case:
// builder.Services.AddScoped<CoreIdent.Core.Stores.IRefreshTokenStore, CoreIdent.Storage.EntityFrameworkCore.Stores.EfRefreshTokenStore>();
// Ensure your DbContext is registered and migrations are applied as per Option B.
*/

// ... other services like Controllers, Swagger, etc.

var app = builder.Build();

// Configure the HTTP request pipeline.
// ... other middleware like HTTPS redirection, Swagger UI

app.UseAuthentication();
app.UseAuthorization();

// Map CoreIdent endpoints (e.g., under /auth/)
app.MapCoreIdentEndpoints(basePath: "/auth");

// Map your application's controllers/endpoints
// app.MapControllers();

app.Run();
```

### 4. Core Functionality (Through Phase 2)

With the setup above, the following endpoints provided by `CoreIdent.Core` will be available (assuming `basePath: "/auth"`):

*   `POST /auth/register`: Register a new user with email and password (requires a non-delegated `IUserStore`).
*   `POST /auth/login`: Log in with email and password, receive JWT access and refresh tokens.
*   `POST /auth/token/refresh`: Exchange a valid refresh token for new tokens (uses `IRefreshTokenStore`).

**Storage:**
*   CoreIdent now requires configuration of a persistent storage mechanism for production use.
*   **EF Core:** Provides full persistence for users, refresh tokens, clients, and scopes (when implemented) via `CoreIdent.Storage.EntityFrameworkCore`.
*   **Delegated:** Allows using an existing user system via `CoreIdent.Adapters.DelegatedUserStore`, but requires a separate persistent store (like EF Core) for refresh tokens.
*   **Refresh Tokens:** Refresh tokens are now persisted (typically via EF Core) and rotated upon successful use for enhanced security.

## Running / Testing

1.  Ensure you have the .NET SDK (9+) installed.
2.  Clone the repository.
3.  Run the associated example API project (if available) or execute the tests:
    ```bash
    cd path/to/CoreIdent
    dotnet test
    ```

## License

CoreIdent is licensed under the [MIT License](https://opensource.org/licenses/MIT).

## Contributing

Contributions are welcome! Please refer to the (upcoming) contribution guidelines.
