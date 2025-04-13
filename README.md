# CoreIdent: Modern .NET Identity & Authentication

![image](https://github.com/user-attachments/assets/96ac08ce-d88e-4d78-af98-101bb95aa317)

[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Current Status:** Phase 1 (MVP - Core Registration/Login/Tokens with In-Memory Storage) is complete. Phase 2 (Persistent Storage) development is underway.

**Development Phases:**
*   **Phase 1 (Completed):** MVP - Core Registration/Login/Tokens with In-Memory Storage.
*   **Phase 2 (Current):** Persistent Storage (EF Core) & Interface Refinement.
*   **Phase 3:** Enhanced Token Management & Security (Revocation, Sliding Expiration).
*   **Phase 4:** UI/Admin Portal (Basic Management).
*   **Phase 5:** Pluggable Providers & Advanced Features (Social Logins, Passkeys, etc.).

**CoreIdent** aims to be the modern, open-source, developer-friendly identity and authentication solution for the .NET ecosystem. It prioritizes convention over configuration, modularity, and ease of integration.

## Why CoreIdent?

In a world where authentication solutions are often complex or tied to specific vendors, CoreIdent stands out by offering:
*   **Developer Freedom:** Open-source (MIT) with no vendor lock-in. Build authentication your way.
*   **Convention Over Configuration:** Spend less time on setup. Our streamlined `AddCoreIdent()` method and sensible defaults get you started quickly with minimal code.
*   **Ease of Use:** Minimize boilerplate with sensible defaults and clear APIs. Get secure auth up and running fast.
*   **Modularity:** Core is lean; add only the features you need via separate NuGet packages.
*   **Future-Proof:** Built on modern .NET (9+), supporting traditional logins, passwordless methods (Passkeys/WebAuthn), and even decentralized identity (Web3, LNURL).
*   **Security First:** Best practices baked in for token handling, password storage, and endpoint protection.

## Future Vision

CoreIdent is just getting started. Beyond Phase 1, we're building towards:
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

For a detailed walkthrough of the architecture, setup, and Phase 1 features, please refer to the **[Developer Training Guide](./docs/Developer_Training_Guide.md)**.

## Getting Started (Phase 1 - MVP)

This guide covers the initial setup for the core functionality available in Phase 1.

### 1. Installation

CoreIdent is under active development. Once published to NuGet, you would install the core package:

```bash
dotnet add package CoreIdent.Core
```

*(Note: For now, you'll need to add a project reference to `CoreIdent.Core` from your main application project.)*

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

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// ... other services

// Configure CoreIdent
builder.Services.AddCoreIdent(options =>
{
    // Bind options from configuration (e.g., appsettings.json)
    builder.Configuration.GetSection("CoreIdent").Bind(options);

    // You could also set options directly:
    // options.Issuer = "https://myissuer.com";
    // options.Audience = "my_api";
    // options.SigningKeySecret = Environment.GetEnvironmentVariable("COREIDENT_SIGNING_KEY");
    // options.AccessTokenLifetime = TimeSpan.FromMinutes(30);
});

// If your API needs to validate CoreIdent JWTs:
builder.Services.AddAuthentication()
    .AddJwtBearer(options =>
    {
        // Configure validation parameters based on CoreIdentOptions
        // This part requires reading the options, typically done manually or via a helper
        var coreIdentOptions = builder.Configuration.GetSection("CoreIdent").Get<CoreIdent.Core.Configuration.CoreIdentOptions>()!;
        options.Authority = coreIdentOptions.Issuer;
        options.Audience = coreIdentOptions.Audience;
        // Additional validation parameters as needed...
    });

builder.Services.AddAuthorization();

// --- Storage Configuration --- 

// Option 1: Default In-Memory Store (Phase 1)
// If you don't configure anything else after AddCoreIdent(), it uses in-memory stores.

// Option 2: Entity Framework Core (SQLite Example - Phase 2+)
// First, add the necessary package:
// dotnet add package CoreIdent.Storage.EntityFrameworkCore 
// dotnet add package Microsoft.EntityFrameworkCore.Sqlite

// Configure the DbContext for your application
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? "DataSource=coreident.db;Cache=Shared";
builder.Services.AddDbContext<CoreIdentDbContext>(options =>
    options.UseSqlite(connectionString));

// Tell CoreIdent to use the EF Core stores with your DbContext
// This MUST be called AFTER AddCoreIdent() and AddDbContext()
builder.Services.AddCoreIdentEntityFrameworkStores<CoreIdentDbContext>();

// Option 3: Delegated User Store
// Use this if you have an existing user database/system and want CoreIdent to delegate
// authentication and user lookup to it.
// First, add the necessary package:
// dotnet add package CoreIdent.Adapters.DelegatedUserStore

// Configure the delegates in Program.cs
// This replaces the IUserStore registration (either In-Memory or EF Core)
/* // Uncomment to use Delegated Store
builder.Services.AddCoreIdentDelegatedUserStore(options =>
{
    // REQUIRED: Provide a function to find a user by their unique ID
    options.FindUserByIdAsync = async (userId, ct) => {
        // Your logic to query your external user store/API by ID
        var externalUser = await myExternalUserService.FindByIdAsync(userId);
        if (externalUser == null) return null;
        return new CoreIdentUser { 
            Id = externalUser.Id,
            UserName = externalUser.Email, // Map relevant properties
            NormalizedUserName = externalUser.Email?.ToUpperInvariant()
            // Do NOT map PasswordHash here
        };
    };

    // REQUIRED: Provide a function to find a user by username/email
    options.FindUserByUsernameAsync = async (normalizedUsername, ct) => {
        // Your logic to query your external user store/API by username/email
        // Ensure you handle normalization consistently
        var externalUser = await myExternalUserService.FindByUsernameAsync(normalizedUsername);
        if (externalUser == null) return null;
        return new CoreIdentUser {
            Id = externalUser.Id,
            UserName = externalUser.Email, // Map relevant properties
            NormalizedUserName = externalUser.Email?.ToUpperInvariant()
            // Do NOT map PasswordHash here
        };
    };

    // REQUIRED: Provide a function to validate credentials
    // This function receives the username/email and the submitted password
    options.ValidateCredentialsAsync = async (username, password, ct) => {
        // Your logic to validate the password against your external user store/API
        return await myExternalUserService.CheckPasswordAsync(username, password);
    };

    // OPTIONAL: Provide a function to get user claims
    options.GetClaimsAsync = async (coreIdentUser, ct) => {
        // Your logic to get claims for the user from your external system
        var externalClaims = await myExternalUserService.GetUserClaimsAsync(coreIdentUser.Id);
        var claims = externalClaims.Select(c => new System.Security.Claims.Claim(c.Type, c.Value)).ToList();
        // Ensure NameIdentifier and Name claims are present if not already included
        if (!claims.Any(c => c.Type == System.Security.Claims.ClaimTypes.NameIdentifier)){
             claims.Add(new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, coreIdentUser.Id!));
        }
        if (!claims.Any(c => c.Type == System.Security.Claims.ClaimTypes.Name)){
             claims.Add(new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Name, coreIdentUser.UserName!));
        }
        return claims;
    };
});
*/

// *** Important: After setting up EF Core, you need to create and apply migrations: ***
// 1. Add migration: dotnet ef migrations add InitialCreate --context CoreIdentDbContext -p src/CoreIdent.Storage.EntityFrameworkCore -s <Your_Web_Project>
// 2. Apply migration: dotnet ef database update --context CoreIdentDbContext -s <Your_Web_Project>

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

### 4. Phase 1 Functionality

With the setup above, the following endpoints provided by `CoreIdent.Core` will be available (assuming `basePath: "/auth"`):

*   `POST /auth/register`: Register a new user with email and password.
*   `POST /auth/login`: Log in with email and password, receive JWT access and refresh tokens.
*   `POST /auth/token/refresh`: Exchange a valid refresh token for new tokens.

**Storage (Phase 1):** Initially, Phase 1 used a simple `InMemoryUserStore` and an in-memory refresh token store. Data was **not persisted** across application restarts.

**Storage (Phase 2+ / Current):** If configured with `AddCoreIdentEntityFrameworkStores()`, CoreIdent now uses EF Core for persistence.
*   User, client, and scope data are stored in the configured database via `IUserStore`, `IClientStore`, `IScopeStore`.
*   **Refresh Tokens:** Refresh tokens are now persisted via `IRefreshTokenStore`. When a refresh token is used successfully at the `/token/refresh` endpoint, it is **consumed** (marked as used or deleted, depending on store implementation) and a **new refresh token** is issued alongside the new access token (Refresh Token Rotation). This enhances security by preventing token replay.

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
