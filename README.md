# CoreIdent: Modern .NET Identity & Authentication

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

**Storage:** Phase 1 uses a simple `InMemoryUserStore` and an in-memory refresh token store. Data is **not persisted** across application restarts.

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
