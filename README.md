# CoreIdent: Modern .NET Identity & Authentication

[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**CoreIdent** aims to be the modern, open-source, developer-friendly identity and authentication solution for the .NET ecosystem. It prioritizes convention over configuration, modularity, and ease of integration.

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
