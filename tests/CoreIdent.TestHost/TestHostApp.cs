using System.Security.Cryptography;
using CoreIdent.Aspire;
using CoreIdent.Core.Extensions;
using CoreIdent.OpenApi.Extensions;
using CoreIdent.Passkeys.AspNetIdentity.Endpoints;
using CoreIdent.Passkeys.AspNetIdentity.Extensions;
using CoreIdent.Passwords.AspNetIdentity.Extensions;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace CoreIdent.TestHost;

/// <summary>
/// Factory for building the CoreIdent test host application.
/// This allows tests to start the host in-proc (Kestrel) without shelling out to <c>dotnet run</c>.
/// </summary>
public static class TestHostApp
{
    public static WebApplication Build(
        string[] args,
        string? sqliteDbPath = null,
        Action<IServiceCollection>? configureServices = null,
        Action<WebApplication>? configureApp = null)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.AddCoreIdentDefaults();

        // IMPORTANT: Register EF Core stores BEFORE AddCoreIdent() because
        // AddCoreIdent uses TryAdd* which won't override existing registrations.
        var db = sqliteDbPath ?? "coreident-testhost.db";
        builder.Services.AddDbContext<CoreIdentDbContext>(options =>
            options.UseSqlite($"DataSource={db};Mode=ReadWriteCreate;Cache=Shared"));
        builder.Services.AddEntityFrameworkCoreStores();
        builder.Services.AddAspNetIdentityPasswordHasher();

        builder.Services.AddCoreIdent(o =>
        {
            o.Issuer = "https://issuer.example";
            o.Audience = "https://resource.example";
        });

        // Use RSA for signing - this publishes to JWKS and is OIDC-conformant
        builder.Services.AddSigningKey(o => o.UseRsaPem(GenerateTestRsaKeyPem()));

        builder.Services.AddPasskeys();

        builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = TestHeaderAuthenticationHandler.SchemeName;
                options.DefaultChallengeScheme = TestHeaderAuthenticationHandler.SchemeName;
            })
            .AddScheme<AuthenticationSchemeOptions, TestHeaderAuthenticationHandler>(
                TestHeaderAuthenticationHandler.SchemeName,
                _ => { });

        builder.Services.AddAuthorization();
        builder.Services.AddCoreIdentOpenApi();

        configureServices?.Invoke(builder.Services);

        var app = builder.Build();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapCoreIdentDefaultEndpoints();
        app.MapCoreIdentEndpoints();
        app.MapCoreIdentPasskeyEndpoints();
        app.MapCoreIdentOpenApi();

        configureApp?.Invoke(app);

        return app;
    }

    /// <summary>
    /// Generates a test RSA private key in PEM format.
    /// This key is ephemeral and for testing only - generated fresh each test run.
    /// </summary>
    private static string GenerateTestRsaKeyPem()
    {
        using var rsa = RSA.Create(2048);
        return rsa.ExportRSAPrivateKeyPem();
    }
}
