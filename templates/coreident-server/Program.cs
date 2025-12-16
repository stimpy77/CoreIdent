using System;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CoreIdent.Core.Extensions;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
//#if (usePasskeys)
using CoreIdent.Passkeys.AspNetIdentity.Endpoints;
using CoreIdent.Passkeys.AspNetIdentity.Extensions;
//#endif
using CoreIdent.Passwords.AspNetIdentity.Extensions;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Extensions;
using CoreIdent.Storage.EntityFrameworkCore.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

static string GetRequired(IConfiguration config, string key)
{
    var value = config[key];
    if (string.IsNullOrWhiteSpace(value))
    {
        throw new InvalidOperationException($"Missing required configuration value: {key}");
    }

    return value;
}

builder.Services.AddCoreIdent(o =>
{
    o.Issuer = GetRequired(builder.Configuration, "CoreIdent:Issuer");
    o.Audience = GetRequired(builder.Configuration, "CoreIdent:Audience");
});

builder.Services.AddSigningKey(o =>
    o.UseSymmetric(GetRequired(builder.Configuration, "CoreIdent:DevSigningKey")));

//#if (usePasswordless)
builder.Services.AddSingleton<IEmailSender, DevEmailSender>();
//#endif

builder.Services.AddDbContext<CoreIdentDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("CoreIdent") ?? "Data Source=coreident.db"));

builder.Services.AddEntityFrameworkCoreStores();

builder.Services.AddAspNetIdentityPasswordHasher();

//#if (usePasskeys)
builder.Services.AddPasskeys();
//#endif

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<CoreIdentDbContext>();
    db.Database.EnsureCreated();

    if (!db.Scopes.Any())
    {
        db.Scopes.AddRange(new[]
        {
            new ScopeEntity
            {
                Name = StandardScopes.OpenId,
                DisplayName = "OpenID",
                Description = "Your user identifier",
                Required = true,
                Emphasize = false,
                ShowInDiscoveryDocument = true,
                UserClaimsJson = JsonSerializer.Serialize(new[] { "sub" })
            },
            new ScopeEntity
            {
                Name = StandardScopes.Profile,
                DisplayName = "Profile",
                Description = "Basic profile information",
                Required = false,
                Emphasize = false,
                ShowInDiscoveryDocument = true,
                UserClaimsJson = JsonSerializer.Serialize(new[] { "name" })
            }
        });

        db.SaveChanges();
    }

    if (!db.Clients.Any())
    {
        db.Clients.Add(new ClientEntity
        {
            ClientId = "example_client",
            ClientName = "Example Client",
            ClientType = nameof(ClientType.Confidential),
            ClientSecretHash = scope.ServiceProvider.GetRequiredService<IClientSecretHasher>().HashSecret("example-secret"),
            AllowedGrantTypesJson = JsonSerializer.Serialize(new[] { GrantTypes.ClientCredentials }),
            AllowedScopesJson = JsonSerializer.Serialize(new[] { StandardScopes.OpenId }),
            RedirectUrisJson = "[]",
            PostLogoutRedirectUrisJson = "[]",
            AccessTokenLifetimeSeconds = 3600,
            RefreshTokenLifetimeSeconds = 86400,
            RequirePkce = true,
            RequireConsent = false,
            AllowOfflineAccess = false,
            Enabled = true,
            CreatedAt = DateTime.UtcNow
        });

        db.SaveChanges();
    }

    //#if (usePasskeys)
    if (!db.Clients.Any(c => c.ClientId == "passkey"))
    {
        db.Clients.Add(new ClientEntity
        {
            ClientId = "passkey",
            ClientName = "Passkey Client",
            ClientType = nameof(ClientType.Public),
            ClientSecretHash = null,
            AllowedGrantTypesJson = JsonSerializer.Serialize(new[] { "passkey" }),
            AllowedScopesJson = JsonSerializer.Serialize(Array.Empty<string>()),
            RedirectUrisJson = "[]",
            PostLogoutRedirectUrisJson = "[]",
            AccessTokenLifetimeSeconds = 3600,
            RefreshTokenLifetimeSeconds = 86400,
            RequirePkce = true,
            RequireConsent = false,
            AllowOfflineAccess = false,
            Enabled = true,
            CreatedAt = DateTime.UtcNow
        });

        db.SaveChanges();
    }
    //#endif
}

app.MapGet("/", () => Results.Text("CoreIdent Server is running"));

app.MapGet("/health/check", () => Results.Ok());

app.MapCoreIdentEndpoints();

//#if (usePasskeys)
app.MapCoreIdentPasskeyEndpoints();
//#endif

app.Run();

//#if (usePasswordless)
sealed class DevEmailSender : IEmailSender
{
    public Task SendAsync(EmailMessage message, CancellationToken ct = default)
    {
        Console.WriteLine($"[CoreIdent] Email to={message.To} subject={message.Subject}");
        Console.WriteLine(message.HtmlBody);
        return Task.CompletedTask;
    }
}
//#endif
