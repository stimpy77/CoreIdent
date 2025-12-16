using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CoreIdent.Core.Extensions;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

//#if (useEfCore)
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Extensions;
using CoreIdent.Storage.EntityFrameworkCore.Models;
using Microsoft.EntityFrameworkCore;
//#endif

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

//#if (useEfCore)
builder.Services.AddDbContext<CoreIdentDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("CoreIdent") ?? "Data Source=coreident.db"));

builder.Services.RemoveAll<IClientStore>();
builder.Services.RemoveAll<IScopeStore>();
builder.Services.RemoveAll<IRefreshTokenStore>();
builder.Services.RemoveAll<IAuthorizationCodeStore>();
builder.Services.RemoveAll<IUserGrantStore>();
builder.Services.RemoveAll<ITokenRevocationStore>();
builder.Services.RemoveAll<IUserStore>();
builder.Services.RemoveAll<IPasswordlessTokenStore>();

builder.Services.AddEntityFrameworkCoreStores();
//#endif

builder.Services.AddInMemoryClients(
    new (CoreIdentClient Client, string? PlaintextSecret)[]
    {
        (
            new CoreIdentClient
            {
                ClientId = "example_client",
                ClientName = "Example Client",
                ClientType = ClientType.Confidential,
                AllowedGrantTypes = new List<string> { GrantTypes.ClientCredentials },
                AllowedScopes = new List<string> { StandardScopes.OpenId }
            },
            "example-secret"
        )
    });

var app = builder.Build();

//#if (useEfCore)
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
            RedirectUrisJson = "[]",
            PostLogoutRedirectUrisJson = "[]",
            AllowedScopesJson = JsonSerializer.Serialize(new[] { StandardScopes.OpenId }),
            AllowedGrantTypesJson = JsonSerializer.Serialize(new[] { GrantTypes.ClientCredentials }),
            AccessTokenLifetimeSeconds = 900,
            RefreshTokenLifetimeSeconds = 86400,
            RequirePkce = false,
            RequireConsent = false,
            AllowOfflineAccess = false,
            Enabled = true,
            CreatedAt = DateTime.UtcNow
        });
        db.SaveChanges();
    }
}
//#endif

app.MapCoreIdentEndpoints();

app.MapGet("/", () => Results.Text("CoreIdent API is running"));

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
