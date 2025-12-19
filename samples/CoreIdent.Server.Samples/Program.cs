using CoreIdent.Core.Extensions;
using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using CoreIdent.Server.Samples;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// This sample is intended for local testing.
// IMPORTANT: issuer is used to build absolute endpoints in the discovery document.
const string issuer = "http://localhost:5080";

builder.Services.AddCoreIdent(o =>
{
    o.Issuer = issuer;
    o.Audience = issuer;
});

builder.Services.AddInMemoryUserStore();

builder.Services.Configure<CoreIdentUserInfoOptions>(o =>
{
    o.CustomClaimsScope = "custom_claims";
});

// Dev-only signing key (HS256). For production, use RSA/ECDSA.
builder.Services.AddSigningKey(o => o.UseSymmetric("this-is-a-dev-only-secret-please-change-32bytes!!"));

// Seed a single confidential client for Authorization Code + PKCE.
var clientId = "coreident-client";
var clientSecret = "coreident-client-secret"; // dev-only
var redirectUri = "http://localhost:7890/callback/";

var client = new CoreIdentClient
{
    ClientId = clientId,
    ClientName = "CoreIdent Client Samples",
    ClientType = ClientType.Confidential,
    RedirectUris = [redirectUri],
    AllowedGrantTypes = ["authorization_code", "refresh_token"],
    AllowedScopes = ["openid", "profile", "email", "custom_claims"],
    RequirePkce = true,
    AllowOfflineAccess = false,
    RequireConsent = false
};

builder.Services.AddInMemoryClients([(client, clientSecret)]);

// Authenticate requests using a test header scheme so /auth/authorize can proceed without cookies/UI.
builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = TestHeaderAuthenticationHandler.SchemeName;
        options.DefaultChallengeScheme = TestHeaderAuthenticationHandler.SchemeName;
    })
    .AddScheme<AuthenticationSchemeOptions, TestHeaderAuthenticationHandler>(
        TestHeaderAuthenticationHandler.SchemeName,
        _ => { });

builder.Services.AddAuthorization();

var app = builder.Build();

app.Urls.Add(issuer);

using (var scope = app.Services.CreateScope())
{
    var inMemoryScopeStore = scope.ServiceProvider.GetRequiredService<InMemoryScopeStore>();
    inMemoryScopeStore.SeedScopes(new[]
    {
        new CoreIdentScope
        {
            Name = "custom_claims",
            DisplayName = "Custom Claims",
            Description = "Additional non-standard user claims",
            Required = false,
            Emphasize = true,
            ShowInDiscoveryDocument = true,
            UserClaims = []
        }
    });

    var userStore = scope.ServiceProvider.GetRequiredService<IUserStore>();
    var userId = "user-1";
    var email = "alice@example.com";
    var user = userStore.FindByIdAsync(userId).GetAwaiter().GetResult();
    if (user is null)
    {
        userStore.CreateAsync(new CoreIdentUser
        {
            Id = userId,
            UserName = email,
            NormalizedUserName = email.Trim().ToUpperInvariant(),
            CreatedAt = DateTime.UtcNow
        }).GetAwaiter().GetResult();
    }

    userStore.SetClaimsAsync(userId, new[]
    {
        new Claim(ClaimTypes.Email, email),
        new Claim(ClaimTypes.Name, email),
        new Claim(ClaimTypes.Role, "admin"),
        new Claim("delegated_sub", "admin-1")
    }).GetAwaiter().GetResult();
}

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => Results.Text("CoreIdent.Server.Samples running"));
app.MapCoreIdentEndpoints();

app.Run();
