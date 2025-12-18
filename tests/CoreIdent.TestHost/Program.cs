using CoreIdent.Core.Extensions;
using CoreIdent.Aspire;
using CoreIdent.Passkeys.AspNetIdentity.Endpoints;
using CoreIdent.Passkeys.AspNetIdentity.Extensions;
using CoreIdent.Passwords.AspNetIdentity.Extensions;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Extensions;
using CoreIdent.OpenApi.Extensions;
using CoreIdent.TestHost;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.AddCoreIdentDefaults();

builder.Services.AddCoreIdent(o =>
{
    o.Issuer = "https://issuer.example";
    o.Audience = "https://resource.example";
});

builder.Services.AddSigningKey(o => o.UseSymmetric("0123456789abcdef0123456789abcdef"));

builder.Services.AddDbContext<CoreIdentDbContext>(options =>
    options.UseSqlite("DataSource=coreident-testhost.db"));

builder.Services.AddEntityFrameworkCoreStores();

builder.Services.AddAspNetIdentityPasswordHasher();

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

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapCoreIdentDefaultEndpoints();

app.MapCoreIdentEndpoints();

app.MapCoreIdentPasskeyEndpoints();

app.MapCoreIdentOpenApi();

app.Run();

public partial class Program;
