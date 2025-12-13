using CoreIdent.Core.Extensions;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Extensions;
using CoreIdent.TestHost;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCoreIdent(o =>
{
    o.Issuer = "https://issuer.example";
    o.Audience = "https://resource.example";
});

builder.Services.AddSigningKey(o => o.UseSymmetric("0123456789abcdef0123456789abcdef"));

builder.Services.AddDbContext<CoreIdentDbContext>(options =>
    options.UseSqlite("DataSource=coreident-testhost.db"));

builder.Services.AddEntityFrameworkCoreStores();

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

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health/check", () => Results.Ok());

app.MapCoreIdentEndpoints();

app.Run();

public partial class Program;
