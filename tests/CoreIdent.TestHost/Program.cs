using CoreIdent.Core.Extensions;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Extensions;
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

var app = builder.Build();

app.MapGet("/health/check", () => Results.Ok());

app.MapCoreIdentEndpoints();

app.Run();

public partial class Program;
