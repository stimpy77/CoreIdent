using CoreIdent.Core.Configuration;
using CoreIdent.Core.Extensions;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Extensions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Add CoreIdent services with minimal valid configuration for testing
builder.Services.AddCoreIdent(options =>
{
    options.Issuer = "urn:test-issuer";
    options.Audience = "urn:test-audience";
    // Use a secure, sufficiently long key (at least 32 bytes / 256 bits recommended for HS256)
    options.SigningKeySecret = "MySuperSecretTestHostKeyLongEnough32Bytes";
    options.AccessTokenLifetime = TimeSpan.FromMinutes(5);
    options.RefreshTokenLifetime = TimeSpan.FromMinutes(10); // Short lifetime for testing expiration, > AccessTokenLifetime
});

// --- Keep Storage Configuration Commented Out in TestHost Program.cs ---
// builder.Services.AddDbContext<CoreIdentDbContext>(options =>
//     options.UseSqlite($"DataSource=file:memdb-{Guid.NewGuid()}?mode=memory&cache=shared"), 
//     ServiceLifetime.Scoped);
// builder.Services.AddCoreIdentEntityFrameworkStores<CoreIdentDbContext>();
// --- End Comment Out ---

// Let the WebApplicationFactory configure the DbContext and stores for tests.

var app = builder.Build();

// --- Keep migration logic Commented Out in TestHost Program.cs ---
// using (var scope = app.Services.CreateScope())
// {
//     var dbContext = scope.ServiceProvider.GetRequiredService<CoreIdentDbContext>();
//     dbContext.Database.Migrate(); 
// }
// --- End Comment Out ---

// Configure a simple exception handler for the test environment
// app.UseExceptionHandler(exceptionHandlerApp =>
// {
//     exceptionHandlerApp.Run(async context =>
//     {
//         context.Response.StatusCode = StatusCodes.Status500InternalServerError;
//         await context.Response.WriteAsync("An unexpected error occurred.");
//     });
// });

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Map CoreIdent endpoints - use the new Action overload
app.MapCoreIdentEndpoints(options =>
{
    // Example: Customize routes if needed for testing
    // options.BasePath = "/test-auth";
});

app.Run();

// Make Program accessible for WebApplicationFactory
namespace CoreIdent.TestHost
{
    public partial class Program { }
}
