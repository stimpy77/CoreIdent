using CoreIdent.Core.Configuration;
using CoreIdent.Core.Extensions;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Extensions;
using Microsoft.EntityFrameworkCore;

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
    options.RefreshTokenLifetime = TimeSpan.FromSeconds(30); // Short lifetime for testing expiration
});

// --- Storage Configuration for Integration Tests ---
// Use SQLite In-Memory for isolated test runs, or a file for persistence checking
// Ensure the connection string matches what tests might expect if accessing directly.
// Option 1: In-Memory (Unique per test run usually)
// builder.Services.AddDbContext<CoreIdentDbContext>(options =>
//    options.UseSqlite($"DataSource=file:memdb{Guid.NewGuid()}?mode=memory&cache=shared")); // Ensure unique name or shared cache

// Option 2: File-based (Matches design-time migration target)
var connectionString = "DataSource=coreident_integration_test.db;Cache=Shared";
builder.Services.AddDbContext<CoreIdentDbContext>(options =>
    options.UseSqlite(connectionString));

// Configure CoreIdent to use the EF Core stores
builder.Services.AddCoreIdentEntityFrameworkStores<CoreIdentDbContext>();

var app = builder.Build();

// Configure a simple exception handler for the test environment
// app.UseExceptionHandler(exceptionHandlerApp =>
// {
//     exceptionHandlerApp.Run(async context =>
//     {
//         context.Response.StatusCode = StatusCodes.Status500InternalServerError;
//         await context.Response.WriteAsync("An unexpected error occurred.");
//     });
// });

// Ensure database is created for tests
// This is crucial when using WebApplicationFactory as migrations aren't automatically run
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<CoreIdentDbContext>();
    // Use EnsureCreated for simple cases or Database.Migrate for migrations
    // dbContext.Database.Migrate(); // Apply migrations to the test database
    dbContext.Database.EnsureCreated(); // Ensure schema exists, doesn't use migrations
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Map CoreIdent endpoints under the /auth base path
app.MapCoreIdentEndpoints("/auth"); // Specify base path

app.Run();

// Make Program accessible for WebApplicationFactory
public partial class Program { }
