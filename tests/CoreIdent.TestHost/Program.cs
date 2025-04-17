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
    options.RefreshTokenLifetime = TimeSpan.FromSeconds(30); // Short lifetime for testing expiration
});

// --- REMOVE Storage Configuration specific to TestHost Program.cs ---
// // Revert to unique DB per factory run
// builder.Services.AddDbContext<CoreIdentDbContext>(options =>
//     options.UseSqlite($"DataSource=file:memdb-{Guid.NewGuid()}?mode=memory&cache=shared"),
//     ServiceLifetime.Scoped); // Explicitly Scoped
// 
// // Configure CoreIdent to use the EF Core stores
// builder.Services.AddCoreIdentEntityFrameworkStores<CoreIdentDbContext>();
// --- End REMOVAL ---

// Let the WebApplicationFactory configure the DbContext and stores for tests.

var app = builder.Build();

// --- REMOVE Post-Build Migration Logic ---
// using (var scope = app.Services.CreateScope())
// {
    // ... migration logic ...
// }
// --- End REMOVAL ---

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

// Map CoreIdent endpoints under the /auth base path
app.MapCoreIdentEndpoints("/auth"); // Specify base path

app.Run();

// Make Program accessible for WebApplicationFactory
public partial class Program { }
