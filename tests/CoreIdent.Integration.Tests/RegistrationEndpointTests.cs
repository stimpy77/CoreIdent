using System.Net;
using System.Net.Http.Json;
using CoreIdent.Core.Models.Requests;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Extensions; // Needed for AddCoreIdentEntityFrameworkStores
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions; // For RemoveAll
using Microsoft.Extensions.Logging;
using Shouldly; // For assertions
using Xunit;
using System.Threading.Tasks;

namespace CoreIdent.Integration.Tests;

// Custom factory using a shared, kept-alive connection for the DbContext
public class RegistrationTestWebApplicationFactory : WebApplicationFactory<Program>, IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly string _connectionString = $"DataSource=file:RegTests_{Guid.NewGuid()}?mode=memory&cache=shared"; // Unique name per run, shared cache

    public RegistrationTestWebApplicationFactory()
    {
        _connection = new SqliteConnection(_connectionString);
        _connection.Open(); // Keep the connection open for the lifetime of the factory
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            // Remove the default DbContext registration if it exists (added by generic host/etc)
            services.RemoveAll<DbContextOptions<CoreIdentDbContext>>();
            services.RemoveAll<CoreIdentDbContext>();

            // Register DbContext to use the single, shared connection
            services.AddDbContext<CoreIdentDbContext>(options =>
            {
                options.UseSqlite(_connection); // Use the single, open connection
            }, ServiceLifetime.Scoped);

            // Ensure EF Core stores are registered (they depend on CoreIdentDbContext)
            // Use AddScoped to ensure they get the correct DbContext instance per scope
            services.AddCoreIdentEntityFrameworkStores<CoreIdentDbContext>();

            // --- Run Migrations --- 
            // Build the service provider to run migrations
            var sp = services.BuildServiceProvider();
            using var scope = sp.CreateScope();
            var scopedServices = scope.ServiceProvider;
            var db = scopedServices.GetRequiredService<CoreIdentDbContext>();
            var logger = scopedServices.GetRequiredService<ILogger<RegistrationTestWebApplicationFactory>>();

            try
            {
                db.Database.Migrate();
                logger.LogInformation("Database migrated successfully for {FactoryName} using connection {ConnectionString}.", 
                    nameof(RegistrationTestWebApplicationFactory), _connectionString);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred migrating the database for {FactoryName}. Connection: {ConnectionString}. Error: {ErrorMessage}", 
                    nameof(RegistrationTestWebApplicationFactory), _connectionString, ex.Message);
                throw;
            }
        });

        builder.UseEnvironment("Development");
    }

    // Dispose the connection when the factory is disposed
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _connection.Close();
            _connection.Dispose();
        }
        base.Dispose(disposing);
    }

    // Make IDisposable explicit if needed, though protected Dispose is usually sufficient
    // void IDisposable.Dispose() 
    // { 
    //     Dispose(true); 
    //     GC.SuppressFinalize(this); 
    // }
}

// Use IClassFixture to share the factory instance across tests in this class
// Target the Program class from the global namespace
public class RegistrationEndpointTests : IClassFixture<RegistrationTestWebApplicationFactory>
{
    private readonly HttpClient _client;
    private readonly RegistrationTestWebApplicationFactory _factory;

    public RegistrationEndpointTests(RegistrationTestWebApplicationFactory factory)
    {
        _factory = factory;
        _client = _factory.CreateClient();
    }

    // Helper method to generate unique email addresses for each test run
    private static string GenerateUniqueEmail() => $"test-{Guid.NewGuid():N}@example.com";

    [Fact]
    public async Task PostRegister_WithValidData_ShouldReturnOkAndCreateUser()
    {
        // Arrange
        var registrationRequest = new RegisterRequest
        {
            Email = $"test-{Guid.NewGuid()}@example.com",
            Password = "ValidPassword123!"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/register", registrationRequest);

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.Created); // Expect 201 Created

        // Verify user creation in the database using a separate scope
        using var scope = _factory.Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<CoreIdentDbContext>();
        var normalizedEmail = registrationRequest.Email.ToUpperInvariant();
        var user = await context.Users.FirstOrDefaultAsync(u => u.NormalizedUserName == normalizedEmail);
        user.ShouldNotBeNull();
        user.UserName.ShouldBe(registrationRequest.Email);
    }

    [Fact]
    public async Task PostRegister_WithExistingEmail_ShouldReturnConflict()
    {
        // Arrange - First registration
        var email = $"test-{Guid.NewGuid()}@example.com";
        var registrationRequest1 = new RegisterRequest { Email = email, Password = "ValidPassword123!" };
        var response1 = await _client.PostAsJsonAsync("/auth/register", registrationRequest1);
        response1.EnsureSuccessStatusCode(); // Ensure first one succeeds (should be 201)

        // Act - Second registration with the same email
        var registrationRequest2 = new RegisterRequest { Email = email, Password = "AnotherPassword456?" };
        var response2 = await _client.PostAsJsonAsync("/auth/register", registrationRequest2);

        // Assert
        response2.StatusCode.ShouldBe(HttpStatusCode.Conflict); // Expect 409 Conflict
    }

    [Theory]
    [InlineData("", "Password123!")] // Missing Email
    [InlineData("invalid-email", "Password123!")] // Invalid Email format
    [InlineData("test@example.com", "")] // Missing Password
    [InlineData("test2@example.com", "short")] // Password too short (assuming validator checks length)
    public async Task PostRegister_WithInvalidData_ShouldReturnBadRequest(string email, string password)
    {
        // Arrange
        var request = new RegisterRequest
        {
            Email = email,
            Password = password
        };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/register", request);

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        // Optionally check response body for validation problem details
        // var problemDetails = await response.Content.ReadFromJsonAsync<ValidationProblemDetails>();
        // problemDetails.ShouldNotBeNull();
        // problemDetails.Errors.Count.ShouldBeGreaterThan(0);
    }

    // Helper classes for deserializing responses (adjust based on actual endpoint responses)
    private class RegistrationSuccessResponse
    {
        public string? UserId { get; set; }
        public string? Message { get; set; }
    }

    private class ErrorResponse
    {
        public string? Message { get; set; }
    }
}
