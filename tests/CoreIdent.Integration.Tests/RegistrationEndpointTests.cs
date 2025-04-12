using CoreIdent.Core.Models.Requests;
using CoreIdent.Core.Stores;
using Microsoft.AspNetCore.Mvc.Testing; // WebApplicationFactory
using Microsoft.Extensions.DependencyInjection; // IServiceScope, GetRequiredService
using Shouldly; // Assertions
using System.Net;
using System.Net.Http.Json; // ReadFromJsonAsync, PostAsJsonAsync
using System.Threading.Tasks;
using Xunit;

namespace CoreIdent.Integration.Tests;

// Use IClassFixture to share the factory instance across tests in this class
// Target the Program class from the global namespace
public class RegistrationEndpointTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public RegistrationEndpointTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        // Create an HttpClient instance that bypasses the network stack and calls the test server directly
        _client = _factory.CreateClient(); 
    }

    // Helper method to generate unique email addresses for each test run
    private static string GenerateUniqueEmail() => $"test-{Guid.NewGuid():N}@example.com";

    [Fact]
    public async Task PostRegister_WithValidData_ShouldReturnOkAndCreateUser()
    {
        // Arrange
        var uniqueEmail = GenerateUniqueEmail();
        var request = new RegisterRequest
        {
            Email = uniqueEmail,
            Password = "ValidPassword123!"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/register", request);

        // Assert: Check HTTP response
        response.StatusCode.ShouldBe(HttpStatusCode.Created); // Expect 201 Created for resource creation
        var responseBody = await response.Content.ReadFromJsonAsync<RegistrationSuccessResponse>(); // Assuming a simple response structure
        responseBody.ShouldNotBeNull();
        responseBody.Message.ShouldBe("User registered successfully.");
        responseBody.UserId.ShouldNotBeNullOrWhiteSpace();

        // Assert: Check user creation in the store (using a service scope)
        using var scope = _factory.Services.CreateScope();
        var userStore = scope.ServiceProvider.GetRequiredService<IUserStore>();
        var createdUser = await userStore.FindUserByUsernameAsync(uniqueEmail.ToUpperInvariant(), CancellationToken.None);

        createdUser.ShouldNotBeNull();
        createdUser.UserName.ShouldBe(uniqueEmail);
        createdUser.PasswordHash.ShouldNotBeNullOrWhiteSpace();
        createdUser.Id.ShouldBe(responseBody.UserId);
    }

    [Fact]
    public async Task PostRegister_WithExistingEmail_ShouldReturnConflict()
    {
        // Arrange: Create the first user
        var existingEmail = GenerateUniqueEmail();
        var initialRequest = new RegisterRequest { Email = existingEmail, Password = "Password123!" };
        var initialResponse = await _client.PostAsJsonAsync("/auth/register", initialRequest);
        initialResponse.EnsureSuccessStatusCode(); // Ensure the first registration worked

        // Arrange: Prepare request with the same email
        var duplicateRequest = new RegisterRequest
        {
            Email = existingEmail,
            Password = "AnotherPassword456?"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/register", duplicateRequest);

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.Conflict);
        var errorBody = await response.Content.ReadFromJsonAsync<ErrorResponse>(); // Assuming an error response structure
        errorBody.ShouldNotBeNull();
        errorBody.Message!.ShouldContain($"Username '{existingEmail}' already exists."); // Add ! to suppress CS8604 warning
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
