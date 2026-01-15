using System.Net.Http.Json;
using System.Text.Json;
using CoreIdent.Core.Configuration;
using CoreIdent.Testing.Browser;
using CoreIdent.Testing.Fixtures;
using CoreIdent.Testing.Host;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Playwright;
using Shouldly;
using Xunit;

namespace CoreIdent.E2E.Tests;

/// <summary>
/// End-to-end browser tests for passkey/WebAuthn flows using Playwright virtual authenticator.
/// </summary>
/// <remarks>
/// These tests use the CDP virtual authenticator to simulate hardware authenticators.
/// Run with: dotnet test --filter "Category=E2E"
/// Requires: dotnet playwright install chromium
/// </remarks>
[Collection("E2E")]
[Trait("Category", "E2E")]
public class PasskeyE2ETests : IAsyncLifetime
{
    private readonly PlaywrightFixture _playwrightFixture;
    private KestrelTestHostFixture _hostFixture = null!;
    private HttpClient _client = null!;

    public PasskeyE2ETests()
    {
        _playwrightFixture = new PlaywrightFixture();
    }

    public async Task InitializeAsync()
    {
        await _playwrightFixture.InitializeAsync();
        _hostFixture = new KestrelTestHostFixture();
        await _hostFixture.InitializeAsync();
        _client = _hostFixture.CreateClient();
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _hostFixture.DisposeAsync();
        await _playwrightFixture.DisposeAsync();
    }

    [Fact]
    public async Task PasskeyEndpoints_AreAvailable()
    {
        // Arrange & Act
        var discovery = await _client.GetFromJsonAsync<JsonDocument>("/.well-known/openid-configuration");

        // Assert - just verify endpoints are discoverable
        discovery.ShouldNotBeNull();
    }

    [Fact]
    public async Task TestClient_CanObtainToken()
    {
        // Register a test user first
        var email = $"token-test-{Guid.NewGuid():N}@example.com";
        var password = "TestPass123!";

        var registerResponse = await _client.PostAsJsonAsync("/auth/register", new
        {
            email,
            password,
            confirmPassword = password
        });
        registerResponse.IsSuccessStatusCode.ShouldBeTrue($"Registration failed: {await registerResponse.Content.ReadAsStringAsync()}");

        // Now try to get a token with the test client
        var tokenResponse = await _client.PostAsync("/auth/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = KestrelTestHostFixture.TestClientId,
            ["username"] = email,
            ["password"] = password,
            ["scope"] = "openid"
        }));
        var tokenContent = await tokenResponse.Content.ReadAsStringAsync();
        
        // Debug info
        if (!tokenResponse.IsSuccessStatusCode)
        {
            // Try listing all clients - won't work but error message might help
            throw new InvalidOperationException($"Token failed with client '{KestrelTestHostFixture.TestClientId}': {tokenContent}");
        }

        tokenResponse.IsSuccessStatusCode.ShouldBeTrue($"Token failed: {tokenContent}");
    }

    [Fact]
    public async Task PasskeyRegisterOptions_ReturnsChallenge_ForAuthenticatedUser()
    {
        // First verify the client exists by checking discovery
        var discoveryResponse = await _client.GetAsync("/.well-known/openid-configuration");
        discoveryResponse.IsSuccessStatusCode.ShouldBeTrue("Discovery endpoint should be available");

        // Arrange - create a user and get a valid access token
        var email = $"passkey-test-{Guid.NewGuid():N}@example.com";
        var password = "TestPass123!";

        // Register user via HTTP
        var registerResponse = await _client.PostAsJsonAsync("/auth/register", new
        {
            email,
            password,
            confirmPassword = password
        });
        registerResponse.IsSuccessStatusCode.ShouldBeTrue($"User registration failed: {await registerResponse.Content.ReadAsStringAsync()}");

        // Get access token via password grant using the seeded test client
        var tokenResponse = await _client.PostAsync("/auth/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = KestrelTestHostFixture.TestClientId,
            ["username"] = email,
            ["password"] = password,
            ["scope"] = "openid profile"
        }));
        var tokenContent = await tokenResponse.Content.ReadAsStringAsync();
        tokenResponse.IsSuccessStatusCode.ShouldBeTrue($"Token request failed: {tokenContent}");

        var tokenResult = await tokenResponse.Content.ReadFromJsonAsync<JsonDocument>();
        var accessToken = tokenResult?.RootElement.GetProperty("access_token").GetString();
        accessToken.ShouldNotBeNullOrEmpty("Token response should contain access_token");

        // Act - request passkey registration options with the bearer token
        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/passkey/register/options");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

        var optionsResponse = await _client.SendAsync(request);
        var optionsContent = await optionsResponse.Content.ReadAsStringAsync();

        // Assert
        optionsResponse.IsSuccessStatusCode.ShouldBeTrue($"Passkey options request failed: {optionsContent}");
        optionsContent.ShouldContain("challenge"); // Response should contain a challenge
        optionsContent.ShouldContain("rp"); // Response should contain relying party info
        optionsContent.ShouldContain("user"); // Response should contain user info
    }

    [Fact]
    public async Task PasskeyAuthenticateOptions_ReturnsChallenge()
    {
        // Act - request authentication options (no auth required)
        var optionsResponse = await _client.PostAsJsonAsync("/auth/passkey/authenticate/options", new
        {
            username = (string?)null // Can be null for discoverable credentials
        });
        var optionsContent = await optionsResponse.Content.ReadAsStringAsync();

        // Assert
        optionsResponse.IsSuccessStatusCode.ShouldBeTrue($"Passkey auth options failed: {optionsContent}");
        optionsContent.ShouldContain("challenge"); // Response should contain a challenge
        optionsContent.ShouldContain("rpId"); // Response should contain RP ID
    }

    [Fact]
    public async Task VirtualAuthenticator_CanBeCreated()
    {
        // Arrange
        await using var context = await _playwrightFixture.CreateContextAsync(
            nameof(VirtualAuthenticator_CanBeCreated));
        var page = await context.NewPageAsync();

        // Act - create virtual authenticator
        await using var authenticator = await WebAuthnHelpers.CreateVirtualAuthenticatorAsync(page);

        // Assert
        authenticator.ShouldNotBeNull();
        authenticator.AuthenticatorId.ShouldNotBeNullOrEmpty();

        // Verify we can interact with it
        var credentials = await authenticator.GetCredentialsAsync();
        credentials.ShouldNotBeNull();
        credentials.Count.ShouldBe(0, "Fresh authenticator should have no credentials");
    }

    [Fact]
    public async Task VirtualAuthenticator_CanAddAndRetrieveCredentials()
    {
        // Arrange
        await using var context = await _playwrightFixture.CreateContextAsync(
            nameof(VirtualAuthenticator_CanAddAndRetrieveCredentials));
        var page = await context.NewPageAsync();
        await using var authenticator = await WebAuthnHelpers.CreateVirtualAuthenticatorAsync(page);

        // Generate a test private key (P-256 / ES256 in PKCS#8 format)
        // This is a minimal valid PKCS#8 wrapped P-256 private key for testing
        var testPrivateKey = GenerateTestPrivateKey();
        var credentialId = Guid.NewGuid().ToByteArray();
        var userHandle = Guid.NewGuid().ToByteArray();

        var credential = new VirtualCredential
        {
            CredentialId = credentialId,
            IsResidentCredential = true,
            RpId = "localhost",
            PrivateKey = testPrivateKey,
            SignCount = 0,
            UserHandle = userHandle
        };

        // Act
        await authenticator.AddCredentialAsync(credential);
        var credentials = await authenticator.GetCredentialsAsync();

        // Assert
        credentials.Count.ShouldBe(1, "Should have exactly one credential");
        credentials[0].RpId.ShouldBe("localhost");
        credentials[0].IsResidentCredential.ShouldBeTrue();
    }

    [Fact]
    public async Task VirtualAuthenticator_CanClearCredentials()
    {
        // Arrange
        await using var context = await _playwrightFixture.CreateContextAsync(
            nameof(VirtualAuthenticator_CanClearCredentials));
        var page = await context.NewPageAsync();
        await using var authenticator = await WebAuthnHelpers.CreateVirtualAuthenticatorAsync(page);

        // Add a credential (userHandle is required for resident credentials)
        var testPrivateKey = GenerateTestPrivateKey();
        await authenticator.AddCredentialAsync(new VirtualCredential
        {
            CredentialId = Guid.NewGuid().ToByteArray(),
            IsResidentCredential = true,
            RpId = "localhost",
            PrivateKey = testPrivateKey,
            SignCount = 0,
            UserHandle = Guid.NewGuid().ToByteArray()
        });

        var beforeClear = await authenticator.GetCredentialsAsync();
        beforeClear.Count.ShouldBe(1);

        // Act
        await authenticator.ClearCredentialsAsync();

        // Assert
        var afterClear = await authenticator.GetCredentialsAsync();
        afterClear.Count.ShouldBe(0, "All credentials should be cleared");
    }

    [Fact]
    public async Task VirtualAuthenticator_CanSetUserVerification()
    {
        // Arrange
        await using var context = await _playwrightFixture.CreateContextAsync(
            nameof(VirtualAuthenticator_CanSetUserVerification));
        var page = await context.NewPageAsync();
        await using var authenticator = await WebAuthnHelpers.CreateVirtualAuthenticatorAsync(page);

        // Act & Assert - should not throw
        await authenticator.SetUserVerifiedAsync(true);
        await authenticator.SetUserVerifiedAsync(false);
    }

    [Fact]
    public async Task VirtualAuthenticator_DifferentTransports_Supported()
    {
        // Arrange
        await using var context = await _playwrightFixture.CreateContextAsync(
            nameof(VirtualAuthenticator_DifferentTransports_Supported));
        var page = await context.NewPageAsync();

        // Act - create USB security key authenticator
        await using var usbAuthenticator = await WebAuthnHelpers.CreateVirtualAuthenticatorAsync(
            page,
            VirtualAuthenticatorOptions.UsbSecurityKey);

        // Assert
        usbAuthenticator.ShouldNotBeNull();
        usbAuthenticator.AuthenticatorId.ShouldNotBeNullOrEmpty();
    }

    /// <summary>
    /// Generates a minimal test P-256 private key in PKCS#8 format for virtual authenticator.
    /// </summary>
    /// <remarks>
    /// This is a valid PKCS#8 structure containing a P-256 (secp256r1) private key.
    /// For test purposes only - never use hardcoded keys in production.
    /// </remarks>
    private static byte[] GenerateTestPrivateKey()
    {
        // Generate a real EC key and export it
        using var ecdsa = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        return ecdsa.ExportPkcs8PrivateKey();
    }
}

/// <summary>
/// Tests for WebAuthn helper functions.
/// </summary>
public class WebAuthnHelpersTests
{
    [Fact]
    public void VirtualAuthenticatorOptions_Default_HasCorrectValues()
    {
        // Arrange & Act
        var options = VirtualAuthenticatorOptions.Default;

        // Assert
        options.Protocol.ShouldBe("ctap2");
        options.Transport.ShouldBe("internal");
        options.HasResidentKey.ShouldBeTrue();
        options.HasUserVerification.ShouldBeTrue();
        options.IsUserVerified.ShouldBeTrue();
        options.AutomaticPresenceSimulation.ShouldBeTrue();
    }

    [Fact]
    public void VirtualAuthenticatorOptions_UsbSecurityKey_HasCorrectValues()
    {
        // Arrange & Act
        var options = VirtualAuthenticatorOptions.UsbSecurityKey;

        // Assert
        options.Protocol.ShouldBe("ctap2");
        options.Transport.ShouldBe("usb");
        options.HasResidentKey.ShouldBeFalse();
        options.HasUserVerification.ShouldBeFalse();
        options.IsUserVerified.ShouldBeFalse();
        options.AutomaticPresenceSimulation.ShouldBeTrue();
    }

    [Fact]
    public void VirtualCredential_DefaultValues_AreEmpty()
    {
        // Arrange & Act
        var credential = new VirtualCredential();

        // Assert
        credential.CredentialId.ShouldBeEmpty();
        credential.RpId.ShouldBe(string.Empty);
        credential.PrivateKey.ShouldBeEmpty();
        credential.SignCount.ShouldBe(0);
        credential.UserHandle.ShouldBeNull();
        credential.IsResidentCredential.ShouldBeFalse();
    }
}
