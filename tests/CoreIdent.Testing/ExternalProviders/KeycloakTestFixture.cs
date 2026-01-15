using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CoreIdent.Testing.ExternalProviders;

/// <summary>
/// Test fixture for running tests against a containerized Keycloak instance.
/// Provides cross-provider parity testing for OAuth/OIDC flows.
/// </summary>
/// <remarks>
/// <para>
/// This fixture requires Docker to be available and Keycloak to be running.
/// Use TestContainers or docker-compose to start Keycloak before tests.
/// </para>
/// <para>
/// Default Keycloak configuration expects:
/// - Keycloak running at http://localhost:8080
/// - Admin credentials: admin/admin
/// - Test realm: coreident-test
/// </para>
/// </remarks>
public class KeycloakTestFixture : IAsyncDisposable
{
    private HttpClient? _httpClient;
    private string? _adminToken;

    /// <summary>
    /// Gets the base URL of the Keycloak server.
    /// </summary>
    public string BaseUrl { get; private set; } = "http://localhost:8080";

    /// <summary>
    /// Gets the test realm name.
    /// </summary>
    public string RealmName { get; private set; } = "coreident-test";

    /// <summary>
    /// Gets the OpenID Connect discovery URL for the test realm.
    /// </summary>
    public string DiscoveryUrl => $"{BaseUrl}/realms/{RealmName}/.well-known/openid-configuration";

    /// <summary>
    /// Gets the authorization endpoint.
    /// </summary>
    public string AuthorizationEndpoint => $"{BaseUrl}/realms/{RealmName}/protocol/openid-connect/auth";

    /// <summary>
    /// Gets the token endpoint.
    /// </summary>
    public string TokenEndpoint => $"{BaseUrl}/realms/{RealmName}/protocol/openid-connect/token";

    /// <summary>
    /// Gets the userinfo endpoint.
    /// </summary>
    public string UserinfoEndpoint => $"{BaseUrl}/realms/{RealmName}/protocol/openid-connect/userinfo";

    /// <summary>
    /// Gets the JWKS endpoint.
    /// </summary>
    public string JwksEndpoint => $"{BaseUrl}/realms/{RealmName}/protocol/openid-connect/certs";

    /// <summary>
    /// Gets the end session endpoint.
    /// </summary>
    public string EndSessionEndpoint => $"{BaseUrl}/realms/{RealmName}/protocol/openid-connect/logout";

    /// <summary>
    /// Gets the revocation endpoint.
    /// </summary>
    public string RevocationEndpoint => $"{BaseUrl}/realms/{RealmName}/protocol/openid-connect/revoke";

    /// <summary>
    /// Gets the introspection endpoint.
    /// </summary>
    public string IntrospectionEndpoint => $"{BaseUrl}/realms/{RealmName}/protocol/openid-connect/token/introspect";

    /// <summary>
    /// Gets whether Keycloak is available and initialized.
    /// </summary>
    public bool IsInitialized { get; private set; }

    /// <summary>
    /// Initializes the fixture with the specified Keycloak URL.
    /// Returns false if Keycloak is not available, true if successfully initialized.
    /// </summary>
    /// <param name="baseUrl">The base URL of the Keycloak server.</param>
    /// <param name="adminUsername">Admin username for setup operations.</param>
    /// <param name="adminPassword">Admin password for setup operations.</param>
    /// <returns>True if initialization succeeded, false if Keycloak is unavailable.</returns>
    public async Task<bool> InitializeAsync(
        string? baseUrl = null,
        string adminUsername = "admin",
        string adminPassword = "admin")
    {
        if (baseUrl != null)
        {
            BaseUrl = baseUrl;
        }

        // Use a handler that doesn't require system proxy - avoids proxy-related failures
        var handler = new SocketsHttpHandler
        {
            ConnectTimeout = TimeSpan.FromSeconds(10),
            UseProxy = false
        };

        _httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri(BaseUrl),
            Timeout = TimeSpan.FromSeconds(30)
        };

        // First check if Keycloak is reachable
        if (!await IsHealthyAsync())
        {
            return false;
        }

        try
        {
            // Get admin token
            _adminToken = await GetAdminTokenAsync(adminUsername, adminPassword);

            // Ensure test realm exists
            await EnsureRealmExistsAsync();

            IsInitialized = true;
            return true;
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            // Invalid credentials - this is expected if Keycloak admin password differs
            LastError = $"Admin authentication failed: {ex.Message}";
            return false;
        }
        catch (HttpRequestException ex)
        {
            // Network/HTTP error during setup
            LastError = $"HTTP error during setup: {ex.StatusCode} - {ex.Message}";
            return false;
        }
        catch (Exception ex)
        {
            // Unexpected error
            LastError = $"Unexpected error during setup: {ex.GetType().Name} - {ex.Message}";
            return false;
        }
    }

    /// <summary>
    /// Gets the last error message from initialization, if any.
    /// </summary>
    public string? LastError { get; private set; }

    /// <summary>
    /// Checks if Keycloak is available by verifying OIDC discovery works.
    /// </summary>
    /// <remarks>
    /// We check the master realm's OIDC discovery endpoint rather than /health/ready
    /// because Keycloak in dev mode doesn't expose health endpoints by default.
    /// </remarks>
    public async Task<bool> IsHealthyAsync()
    {
        try
        {
            // Check master realm OIDC discovery - this works in both dev and prod mode
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var response = await GetHttpClient().GetAsync("/realms/master/.well-known/openid-configuration", cts.Token);
            return response.IsSuccessStatusCode;
        }
        catch (TaskCanceledException)
        {
            // Timeout - Keycloak not responding
            return false;
        }
        catch (HttpRequestException)
        {
            // Network error - Keycloak not reachable
            return false;
        }
        catch (InvalidOperationException)
        {
            // HttpClient not initialized
            return false;
        }
    }

    /// <summary>
    /// Creates a test client in the Keycloak realm.
    /// </summary>
    public async Task<KeycloakClient> CreateClientAsync(KeycloakClientOptions options)
    {
        var client = new KeycloakClient
        {
            ClientId = options.ClientId,
            Secret = options.ClientSecret,
            Name = options.Name ?? options.ClientId,
            Enabled = true,
            Protocol = "openid-connect",
            PublicClient = options.IsPublic,
            DirectAccessGrantsEnabled = options.AllowPasswordGrant,
            StandardFlowEnabled = options.AllowAuthorizationCodeGrant,
            ServiceAccountsEnabled = options.AllowClientCredentialsGrant,
            RedirectUris = options.RedirectUris.ToList(),
            WebOrigins = options.WebOrigins.ToList()
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, $"/admin/realms/{RealmName}/clients")
        {
            Content = JsonContent.Create(client, options: AdminApiJsonOptions)
        };
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _adminToken);

        var response = await GetHttpClient().SendAsync(request);
        response.EnsureSuccessStatusCode();

        return client;
    }

    /// <summary>
    /// Creates a test user in the Keycloak realm.
    /// </summary>
    public async Task<KeycloakUser> CreateUserAsync(KeycloakUserOptions options)
    {
        var user = new KeycloakUser
        {
            Username = options.Username,
            Email = options.Email ?? $"{options.Username}@test.local",
            FirstName = options.FirstName ?? "Test",
            LastName = options.LastName ?? "User",
            Enabled = true,
            EmailVerified = true,
            Credentials =
            [
                new KeycloakCredential
                {
                    Type = "password",
                    Value = options.Password,
                    Temporary = false
                }
            ]
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, $"/admin/realms/{RealmName}/users")
        {
            Content = JsonContent.Create(user, options: AdminApiJsonOptions)
        };
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _adminToken);

        var response = await GetHttpClient().SendAsync(request);
        response.EnsureSuccessStatusCode();

        return user;
    }

    /// <summary>
    /// Gets an access token using resource owner password credentials.
    /// </summary>
    public async Task<KeycloakTokenResponse> GetTokenAsync(
        string clientId,
        string? clientSecret,
        string username,
        string password,
        string scope = "openid")
    {
        var parameters = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = clientId,
            ["username"] = username,
            ["password"] = password,
            ["scope"] = scope
        };

        if (!string.IsNullOrEmpty(clientSecret))
        {
            parameters["client_secret"] = clientSecret;
        }

        var response = await GetHttpClient().PostAsync(
            $"/realms/{RealmName}/protocol/openid-connect/token",
            new FormUrlEncodedContent(parameters));

        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<KeycloakTokenResponse>(TokenResponseJsonOptions)
            ?? throw new InvalidOperationException("Failed to parse token response");
    }

    /// <summary>
    /// Gets an access token using client credentials.
    /// </summary>
    public async Task<KeycloakTokenResponse> GetClientCredentialsTokenAsync(
        string clientId,
        string clientSecret,
        string scope = "openid")
    {
        var parameters = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
            ["scope"] = scope
        };

        var response = await GetHttpClient().PostAsync(
            $"/realms/{RealmName}/protocol/openid-connect/token",
            new FormUrlEncodedContent(parameters));

        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<KeycloakTokenResponse>(TokenResponseJsonOptions)
            ?? throw new InvalidOperationException("Failed to parse token response");
    }

    /// <summary>
    /// Refreshes an access token.
    /// </summary>
    public async Task<KeycloakTokenResponse> RefreshTokenAsync(
        string clientId,
        string? clientSecret,
        string refreshToken)
    {
        var parameters = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = clientId,
            ["refresh_token"] = refreshToken
        };

        if (!string.IsNullOrEmpty(clientSecret))
        {
            parameters["client_secret"] = clientSecret;
        }

        var response = await GetHttpClient().PostAsync(
            $"/realms/{RealmName}/protocol/openid-connect/token",
            new FormUrlEncodedContent(parameters));

        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<KeycloakTokenResponse>(TokenResponseJsonOptions)
            ?? throw new InvalidOperationException("Failed to parse token response");
    }

    /// <summary>
    /// Revokes a token.
    /// </summary>
    public async Task RevokeTokenAsync(
        string clientId,
        string? clientSecret,
        string token,
        string? tokenTypeHint = null)
    {
        var parameters = new Dictionary<string, string>
        {
            ["client_id"] = clientId,
            ["token"] = token
        };

        if (!string.IsNullOrEmpty(clientSecret))
        {
            parameters["client_secret"] = clientSecret;
        }

        if (!string.IsNullOrEmpty(tokenTypeHint))
        {
            parameters["token_type_hint"] = tokenTypeHint;
        }

        var response = await GetHttpClient().PostAsync(
            $"/realms/{RealmName}/protocol/openid-connect/revoke",
            new FormUrlEncodedContent(parameters));

        response.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// Introspects a token.
    /// </summary>
    public async Task<KeycloakIntrospectionResponse> IntrospectTokenAsync(
        string clientId,
        string clientSecret,
        string token)
    {
        var parameters = new Dictionary<string, string>
        {
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
            ["token"] = token
        };

        var response = await GetHttpClient().PostAsync(
            $"/realms/{RealmName}/protocol/openid-connect/token/introspect",
            new FormUrlEncodedContent(parameters));

        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<KeycloakIntrospectionResponse>(TokenResponseJsonOptions)
            ?? throw new InvalidOperationException("Failed to parse introspection response");
    }

    /// <summary>
    /// Gets the OIDC discovery document.
    /// </summary>
    public async Task<JsonDocument> GetDiscoveryDocumentAsync()
    {
        var response = await GetHttpClient().GetAsync($"/realms/{RealmName}/.well-known/openid-configuration");
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<JsonDocument>()
            ?? throw new InvalidOperationException("Failed to parse discovery document");
    }

    private async Task<string> GetAdminTokenAsync(string username, string password)
    {
        var parameters = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "admin-cli",
            ["username"] = username,
            ["password"] = password
        };

        var response = await GetHttpClient().PostAsync(
            "/realms/master/protocol/openid-connect/token",
            new FormUrlEncodedContent(parameters));

        response.EnsureSuccessStatusCode();

        var token = await response.Content.ReadFromJsonAsync<KeycloakTokenResponse>(TokenResponseJsonOptions);
        return token?.AccessToken ?? throw new InvalidOperationException("Failed to get admin token");
    }

    private async Task EnsureRealmExistsAsync()
    {
        // Check if realm exists
        using var checkRequest = new HttpRequestMessage(HttpMethod.Get, $"/admin/realms/{RealmName}");
        checkRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _adminToken);

        var checkResponse = await GetHttpClient().SendAsync(checkRequest);
        if (checkResponse.IsSuccessStatusCode)
        {
            return; // Realm already exists
        }

        // Create realm
        var realm = new
        {
            realm = RealmName,
            enabled = true,
            registrationAllowed = false,
            loginWithEmailAllowed = true,
            duplicateEmailsAllowed = false,
            resetPasswordAllowed = true,
            editUsernameAllowed = false,
            bruteForceProtected = false
        };

        using var createRequest = new HttpRequestMessage(HttpMethod.Post, "/admin/realms")
        {
            Content = JsonContent.Create(realm, options: AdminApiJsonOptions)
        };
        createRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _adminToken);

        var createResponse = await GetHttpClient().SendAsync(createRequest);
        createResponse.EnsureSuccessStatusCode();
    }

    private HttpClient GetHttpClient()
    {
        return _httpClient ?? throw new InvalidOperationException("Fixture not initialized");
    }

    // Token responses use snake_case (access_token, refresh_token, etc.)
    private static readonly JsonSerializerOptions TokenResponseJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    // Admin API requests/responses use camelCase
    private static readonly JsonSerializerOptions AdminApiJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        _httpClient?.Dispose();
        await Task.CompletedTask;
    }
}

/// <summary>
/// Options for creating a Keycloak client.
/// </summary>
public sealed class KeycloakClientOptions
{
    /// <summary>
    /// The client identifier.
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// The client secret (null for public clients).
    /// </summary>
    public string? ClientSecret { get; init; }

    /// <summary>
    /// Display name.
    /// </summary>
    public string? Name { get; init; }

    /// <summary>
    /// Whether this is a public client.
    /// </summary>
    public bool IsPublic { get; init; }

    /// <summary>
    /// Allow password grant.
    /// </summary>
    public bool AllowPasswordGrant { get; init; }

    /// <summary>
    /// Allow authorization code grant.
    /// </summary>
    public bool AllowAuthorizationCodeGrant { get; init; } = true;

    /// <summary>
    /// Allow client credentials grant.
    /// </summary>
    public bool AllowClientCredentialsGrant { get; init; }

    /// <summary>
    /// Valid redirect URIs.
    /// </summary>
    public string[] RedirectUris { get; init; } = ["*"];

    /// <summary>
    /// Allowed web origins.
    /// </summary>
    public string[] WebOrigins { get; init; } = ["*"];
}

/// <summary>
/// Options for creating a Keycloak user.
/// </summary>
public sealed class KeycloakUserOptions
{
    /// <summary>
    /// The username.
    /// </summary>
    public required string Username { get; init; }

    /// <summary>
    /// The password.
    /// </summary>
    public required string Password { get; init; }

    /// <summary>
    /// Email address.
    /// </summary>
    public string? Email { get; init; }

    /// <summary>
    /// First name.
    /// </summary>
    public string? FirstName { get; init; }

    /// <summary>
    /// Last name.
    /// </summary>
    public string? LastName { get; init; }
}

/// <summary>
/// Keycloak client representation for API operations.
/// </summary>
public sealed class KeycloakClient
{
    [JsonPropertyName("clientId")]
    public string ClientId { get; set; } = string.Empty;

    [JsonPropertyName("secret")]
    public string? Secret { get; set; }

    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; } = true;

    [JsonPropertyName("protocol")]
    public string Protocol { get; set; } = "openid-connect";

    [JsonPropertyName("publicClient")]
    public bool PublicClient { get; set; }

    [JsonPropertyName("directAccessGrantsEnabled")]
    public bool DirectAccessGrantsEnabled { get; set; }

    [JsonPropertyName("standardFlowEnabled")]
    public bool StandardFlowEnabled { get; set; } = true;

    [JsonPropertyName("serviceAccountsEnabled")]
    public bool ServiceAccountsEnabled { get; set; }

    [JsonPropertyName("redirectUris")]
    public List<string> RedirectUris { get; set; } = [];

    [JsonPropertyName("webOrigins")]
    public List<string> WebOrigins { get; set; } = [];
}

/// <summary>
/// Keycloak user representation for API operations.
/// </summary>
public sealed class KeycloakUser
{
    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    [JsonPropertyName("email")]
    public string? Email { get; set; }

    [JsonPropertyName("firstName")]
    public string? FirstName { get; set; }

    [JsonPropertyName("lastName")]
    public string? LastName { get; set; }

    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; } = true;

    [JsonPropertyName("emailVerified")]
    public bool EmailVerified { get; set; }

    [JsonPropertyName("credentials")]
    public List<KeycloakCredential> Credentials { get; set; } = [];
}

/// <summary>
/// Keycloak credential representation.
/// </summary>
public sealed class KeycloakCredential
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "password";

    [JsonPropertyName("value")]
    public string Value { get; set; } = string.Empty;

    [JsonPropertyName("temporary")]
    public bool Temporary { get; set; }
}

/// <summary>
/// Keycloak token response.
/// </summary>
public sealed class KeycloakTokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    [JsonPropertyName("refresh_expires_in")]
    public int RefreshExpiresIn { get; set; }

    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = "Bearer";

    [JsonPropertyName("id_token")]
    public string? IdToken { get; set; }

    [JsonPropertyName("not-before-policy")]
    public int NotBeforePolicy { get; set; }

    [JsonPropertyName("session_state")]
    public string? SessionState { get; set; }

    [JsonPropertyName("scope")]
    public string? Scope { get; set; }
}

/// <summary>
/// Keycloak token introspection response.
/// </summary>
public sealed class KeycloakIntrospectionResponse
{
    [JsonPropertyName("active")]
    public bool Active { get; set; }

    [JsonPropertyName("exp")]
    public long? Exp { get; set; }

    [JsonPropertyName("iat")]
    public long? Iat { get; set; }

    [JsonPropertyName("sub")]
    public string? Sub { get; set; }

    [JsonPropertyName("aud")]
    public object? Aud { get; set; }

    [JsonPropertyName("client_id")]
    public string? ClientId { get; set; }

    [JsonPropertyName("username")]
    public string? Username { get; set; }

    [JsonPropertyName("scope")]
    public string? Scope { get; set; }
}
