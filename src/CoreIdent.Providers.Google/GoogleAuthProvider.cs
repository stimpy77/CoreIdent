using System.Security.Claims;
using System.Text.Json;
using System.Web;
using CoreIdent.Providers.Abstractions;
using CoreIdent.Providers.Abstractions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CoreIdent.Providers.Google;

/// <summary>
/// Google OAuth 2.0 authentication provider.
/// </summary>
public class GoogleAuthProvider : IExternalAuthProvider
{
    private readonly GoogleProviderOptions _options;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<GoogleAuthProvider> _logger;

    /// <summary>
    /// The Google provider name.
    /// </summary>
    public string ProviderName => "Google";

    /// <summary>
    /// Creates a new Google authentication provider.
    /// </summary>
    public GoogleAuthProvider(
        IOptions<GoogleProviderOptions> options,
        IHttpClientFactory httpClientFactory,
        ILogger<GoogleAuthProvider> logger)
    {
        _options = options.Value;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    /// <inheritdoc />
    public Task<string> BuildAuthorizationUrlAsync(
        string redirectUri,
        string? state,
        IEnumerable<string> scopes,
        CancellationToken ct = default)
    {
        var query = HttpUtility.ParseQueryString(string.Empty);
        
        query["client_id"] = _options.ClientId;
        query["redirect_uri"] = redirectUri ?? _options.RedirectUri;
        query["response_type"] = "code";
        query["scope"] = string.Join(" ", scopes);
        query["access_type"] = "offline"; // Request refresh token
        query["prompt"] = "consent"; // Force consent to get refresh token
        
        if (!string.IsNullOrEmpty(state))
        {
            query["state"] = state;
        }

        var url = $"{_options.AuthorizationEndpoint}?{query}";
        _logger.LogDebug("Generated Google authorization URL for scopes: {Scopes}", string.Join(" ", scopes));

        return Task.FromResult(url);
    }

    /// <inheritdoc />
    public async Task<ExternalAuthResult> ExchangeCodeAsync(
        string code,
        string redirectUri,
        CancellationToken ct = default)
    {
        try
        {
            var client = _httpClientFactory.CreateClient();
            
            var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = _options.ClientId,
                ["client_secret"] = _options.ClientSecret,
                ["code"] = code,
                ["grant_type"] = "authorization_code",
                ["redirect_uri"] = redirectUri ?? _options.RedirectUri ?? ""
            });

            var response = await client.PostAsync(_options.TokenEndpoint, content, ct);
            var responseBody = await response.Content.ReadAsStringAsync(ct);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Google token exchange failed: {StatusCode} {Body}", 
                    response.StatusCode, responseBody);
                return ExternalAuthResult.Failed(
                    "Failed to exchange authorization code",
                    "token_exchange_failed");
            }

            var tokenResponse = JsonSerializer.Deserialize<GoogleTokenResponse>(responseBody);
            
            if (tokenResponse == null || string.IsNullOrEmpty(tokenResponse.AccessToken))
            {
                return ExternalAuthResult.Failed(
                    "Invalid token response from Google",
                    "invalid_token_response");
            }

            // Get user info with the access token
            var userProfile = await GetUserInfoAsync(tokenResponse.AccessToken, ct);
            
            return ExternalAuthResult.Succeeded(userProfile);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error exchanging Google authorization code");
            return ExternalAuthResult.Failed(
                ex.Message,
                "exchange_error");
        }
    }

    /// <inheritdoc />
    public async Task<ExternalUserProfile> GetUserInfoAsync(
        string accessToken,
        CancellationToken ct = default)
    {
        var client = _httpClientFactory.CreateClient();
        client.DefaultRequestHeaders.Authorization = 
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

        var response = await client.GetAsync(_options.UserInfoEndpoint, ct);
        var responseBody = await response.Content.ReadAsStringAsync(ct);

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Google userinfo request failed: {StatusCode} {Body}",
                response.StatusCode, responseBody);
            throw new InvalidOperationException("Failed to get user info from Google");
        }

        var userInfo = JsonSerializer.Deserialize<GoogleUserInfoResponse>(responseBody);
        
        if (userInfo == null)
        {
            throw new InvalidOperationException("Invalid user info response from Google");
        }

        return new ExternalUserProfile(
            ProviderKey: userInfo.Sub ?? throw new InvalidOperationException("Missing 'sub' in Google response"),
            ProviderName: ProviderName,
            Email: userInfo.Email,
            DisplayName: userInfo.Name,
            FirstName: userInfo.GivenName,
            LastName: userInfo.FamilyName,
            PictureUrl: userInfo.Picture
        );
    }

    /// <inheritdoc />
    public async Task RevokeAccessAsync(string accessToken, CancellationToken ct = default)
    {
        var client = _httpClientFactory.CreateClient();
        
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = accessToken
        });

        var revokeResponse = await client.PostAsync(_options.RevokeEndpoint, content, ct);
        if (!revokeResponse.IsSuccessStatusCode)
        {
            _logger.LogWarning("Google token revocation failed with status {StatusCode}.", revokeResponse.StatusCode);
        }
    }

    private class GoogleTokenResponse
    {
        [System.Text.Json.Serialization.JsonPropertyName("access_token")]
        public string? AccessToken { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("refresh_token")]
        public string? RefreshToken { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("token_type")]
        public string? TokenType { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("expires_in")]
        public int? ExpiresIn { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("scope")]
        public string? Scope { get; set; }
    }

    private class GoogleUserInfoResponse
    {
        [System.Text.Json.Serialization.JsonPropertyName("sub")]
        public string? Sub { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("name")]
        public string? Name { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("given_name")]
        public string? GivenName { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("family_name")]
        public string? FamilyName { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("picture")]
        public string? Picture { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("email")]
        public string? Email { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("email_verified")]
        public bool? EmailVerified { get; set; }
    }
}
