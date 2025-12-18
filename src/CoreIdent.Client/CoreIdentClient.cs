using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace CoreIdent.Client;

/// <summary>
/// Default implementation of <see cref="ICoreIdentClient"/>.
/// </summary>
public sealed class CoreIdentClient : ICoreIdentClient, IDisposable
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    private static readonly TimeSpan DiscoveryCacheLifetime = TimeSpan.FromHours(24);
    private static readonly TimeSpan JwksCacheLifetime = TimeSpan.FromHours(24);

    private readonly CoreIdentClientOptions _options;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly ISecureTokenStorage _tokenStorage;
    private readonly IBrowserLauncher _browserLauncher;
    private readonly TimeProvider _timeProvider;

    private readonly ECDsaSecurityKey? _dpopKey;
    private readonly ECDsa? _dpopEcdsa;

    private readonly object _dpopNonceGate = new();
    private readonly Dictionary<string, string> _dpopNoncesByHtu = new(StringComparer.Ordinal);

    private readonly object _discoveryGate = new();
    private DiscoveryDocument? _discovery;
    private DateTimeOffset _discoveryCachedAt;

    private readonly object _jwksGate = new();
    private IReadOnlyCollection<SecurityKey>? _jwksSigningKeys;
    private DateTimeOffset _jwksCachedAt;

    private readonly object _authGate = new();
    private bool _isAuthenticated;

    /// <summary>
    /// Creates a new <see cref="CoreIdentClient"/>.
    /// </summary>
    public CoreIdentClient(
        CoreIdentClientOptions options,
        HttpClient? httpClient = null,
        ISecureTokenStorage? tokenStorage = null,
        IBrowserLauncher? browserLauncher = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrWhiteSpace(options.Authority))
        {
            throw new ArgumentException("Authority is required.", nameof(options));
        }

        if (string.IsNullOrWhiteSpace(options.ClientId))
        {
            throw new ArgumentException("ClientId is required.", nameof(options));
        }

        if (string.IsNullOrWhiteSpace(options.RedirectUri))
        {
            throw new ArgumentException("RedirectUri is required.", nameof(options));
        }

        _options = options;

        if (httpClient is null)
        {
            _ownsHttp = true;
            _http = new HttpClient
            {
                BaseAddress = new Uri(NormalizeAuthority(options.Authority), UriKind.Absolute)
            };
        }
        else
        {
            _ownsHttp = false;
            _http = httpClient;
            if (_http.BaseAddress is null)
            {
                _http.BaseAddress = new Uri(NormalizeAuthority(options.Authority), UriKind.Absolute);
            }
        }

        _tokenStorage = tokenStorage ?? new InMemoryTokenStorage();
        _browserLauncher = browserLauncher ?? new SystemBrowserLauncher();
        _timeProvider = timeProvider ?? TimeProvider.System;

        if (_options.UseDPoP)
        {
            _dpopEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            _dpopKey = new ECDsaSecurityKey(_dpopEcdsa);
        }
    }

    /// <inheritdoc />
    public bool IsAuthenticated
    {
        get
        {
            lock (_authGate)
            {
                return _isAuthenticated;
            }
        }
        private set
        {
            var changed = false;

            lock (_authGate)
            {
                if (_isAuthenticated != value)
                {
                    _isAuthenticated = value;
                    changed = true;
                }
            }

            if (changed)
            {
                AuthStateChanged?.Invoke(this, new AuthStateChangedEventArgs(value));
            }
        }
    }

    private async Task TryRevokeAsync(string revocationEndpoint, string token, string tokenTypeHint, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(_options.ClientId))
        {
            return;
        }

        try
        {
            var form = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["token"] = token,
                ["token_type_hint"] = tokenTypeHint,
                ["client_id"] = _options.ClientId
            };

            var revocationUri = GetAbsoluteEndpointUri(revocationEndpoint);
            using var msg = new HttpRequestMessage(HttpMethod.Post, revocationUri)
            {
                Content = new FormUrlEncodedContent(form)
            };

            if (_options.UseDPoP)
            {
                var htu = msg.RequestUri!.ToString();
                var dpopNonce = GetDpopNonce(htu);
                msg.Headers.TryAddWithoutValidation("DPoP", CreateDpopProofJwt("POST", htu, dpopNonce, accessToken: null));
            }

            if (!string.IsNullOrWhiteSpace(_options.ClientSecret))
            {
                var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Uri.EscapeDataString(_options.ClientId)}:{Uri.EscapeDataString(_options.ClientSecret)}"));
                msg.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic);
            }

            using var _ = await _http.SendAsync(msg, ct);
        }
        catch
        {
            // best-effort
        }
    }

    /// <inheritdoc />
    public event EventHandler<AuthStateChangedEventArgs>? AuthStateChanged;

    /// <inheritdoc />
    public async Task<AuthResult> LoginAsync(CancellationToken ct = default)
    {
        var discovery = await GetDiscoveryAsync(ct);
        if (discovery.AuthorizationEndpoint is null)
        {
            return AuthResult.Fail("configuration_error", "Discovery document does not include authorization_endpoint.");
        }

        if (discovery.TokenEndpoint is null)
        {
            return AuthResult.Fail("configuration_error", "Discovery document does not include token_endpoint.");
        }

        var state = Pkce.Base64UrlEncode(RandomNumberGenerator.GetBytes(16));
        var nonce = Pkce.Base64UrlEncode(RandomNumberGenerator.GetBytes(16));

        string? codeVerifier = null;
        string? codeChallenge = null;

        if (_options.UsePkce)
        {
            codeVerifier = Pkce.CreateCodeVerifier();
            codeChallenge = Pkce.CreateS256CodeChallenge(codeVerifier);
        }

        var scope = string.Join(' ', _options.Scopes ?? ["openid", "profile"]);

        var authorizeParams = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["client_id"] = _options.ClientId,
            ["redirect_uri"] = _options.RedirectUri,
            ["response_type"] = "code",
            ["scope"] = scope,
            ["state"] = state,
            ["nonce"] = nonce
        };

        if (_options.UsePkce)
        {
            authorizeParams["code_challenge"] = codeChallenge!;
            authorizeParams["code_challenge_method"] = "S256";
        }

        var authorizeUrl = UrlHelpers.AppendQueryString(discovery.AuthorizationEndpoint, authorizeParams);

        var browserResult = await _browserLauncher.LaunchAsync(authorizeUrl, _options.RedirectUri, ct);
        if (!browserResult.IsSuccess)
        {
            return AuthResult.Fail(browserResult.Error ?? "login_failed", browserResult.ErrorDescription);
        }

        if (string.IsNullOrWhiteSpace(browserResult.ResponseUrl))
        {
            return AuthResult.Fail("login_failed", "Browser response did not include a response URL.");
        }

        var query = UrlHelpers.ParseQuery(browserResult.ResponseUrl);

        if (query.TryGetValue("error", out var error))
        {
            query.TryGetValue("error_description", out var desc);
            return AuthResult.Fail(error, desc);
        }

        if (!query.TryGetValue("state", out var returnedState) || !string.Equals(returnedState, state, StringComparison.Ordinal))
        {
            return AuthResult.Fail("invalid_state", "State parameter mismatch.");
        }

        if (!query.TryGetValue("code", out var code) || string.IsNullOrWhiteSpace(code))
        {
            return AuthResult.Fail("invalid_response", "Authorization response did not include a code.");
        }

        var tokenResult = await ExchangeAuthorizationCodeAsync(discovery.TokenEndpoint, code, codeVerifier, ct);
        if (!tokenResult.IsSuccess)
        {
            return AuthResult.Fail(tokenResult.Error ?? "token_error", tokenResult.ErrorDescription);
        }

        var tokenResponse = tokenResult.Token;
        if (tokenResponse is null || string.IsNullOrWhiteSpace(tokenResponse.AccessToken))
        {
            return AuthResult.Fail("token_error", "Token response did not include an access token.");
        }

        if (!string.IsNullOrWhiteSpace(tokenResponse.IdToken))
        {
            var validated = await ValidateIdTokenAsync(tokenResponse.IdToken, expectedNonce: nonce, ct);
            if (!validated.IsSuccess)
            {
                return AuthResult.Fail(validated.Error ?? "invalid_id_token", validated.ErrorDescription);
            }
        }

        await _tokenStorage.StoreTokensAsync(ToTokenSet(tokenResponse), ct);
        IsAuthenticated = true;

        return AuthResult.Success();
    }

    /// <inheritdoc />
    public async Task<AuthResult> LoginSilentAsync(CancellationToken ct = default)
    {
        var tokens = await _tokenStorage.GetTokensAsync(ct);
        if (tokens is null)
        {
            IsAuthenticated = false;
            return AuthResult.Fail("not_authenticated");
        }

        if (!ShouldRefresh(tokens))
        {
            IsAuthenticated = true;
            return AuthResult.Success();
        }

        if (string.IsNullOrWhiteSpace(tokens.RefreshToken))
        {
            IsAuthenticated = true;
            return AuthResult.Success();
        }

        var refreshed = await TryRefreshAsync(tokens.RefreshToken, ct);
        if (!refreshed.IsSuccess || refreshed.Token is null)
        {
            await _tokenStorage.ClearTokensAsync(ct);
            IsAuthenticated = false;
            return AuthResult.Fail("refresh_failed");
        }

        await _tokenStorage.StoreTokensAsync(ToTokenSet(refreshed.Token), ct);
        IsAuthenticated = true;
        return AuthResult.Success();
    }

    /// <inheritdoc />
    public async Task LogoutAsync(CancellationToken ct = default)
    {
        var tokens = await _tokenStorage.GetTokensAsync(ct);
        await _tokenStorage.ClearTokensAsync(ct);
        IsAuthenticated = false;

        if (tokens is null)
        {
            return;
        }

        var discovery = await GetDiscoveryAsync(ct);

        // Best-effort: revoke refresh token to prevent further silent logins.
        if (!string.IsNullOrWhiteSpace(tokens.RefreshToken) && !string.IsNullOrWhiteSpace(discovery.RevocationEndpoint))
        {
            _ = TryRevokeAsync(discovery.RevocationEndpoint, tokens.RefreshToken, tokenTypeHint: "refresh_token", ct);
        }

        // Optional: if server advertises end_session_endpoint, attempt browser logout.
        if (!string.IsNullOrWhiteSpace(discovery.EndSessionEndpoint)
            && !string.IsNullOrWhiteSpace(tokens.IdToken)
            && !string.IsNullOrWhiteSpace(_options.PostLogoutRedirectUri))
        {
            var query = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["id_token_hint"] = tokens.IdToken,
                ["post_logout_redirect_uri"] = _options.PostLogoutRedirectUri,
                ["state"] = Pkce.Base64UrlEncode(RandomNumberGenerator.GetBytes(16))
            };

            var url = UrlHelpers.AppendQueryString(discovery.EndSessionEndpoint, query);

            try
            {
                await _browserLauncher.LaunchAsync(url, _options.PostLogoutRedirectUri, ct);
            }
            catch
            {
                // best-effort
            }
        }
    }

    /// <inheritdoc />
    public async Task<string?> GetAccessTokenAsync(CancellationToken ct = default)
    {
        var tokens = await _tokenStorage.GetTokensAsync(ct);
        if (tokens is null)
        {
            IsAuthenticated = false;
            return null;
        }

        if (!ShouldRefresh(tokens))
        {
            IsAuthenticated = true;
            return tokens.AccessToken;
        }

        if (string.IsNullOrWhiteSpace(tokens.RefreshToken))
        {
            IsAuthenticated = true;
            return tokens.AccessToken;
        }

        var refreshed = await TryRefreshAsync(tokens.RefreshToken, ct);
        if (!refreshed.IsSuccess || refreshed.Token is null || string.IsNullOrWhiteSpace(refreshed.Token.AccessToken))
        {
            await _tokenStorage.ClearTokensAsync(ct);
            IsAuthenticated = false;
            return null;
        }

        var tokenSet = ToTokenSet(refreshed.Token);

        // Preserve refresh token if server did not return a new one.
        if (string.IsNullOrWhiteSpace(tokenSet.RefreshToken))
        {
            tokenSet = tokenSet with { RefreshToken = tokens.RefreshToken };
        }

        await _tokenStorage.StoreTokensAsync(tokenSet, ct);
        IsAuthenticated = true;
        return tokenSet.AccessToken;
    }

    /// <inheritdoc />
    public async Task<ClaimsPrincipal?> GetUserAsync(CancellationToken ct = default)
    {
        var accessToken = await GetAccessTokenAsync(ct);
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            return null;
        }

        var tokens = await _tokenStorage.GetTokensAsync(ct);

        var discovery = await GetDiscoveryAsync(ct);
        if (!string.IsNullOrWhiteSpace(discovery.UserInfoEndpoint))
        {
            var userInfoUri = GetAbsoluteEndpointUri(discovery.UserInfoEndpoint);

            using var resp = await SendUserInfoAsync(userInfoUri, accessToken, ct);
            if (!resp.IsSuccessStatusCode)
            {
                return null;
            }

            var json = await resp.Content.ReadAsStringAsync(ct);
            if (string.IsNullOrWhiteSpace(json))
            {
                return null;
            }

            using var doc = JsonDocument.Parse(json);
            var claims = new List<Claim>();

            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                AddClaimsFromJson(claims, prop.Name, prop.Value);
            }

            return new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType: "CoreIdent"));
        }

        if (!string.IsNullOrWhiteSpace(tokens?.IdToken))
        {
            var validated = await ValidateIdTokenAsync(tokens.IdToken, expectedNonce: null, ct);
            if (!validated.IsSuccess || validated.Principal is null)
            {
                return null;
            }

            return validated.Principal;
        }

        return null;
    }

    private async Task<HttpResponseMessage> SendUserInfoAsync(Uri userInfoUri, string accessToken, CancellationToken ct)
    {
        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, userInfoUri);

            if (_options.UseDPoP)
            {
                req.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
                var htu = req.RequestUri!.ToString();
                var dpopNonce = GetDpopNonce(htu);
                req.Headers.TryAddWithoutValidation("DPoP", CreateDpopProofJwt("GET", htu, dpopNonce, accessToken));
            }
            else
            {
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            }

            var resp = await _http.SendAsync(req, ct);

            if (TryCaptureDpopNonce(req.RequestUri!.ToString(), resp))
            {
                if (!resp.IsSuccessStatusCode && attempt == 0)
                {
                    resp.Dispose();
                    continue;
                }
            }

            return resp;
        }

        throw new InvalidOperationException("Unexpected UserInfo retry loop termination.");
    }

    private static void AddClaimsFromJson(List<Claim> claims, string name, JsonElement value)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.String:
                claims.Add(new Claim(name, value.GetString() ?? string.Empty));
                break;
            case JsonValueKind.Number:
                claims.Add(new Claim(name, value.ToString()));
                break;
            case JsonValueKind.True:
            case JsonValueKind.False:
                claims.Add(new Claim(name, value.GetBoolean() ? "true" : "false"));
                break;
            case JsonValueKind.Array:
                foreach (var item in value.EnumerateArray())
                {
                    AddClaimsFromJson(claims, name, item);
                }
                break;
            case JsonValueKind.Object:
                claims.Add(new Claim(name, value.GetRawText()));
                break;
            default:
                break;
        }
    }

    private async Task<DiscoveryDocument> GetDiscoveryAsync(CancellationToken ct)
    {
        lock (_discoveryGate)
        {
            if (_discovery is not null && (_timeProvider.GetUtcNow() - _discoveryCachedAt) < DiscoveryCacheLifetime)
            {
                return _discovery;
            }
        }

        var authority = NormalizeAuthority(_options.Authority);
        var authorityUri = new Uri(authority, UriKind.Absolute);
        var discoveryUrl = new Uri(authorityUri, ".well-known/openid-configuration");

        using var resp = await _http.GetAsync(discoveryUrl, ct);
        resp.EnsureSuccessStatusCode();

        var json = await resp.Content.ReadAsStringAsync(ct);
        var doc = JsonSerializer.Deserialize<DiscoveryDocument>(json, SerializerOptions);
        if (doc is null)
        {
            throw new InvalidOperationException("Failed to parse discovery document.");
        }

        lock (_discoveryGate)
        {
            _discovery = doc;
            _discoveryCachedAt = _timeProvider.GetUtcNow();
        }

        return doc;
    }

    private async Task<IReadOnlyCollection<SecurityKey>> GetJwksSigningKeysAsync(DiscoveryDocument discovery, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(discovery.JwksUri))
        {
            return Array.Empty<SecurityKey>();
        }

        lock (_jwksGate)
        {
            if (_jwksSigningKeys is not null && (_timeProvider.GetUtcNow() - _jwksCachedAt) < JwksCacheLifetime)
            {
                return _jwksSigningKeys;
            }
        }

        using var resp = await _http.GetAsync(discovery.JwksUri, ct);
        resp.EnsureSuccessStatusCode();

        var json = await resp.Content.ReadAsStringAsync(ct);
        var jwks = new JsonWebKeySet(json);
        var keys = jwks.GetSigningKeys().ToArray();

        lock (_jwksGate)
        {
            _jwksSigningKeys = keys;
            _jwksCachedAt = _timeProvider.GetUtcNow();
        }

        return keys;
    }

    private async Task<IdTokenValidationResult> ValidateIdTokenAsync(string idToken, string? expectedNonce, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(idToken))
        {
            return IdTokenValidationResult.Fail("invalid_id_token", "ID token was empty.");
        }

        var discovery = await GetDiscoveryAsync(ct);
        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(idToken);

        if (string.Equals(jwt.Alg, "none", StringComparison.OrdinalIgnoreCase))
        {
            return IdTokenValidationResult.Fail("invalid_id_token", "ID token is unsigned (alg=none).");
        }

        var signingKeys = await GetJwksSigningKeysAsync(discovery, ct);
        ClaimsPrincipal principal;

        if (signingKeys.Count > 0)
        {
            var parameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = discovery.Issuer,
                ValidateAudience = true,
                ValidAudience = _options.ClientId,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = signingKeys,
                ClockSkew = TimeSpan.FromMinutes(2)
            };

            var result = await handler.ValidateTokenAsync(idToken, parameters);
            if (!result.IsValid || result.ClaimsIdentity is null)
            {
                return IdTokenValidationResult.Fail("invalid_id_token", result.Exception?.Message);
            }

            principal = new ClaimsPrincipal(result.ClaimsIdentity);
        }
        else
        {
            if (!string.IsNullOrWhiteSpace(discovery.Issuer)
                && !string.Equals(jwt.Issuer, discovery.Issuer, StringComparison.Ordinal))
            {
                return IdTokenValidationResult.Fail("invalid_id_token", "ID token issuer did not match discovery issuer.");
            }

            if (jwt.Audiences is null || !jwt.Audiences.Contains(_options.ClientId, StringComparer.Ordinal))
            {
                return IdTokenValidationResult.Fail("invalid_id_token", "ID token audience did not include this client_id.");
            }

            var now = _timeProvider.GetUtcNow().UtcDateTime;
            if (jwt.ValidTo != DateTime.MinValue && jwt.ValidTo < now)
            {
                return IdTokenValidationResult.Fail("invalid_id_token", "ID token is expired.");
            }

            principal = new ClaimsPrincipal(new ClaimsIdentity(jwt.Claims, authenticationType: "CoreIdent"));
        }

        if (!string.IsNullOrWhiteSpace(expectedNonce))
        {
            var nonceClaim = principal.FindFirst("nonce")?.Value;
            if (!string.Equals(nonceClaim, expectedNonce, StringComparison.Ordinal))
            {
                return IdTokenValidationResult.Fail("invalid_nonce", "ID token nonce did not match.");
            }
        }

        return IdTokenValidationResult.Success(principal);
    }

    private async Task<TokenRequestResult> ExchangeAuthorizationCodeAsync(
        string tokenEndpoint,
        string code,
        string? codeVerifier,
        CancellationToken ct)
    {
        var form = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = _options.ClientId,
            ["code"] = code,
            ["redirect_uri"] = _options.RedirectUri
        };

        if (_options.UsePkce)
        {
            if (string.IsNullOrWhiteSpace(codeVerifier))
            {
                throw new InvalidOperationException("PKCE is enabled but codeVerifier is missing.");
            }

            form["code_verifier"] = codeVerifier;
        }

        return await PostTokenRequestAsync(tokenEndpoint, form, ct);
    }

    private async Task<TokenRequestResult> TryRefreshAsync(string refreshToken, CancellationToken ct)
    {
        var discovery = await GetDiscoveryAsync(ct);
        if (string.IsNullOrWhiteSpace(discovery.TokenEndpoint))
        {
            return TokenRequestResult.Fail("configuration_error", "Discovery document does not include token_endpoint.");
        }

        var form = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = _options.ClientId,
            ["refresh_token"] = refreshToken
        };

        return await PostTokenRequestAsync(discovery.TokenEndpoint, form, ct);
    }

    private async Task<TokenRequestResult> PostTokenRequestAsync(string tokenEndpoint, Dictionary<string, string> form, CancellationToken ct)
    {
        var tokenUri = GetAbsoluteEndpointUri(tokenEndpoint);

        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var msg = new HttpRequestMessage(HttpMethod.Post, tokenUri)
            {
                Content = new FormUrlEncodedContent(form)
            };

            if (!string.IsNullOrWhiteSpace(_options.ClientSecret))
            {
                var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Uri.EscapeDataString(_options.ClientId)}:{Uri.EscapeDataString(_options.ClientSecret)}"));
                msg.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic);
            }

            if (_options.UseDPoP)
            {
                var htu = msg.RequestUri!.ToString();
                var dpopNonce = GetDpopNonce(htu);
                msg.Headers.TryAddWithoutValidation("DPoP", CreateDpopProofJwt("POST", htu, dpopNonce, accessToken: null));
            }

            using var resp = await _http.SendAsync(msg, ct);
            var body = await resp.Content.ReadAsStringAsync(ct);

            TryCaptureDpopNonce(msg.RequestUri!.ToString(), resp);

            if (!resp.IsSuccessStatusCode)
            {
                TryReadOAuthError(body, out var error, out var desc);

                if (_options.UseDPoP
                    && attempt == 0
                    && string.Equals(error, "use_dpop_nonce", StringComparison.Ordinal)
                    && GetDpopNonce(msg.RequestUri!.ToString()) is not null)
                {
                    continue;
                }

                return TokenRequestResult.Fail(error ?? "token_error", desc);
            }

            var parsed = JsonSerializer.Deserialize<OAuthTokenResponse>(body, SerializerOptions);
            if (parsed is null)
            {
                return TokenRequestResult.Fail("token_error", "Failed to parse token response.");
            }

            return TokenRequestResult.Success(parsed);
        }

        return TokenRequestResult.Fail("token_error", "Token request failed after retry.");
    }

    private Uri GetAbsoluteEndpointUri(string endpoint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(endpoint);

        if (Uri.TryCreate(endpoint, UriKind.Absolute, out var absolute))
        {
            return absolute;
        }

        if (_http.BaseAddress is null)
        {
            throw new InvalidOperationException("HttpClient.BaseAddress is required for relative endpoints.");
        }

        return new Uri(_http.BaseAddress, endpoint.TrimStart('/'));
    }

    private string? GetDpopNonce(string htu)
    {
        lock (_dpopNonceGate)
        {
            return _dpopNoncesByHtu.TryGetValue(htu, out var value) ? value : null;
        }
    }

    private void SetDpopNonce(string htu, string nonce)
    {
        lock (_dpopNonceGate)
        {
            _dpopNoncesByHtu[htu] = nonce;
        }
    }

    private bool TryCaptureDpopNonce(string htu, HttpResponseMessage resp)
    {
        if (!resp.Headers.TryGetValues("DPoP-Nonce", out var values))
        {
            return false;
        }

        var nonce = values.FirstOrDefault();
        if (string.IsNullOrWhiteSpace(nonce))
        {
            return false;
        }

        SetDpopNonce(htu, nonce);
        return true;
    }

    private string CreateDpopProofJwt(string htm, string htu, string? nonce, string? accessToken)
    {
        if (_dpopKey is null)
        {
            throw new InvalidOperationException("DPoP is enabled but no DPoP key is configured.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(htm);
        ArgumentException.ThrowIfNullOrWhiteSpace(htu);

        if (_dpopKey.KeyId is null)
        {
            _dpopKey.KeyId = Pkce.Base64UrlEncode(RandomNumberGenerator.GetBytes(16));
        }

        var now = _timeProvider.GetUtcNow();
        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["htm"] = htm.ToUpperInvariant(),
            ["htu"] = StripFragment(htu),
            ["iat"] = now.ToUnixTimeSeconds(),
            ["jti"] = Pkce.Base64UrlEncode(RandomNumberGenerator.GetBytes(16))
        };

        if (!string.IsNullOrWhiteSpace(nonce))
        {
            claims["nonce"] = nonce;
        }

        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            var bytes = Encoding.ASCII.GetBytes(accessToken);
            var hashed = SHA256.HashData(bytes);
            claims["ath"] = Pkce.Base64UrlEncode(hashed);
        }

        var jwk = CreatePublicJwk(_dpopKey);

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            SigningCredentials = new SigningCredentials(_dpopKey, SecurityAlgorithms.EcdsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["typ"] = "dpop+jwt",
                ["jwk"] = jwk
            }
        };

        var handler = new JsonWebTokenHandler();
        return handler.CreateToken(descriptor);
    }

    private static Dictionary<string, object> CreatePublicJwk(ECDsaSecurityKey key)
    {
        var ec = key.ECDsa;
        if (ec is null)
        {
            throw new InvalidOperationException("ECDsaSecurityKey did not contain an ECDsa instance.");
        }

        var parameters = ec.ExportParameters(false);
        if (parameters.Q.X is null || parameters.Q.Y is null)
        {
            throw new InvalidOperationException("ECDsa public key parameters were missing.");
        }

        return new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Pkce.Base64UrlEncode(parameters.Q.X),
            ["y"] = Pkce.Base64UrlEncode(parameters.Q.Y)
        };
    }

    private static string StripFragment(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var absolute))
        {
            return url.Split('#', 2)[0];
        }

        var builder = new UriBuilder(absolute) { Fragment = string.Empty };
        return builder.Uri.ToString();
    }

    private static bool TryReadOAuthError(string json, out string? error, out string? description)
    {
        error = null;
        description = null;

        if (string.IsNullOrWhiteSpace(json))
        {
            return false;
        }

        try
        {
            var parsed = JsonSerializer.Deserialize<OAuthErrorResponse>(json, SerializerOptions);
            error = parsed?.Error;
            description = parsed?.ErrorDescription;
            return !string.IsNullOrWhiteSpace(error);
        }
        catch
        {
            return false;
        }
    }

    private bool ShouldRefresh(TokenSet tokens)
    {
        var now = _timeProvider.GetUtcNow();
        return tokens.ExpiresAtUtc <= now.Add(_options.TokenRefreshThreshold);
    }

    private TokenSet ToTokenSet(OAuthTokenResponse response)
    {
        var now = _timeProvider.GetUtcNow();
        var expiresAt = now.Add(TimeSpan.FromSeconds(Math.Max(0, response.ExpiresIn)));

        return new TokenSet
        {
            AccessToken = response.AccessToken ?? string.Empty,
            RefreshToken = response.RefreshToken,
            IdToken = response.IdToken,
            Scope = response.Scope,
            TokenType = response.TokenType ?? "Bearer",
            ExpiresAtUtc = expiresAt
        };
    }

    private static string NormalizeAuthority(string authority)
    {
        var trimmed = authority.Trim();
        if (!trimmed.EndsWith("/", StringComparison.Ordinal))
        {
            trimmed += "/";
        }

        return trimmed;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_ownsHttp)
        {
            _http.Dispose();
        }

        _dpopEcdsa?.Dispose();
    }

    private sealed record TokenRequestResult(bool IsSuccess, OAuthTokenResponse? Token, string? Error, string? ErrorDescription)
    {
        public static TokenRequestResult Success(OAuthTokenResponse token) => new(true, token, null, null);

        public static TokenRequestResult Fail(string error, string? description) => new(false, null, error, description);
    }

    private sealed record IdTokenValidationResult(bool IsSuccess, ClaimsPrincipal? Principal, string? Error, string? ErrorDescription)
    {
        public static IdTokenValidationResult Success(ClaimsPrincipal principal) => new(true, principal, null, null);
        public static IdTokenValidationResult Fail(string error, string? description) => new(false, null, error, description);
    }
}
