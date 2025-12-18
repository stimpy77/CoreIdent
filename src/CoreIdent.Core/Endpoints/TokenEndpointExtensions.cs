using System.Diagnostics;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using CoreIdent.Core.Configuration;
using CoreIdent.Core.Extensions;
using CoreIdent.Core.Models;
using CoreIdent.Core.Observability;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;

namespace CoreIdent.Core.Endpoints;

/// <summary>
/// Endpoint mapping for the OAuth 2.0 token endpoint.
/// </summary>
public static class TokenEndpointExtensions
{
    /// <summary>
    /// Maps the token endpoint using route options resolved from DI.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <returns>The endpoint route builder.</returns>
    public static IEndpointRouteBuilder MapCoreIdentTokenEndpoint(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var routeOptions = endpoints.ServiceProvider.GetRequiredService<IOptions<CoreIdentRouteOptions>>().Value;
        var tokenPath = routeOptions.CombineWithBase(routeOptions.TokenPath);

        return endpoints.MapCoreIdentTokenEndpoint(tokenPath);
    }

    /// <summary>
    /// Maps the token endpoint at the specified path.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="tokenPath">Token endpoint path.</param>
    /// <returns>The endpoint route builder.</returns>
    public static IEndpointRouteBuilder MapCoreIdentTokenEndpoint(this IEndpointRouteBuilder endpoints, string tokenPath)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenPath);

        endpoints.MapPost(tokenPath, HandleTokenRequest);

        return endpoints;
    }

    private static async Task<IResult> HandleTokenRequest(
        HttpRequest request,
        IClientStore clientStore,
        ITokenService tokenService,
        IRefreshTokenStore refreshTokenStore,
        IUserStore userStore,
        IPasswordHasher passwordHasher,
        IAuthorizationCodeStore authorizationCodeStore,
        ICustomClaimsProvider customClaimsProvider,
        ICoreIdentMetrics metrics,
        IOptions<CoreIdentOptions> coreOptions,
        ILoggerFactory loggerFactory,
        TimeProvider timeProvider,
        CancellationToken ct)
    {
        var logger = loggerFactory.CreateLogger("CoreIdent.TokenEndpoint");
        using var _ = CoreIdentCorrelation.BeginScope(logger, request.HttpContext);
        var options = coreOptions.Value;

        using var activity = CoreIdentActivitySource.ActivitySource.StartActivity("coreident.token");

        if (!request.HasFormContentType)
        {
            activity?.SetTag("error", true);
            return TokenError(TokenErrors.InvalidRequest, "Content-Type must be application/x-www-form-urlencoded.");
        }

        var form = await request.ReadFormAsync(ct);
        var tokenRequest = ParseTokenRequest(form);

        var (clientId, clientSecret) = ExtractClientCredentials(request, tokenRequest);

        activity?.SetTag("grant_type", tokenRequest.GrantType);
        activity?.SetTag("client_id", clientId);

        var authStart = Stopwatch.GetTimestamp();

        if (string.IsNullOrWhiteSpace(clientId))
        {
            metrics.ClientAuthenticated("unknown", success: false, Stopwatch.GetElapsedTime(authStart).TotalMilliseconds);
            return TokenError(TokenErrors.InvalidClient, "Client authentication is required.", StatusCodes.Status401Unauthorized);
        }

        var client = await clientStore.FindByClientIdAsync(clientId, ct);
        if (client is null || !client.Enabled)
        {
            logger.LogWarning("Token request for unknown or disabled client: {ClientId}", clientId);
            metrics.ClientAuthenticated("unknown", success: false, Stopwatch.GetElapsedTime(authStart).TotalMilliseconds);
            return TokenError(TokenErrors.InvalidClient, "Client authentication failed.", StatusCodes.Status401Unauthorized);
        }

        var clientTypeLabel = client.ClientType.ToString().ToLowerInvariant();

        if (client.ClientType == ClientType.Confidential)
        {
            if (string.IsNullOrWhiteSpace(clientSecret))
            {
                metrics.ClientAuthenticated(clientTypeLabel, success: false, Stopwatch.GetElapsedTime(authStart).TotalMilliseconds);
                return TokenError(TokenErrors.InvalidClient, "Client secret is required for confidential clients.", StatusCodes.Status401Unauthorized);
            }

            var secretValid = await clientStore.ValidateClientSecretAsync(clientId, clientSecret, ct);
            if (!secretValid)
            {
                logger.LogWarning("Invalid client secret for client: {ClientId}", clientId);
                metrics.ClientAuthenticated(clientTypeLabel, success: false, Stopwatch.GetElapsedTime(authStart).TotalMilliseconds);
                return TokenError(TokenErrors.InvalidClient, "Client authentication failed.", StatusCodes.Status401Unauthorized);
            }
        }

        metrics.ClientAuthenticated(clientTypeLabel, success: true, Stopwatch.GetElapsedTime(authStart).TotalMilliseconds);

        if (!client.AllowedGrantTypes.Contains(tokenRequest.GrantType))
        {
            logger.LogWarning("Client {ClientId} attempted unauthorized grant type: {GrantType}", clientId, tokenRequest.GrantType);
            return TokenError(TokenErrors.UnauthorizedClient, $"Client is not authorized for grant type '{tokenRequest.GrantType}'.");
        }

        return tokenRequest.GrantType switch
        {
            GrantTypes.ClientCredentials => await HandleClientCredentialsAsync(
                client, tokenRequest, tokenService, refreshTokenStore, customClaimsProvider, metrics, options, timeProvider, logger, ct),
            GrantTypes.RefreshToken => await HandleRefreshTokenAsync(
                client, tokenRequest, tokenService, refreshTokenStore, userStore, customClaimsProvider, metrics, options, timeProvider, logger, ct),
            GrantTypes.AuthorizationCode => await HandleAuthorizationCodeAsync(
                client, tokenRequest, tokenService, refreshTokenStore, authorizationCodeStore, userStore, customClaimsProvider, metrics, options, timeProvider, logger, ct),
            GrantTypes.Password => await HandlePasswordGrantAsync(
                client, tokenRequest, tokenService, refreshTokenStore, userStore, passwordHasher, customClaimsProvider, metrics, options, timeProvider, logger, ct),
            _ => TokenError(TokenErrors.UnsupportedGrantType, $"Grant type '{tokenRequest.GrantType}' is not supported.")
        };
    }

    private static async Task<IResult> HandlePasswordGrantAsync(
        CoreIdentClient client,
        TokenRequest tokenRequest,
        ITokenService tokenService,
        IRefreshTokenStore refreshTokenStore,
        IUserStore userStore,
        IPasswordHasher passwordHasher,
        ICustomClaimsProvider customClaimsProvider,
        ICoreIdentMetrics metrics,
        CoreIdentOptions options,
        TimeProvider timeProvider,
        ILogger logger,
        CancellationToken ct)
    {
        var issuanceStart = Stopwatch.GetTimestamp();
        logger.LogWarning("Password grant is deprecated in OAuth 2.1. Consider using authorization code flow with PKCE.");

        if (string.IsNullOrWhiteSpace(tokenRequest.Username))
        {
            return TokenError(TokenErrors.InvalidRequest, "The username parameter is required.");
        }

        if (string.IsNullOrWhiteSpace(tokenRequest.Password))
        {
            return TokenError(TokenErrors.InvalidRequest, "The password parameter is required.");
        }

        var user = await userStore.FindByUsernameAsync(tokenRequest.Username, ct);
        if (user is null)
        {
            return TokenError(TokenErrors.InvalidGrant, "Invalid resource owner credentials.");
        }

        if (string.IsNullOrWhiteSpace(user.PasswordHash) || !passwordHasher.VerifyHashedPassword(user, user.PasswordHash, tokenRequest.Password))
        {
            return TokenError(TokenErrors.InvalidGrant, "Invalid resource owner credentials.");
        }

        var requestedScopes = ParseScopes(tokenRequest.Scope);
        var grantedScopes = ValidateScopes(requestedScopes, client.AllowedScopes);

        if (requestedScopes.Count > 0 && grantedScopes.Count == 0)
        {
            return TokenError(TokenErrors.InvalidScope, "None of the requested scopes are allowed for this client.");
        }

        var accessTokenLifetime = TimeSpan.FromSeconds(client.AccessTokenLifetimeSeconds);
        var accessTokenExpiresAt = timeProvider.GetUtcNow().Add(accessTokenLifetime);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new("client_id", client.ClientId)
        };

        if (grantedScopes.Count > 0)
        {
            claims.Add(new Claim("scope", string.Join(" ", grantedScopes)));
        }

        var userClaims = await userStore.GetClaimsAsync(user.Id, ct);
        claims.AddRange(userClaims);

        var claimsContext = new ClaimsContext
        {
            SubjectId = user.Id,
            ClientId = client.ClientId,
            Scopes = grantedScopes,
            GrantType = GrantTypes.Password
        };

        var customClaims = await customClaimsProvider.GetAccessTokenClaimsAsync(claimsContext, ct);
        claims.AddRange(customClaims);

        var accessToken = await tokenService.CreateJwtAsync(
            options.Issuer!,
            options.Audience!,
            claims,
            accessTokenExpiresAt,
            ct);

        string? refreshTokenHandle = null;
        if (client.AllowOfflineAccess && grantedScopes.Contains(StandardScopes.OfflineAccess, StringComparer.Ordinal))
        {
            var now = timeProvider.GetUtcNow().UtcDateTime;
            var refreshTokenLifetime = TimeSpan.FromSeconds(client.RefreshTokenLifetimeSeconds);
            refreshTokenHandle = GenerateRefreshTokenHandle();

            var refreshToken = new CoreIdentRefreshToken
            {
                Handle = refreshTokenHandle,
                SubjectId = user.Id,
                ClientId = client.ClientId,
                FamilyId = Guid.NewGuid().ToString("N"),
                Scopes = grantedScopes,
                CreatedAt = now,
                ExpiresAt = now.Add(refreshTokenLifetime)
            };

            await refreshTokenStore.StoreAsync(refreshToken, ct);
        }

        logger.LogInformation("Issued tokens for subject {SubjectId} via password grant", user.Id);

        var elapsedMs = Stopwatch.GetElapsedTime(issuanceStart).TotalMilliseconds;
        metrics.TokenIssued("access_token", GrantTypes.Password, elapsedMs);

        if (!string.IsNullOrWhiteSpace(refreshTokenHandle))
        {
            metrics.TokenIssued("refresh_token", GrantTypes.Password, elapsedMs);
        }

        return Results.Ok(new TokenResponse
        {
            AccessToken = accessToken,
            TokenType = "Bearer",
            ExpiresIn = (int)accessTokenLifetime.TotalSeconds,
            RefreshToken = refreshTokenHandle,
            Scope = grantedScopes.Count > 0 ? string.Join(" ", grantedScopes) : null
        });
    }

    private static async Task<IResult> HandleAuthorizationCodeAsync(
        CoreIdentClient client,
        TokenRequest tokenRequest,
        ITokenService tokenService,
        IRefreshTokenStore refreshTokenStore,
        IAuthorizationCodeStore authorizationCodeStore,
        IUserStore userStore,
        ICustomClaimsProvider customClaimsProvider,
        ICoreIdentMetrics metrics,
        CoreIdentOptions options,
        TimeProvider timeProvider,
        ILogger logger,
        CancellationToken ct)
    {
        var issuanceStart = Stopwatch.GetTimestamp();

        if (string.IsNullOrWhiteSpace(tokenRequest.Code))
        {
            return TokenError(TokenErrors.InvalidRequest, "The code parameter is required.");
        }

        if (string.IsNullOrWhiteSpace(tokenRequest.RedirectUri))
        {
            return TokenError(TokenErrors.InvalidRequest, "The redirect_uri parameter is required.");
        }

        if (string.IsNullOrWhiteSpace(tokenRequest.CodeVerifier))
        {
            return TokenError(TokenErrors.InvalidRequest, "The code_verifier parameter is required.");
        }

        var code = await authorizationCodeStore.GetAsync(tokenRequest.Code, ct);
        if (code is null)
        {
            return TokenError(TokenErrors.InvalidGrant, "The authorization code is invalid or expired.");
        }

        var now = timeProvider.GetUtcNow().UtcDateTime;

        if (code.ExpiresAt <= now)
        {
            return TokenError(TokenErrors.InvalidGrant, "The authorization code is invalid or expired.");
        }

        if (code.ConsumedAt.HasValue)
        {
            return TokenError(TokenErrors.InvalidGrant, "The authorization code has already been used.");
        }

        if (!string.Equals(code.ClientId, client.ClientId, StringComparison.Ordinal))
        {
            return TokenError(TokenErrors.InvalidGrant, "The authorization code was not issued to this client.");
        }

        if (!string.Equals(code.RedirectUri, tokenRequest.RedirectUri, StringComparison.Ordinal))
        {
            return TokenError(TokenErrors.InvalidRequest, "The redirect_uri does not match the authorization code.");
        }

        if (client.RequirePkce)
        {
            if (!string.Equals(code.CodeChallengeMethod, "S256", StringComparison.Ordinal))
            {
                return TokenError(TokenErrors.InvalidGrant, "The authorization code PKCE method is not supported.");
            }

            if (!ValidatePkceS256(tokenRequest.CodeVerifier, code.CodeChallenge))
            {
                return TokenError(TokenErrors.InvalidGrant, "PKCE verification failed.");
            }
        }

        var consumed = await authorizationCodeStore.ConsumeAsync(tokenRequest.Code, ct);
        if (!consumed)
        {
            return TokenError(TokenErrors.InvalidGrant, "The authorization code is invalid or has already been used.");
        }

        var grantedScopes = code.Scopes.ToList();

        var accessTokenLifetime = TimeSpan.FromSeconds(client.AccessTokenLifetimeSeconds);
        var accessTokenExpiresAt = timeProvider.GetUtcNow().Add(accessTokenLifetime);

        var accessTokenClaims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, code.SubjectId),
            new("client_id", client.ClientId)
        };

        if (grantedScopes.Count > 0)
        {
            accessTokenClaims.Add(new Claim("scope", string.Join(" ", grantedScopes)));
        }

        var userClaims = await userStore.GetClaimsAsync(code.SubjectId, ct);
        accessTokenClaims.AddRange(userClaims);

        var claimsContext = new ClaimsContext
        {
            SubjectId = code.SubjectId,
            ClientId = client.ClientId,
            Scopes = grantedScopes,
            GrantType = GrantTypes.AuthorizationCode
        };

        var customAccessClaims = await customClaimsProvider.GetAccessTokenClaimsAsync(claimsContext, ct);
        accessTokenClaims.AddRange(customAccessClaims);

        var accessToken = await tokenService.CreateJwtAsync(
            options.Issuer!,
            options.Audience!,
            accessTokenClaims,
            accessTokenExpiresAt,
            ct);

        string? refreshTokenHandle = null;
        if (client.AllowOfflineAccess && grantedScopes.Contains(StandardScopes.OfflineAccess, StringComparer.Ordinal))
        {
            var refreshTokenLifetime = TimeSpan.FromSeconds(client.RefreshTokenLifetimeSeconds);
            refreshTokenHandle = GenerateRefreshTokenHandle();

            var refreshToken = new CoreIdentRefreshToken
            {
                Handle = refreshTokenHandle,
                SubjectId = code.SubjectId,
                ClientId = client.ClientId,
                FamilyId = Guid.NewGuid().ToString("N"),
                Scopes = grantedScopes,
                CreatedAt = now,
                ExpiresAt = now.Add(refreshTokenLifetime)
            };

            await refreshTokenStore.StoreAsync(refreshToken, ct);
        }

        string? idToken = null;
        if (grantedScopes.Contains(StandardScopes.OpenId, StringComparer.Ordinal))
        {
            var idTokenClaims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, code.SubjectId),
                new("client_id", client.ClientId)
            };

            if (!string.IsNullOrWhiteSpace(code.Nonce))
            {
                idTokenClaims.Add(new Claim("nonce", code.Nonce));
            }

            var customIdClaims = await customClaimsProvider.GetIdTokenClaimsAsync(claimsContext, ct);
            idTokenClaims.AddRange(customIdClaims);

            // audience for id_token is the client_id
            idToken = await tokenService.CreateJwtAsync(
                options.Issuer!,
                client.ClientId,
                idTokenClaims,
                expiresAt: accessTokenExpiresAt,
                ct);
        }

        logger.LogInformation("Issued tokens for subject {SubjectId} via authorization_code grant", code.SubjectId);

        var elapsedMs = Stopwatch.GetElapsedTime(issuanceStart).TotalMilliseconds;
        metrics.TokenIssued("access_token", GrantTypes.AuthorizationCode, elapsedMs);

        if (!string.IsNullOrWhiteSpace(refreshTokenHandle))
        {
            metrics.TokenIssued("refresh_token", GrantTypes.AuthorizationCode, elapsedMs);
        }

        if (!string.IsNullOrWhiteSpace(idToken))
        {
            metrics.TokenIssued("id_token", GrantTypes.AuthorizationCode, elapsedMs);
        }

        return Results.Ok(new TokenResponse
        {
            AccessToken = accessToken,
            TokenType = "Bearer",
            ExpiresIn = (int)accessTokenLifetime.TotalSeconds,
            RefreshToken = refreshTokenHandle,
            Scope = grantedScopes.Count > 0 ? string.Join(" ", grantedScopes) : null,
            IdToken = idToken
        });
    }

    private static async Task<IResult> HandleClientCredentialsAsync(
        CoreIdentClient client,
        TokenRequest tokenRequest,
        ITokenService tokenService,
        IRefreshTokenStore refreshTokenStore,
        ICustomClaimsProvider customClaimsProvider,
        ICoreIdentMetrics metrics,
        CoreIdentOptions options,
        TimeProvider timeProvider,
        ILogger logger,
        CancellationToken ct)
    {
        var issuanceStart = Stopwatch.GetTimestamp();

        var requestedScopes = ParseScopes(tokenRequest.Scope);
        var grantedScopes = ValidateScopes(requestedScopes, client.AllowedScopes);

        if (requestedScopes.Count > 0 && grantedScopes.Count == 0)
        {
            return TokenError(TokenErrors.InvalidScope, "None of the requested scopes are allowed for this client.");
        }

        var now = timeProvider.GetUtcNow();
        var accessTokenLifetime = TimeSpan.FromSeconds(client.AccessTokenLifetimeSeconds);
        var expiresAt = now.Add(accessTokenLifetime);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, client.ClientId),
            new("client_id", client.ClientId)
        };

        if (grantedScopes.Count > 0)
        {
            claims.Add(new Claim("scope", string.Join(" ", grantedScopes)));
        }

        var claimsContext = new ClaimsContext
        {
            SubjectId = null,
            ClientId = client.ClientId,
            Scopes = grantedScopes,
            GrantType = GrantTypes.ClientCredentials
        };

        var customClaims = await customClaimsProvider.GetAccessTokenClaimsAsync(claimsContext, ct);
        claims.AddRange(customClaims);

        var accessToken = await tokenService.CreateJwtAsync(
            options.Issuer!,
            options.Audience!,
            claims,
            expiresAt,
            ct);

        logger.LogInformation("Issued access token for client {ClientId} via client_credentials grant", client.ClientId);

        metrics.TokenIssued("access_token", GrantTypes.ClientCredentials, Stopwatch.GetElapsedTime(issuanceStart).TotalMilliseconds);

        return Results.Ok(new TokenResponse
        {
            AccessToken = accessToken,
            TokenType = "Bearer",
            ExpiresIn = (int)accessTokenLifetime.TotalSeconds,
            Scope = grantedScopes.Count > 0 ? string.Join(" ", grantedScopes) : null
        });
    }

    private static async Task<IResult> HandleRefreshTokenAsync(
        CoreIdentClient client,
        TokenRequest tokenRequest,
        ITokenService tokenService,
        IRefreshTokenStore refreshTokenStore,
        IUserStore userStore,
        ICustomClaimsProvider customClaimsProvider,
        ICoreIdentMetrics metrics,
        CoreIdentOptions options,
        TimeProvider timeProvider,
        ILogger logger,
        CancellationToken ct)
    {
        var issuanceStart = Stopwatch.GetTimestamp();

        if (string.IsNullOrWhiteSpace(tokenRequest.RefreshToken))
        {
            return TokenError(TokenErrors.InvalidRequest, "The refresh_token parameter is required.");
        }

        var storedToken = await refreshTokenStore.GetAsync(tokenRequest.RefreshToken, ct);
        if (storedToken is null)
        {
            logger.LogWarning("Refresh token not found");
            return TokenError(TokenErrors.InvalidGrant, "The refresh token is invalid or expired.");
        }

        if (storedToken.ClientId != client.ClientId)
        {
            logger.LogWarning("Refresh token client mismatch. Token client: {TokenClient}, Request client: {RequestClient}",
                storedToken.ClientId, client.ClientId);
            return TokenError(TokenErrors.InvalidGrant, "The refresh token was not issued to this client.");
        }

        var now = timeProvider.GetUtcNow().UtcDateTime;

        if (storedToken.ExpiresAt <= now)
        {
            logger.LogWarning("Refresh token expired for subject {SubjectId}", storedToken.SubjectId);
            return TokenError(TokenErrors.InvalidGrant, "The refresh token has expired.");
        }

        if (storedToken.IsRevoked)
        {
            logger.LogWarning("Attempt to use revoked refresh token for subject {SubjectId}", storedToken.SubjectId);
            return TokenError(TokenErrors.InvalidGrant, "The refresh token has been revoked.");
        }

        if (storedToken.ConsumedAt.HasValue)
        {
            logger.LogWarning("Refresh token reuse detected for subject {SubjectId}, family {FamilyId}. Revoking family.",
                storedToken.SubjectId, storedToken.FamilyId);

            if (!string.IsNullOrWhiteSpace(storedToken.FamilyId))
            {
                await refreshTokenStore.RevokeFamilyAsync(storedToken.FamilyId, ct);
            }

            return TokenError(TokenErrors.InvalidGrant, "The refresh token has already been used.");
        }

        var consumed = await refreshTokenStore.ConsumeAsync(tokenRequest.RefreshToken, ct);
        if (!consumed)
        {
            logger.LogWarning("Failed to consume refresh token for subject {SubjectId}", storedToken.SubjectId);
            return TokenError(TokenErrors.InvalidGrant, "The refresh token is invalid.");
        }

        var requestedScopes = ParseScopes(tokenRequest.Scope);
        List<string> grantedScopes;

        if (requestedScopes.Count > 0)
        {
            grantedScopes = requestedScopes.Where(s => storedToken.Scopes.Contains(s)).ToList();
            if (grantedScopes.Count == 0)
            {
                return TokenError(TokenErrors.InvalidScope, "The requested scope exceeds the scope granted by the resource owner.");
            }
        }
        else
        {
            grantedScopes = storedToken.Scopes.ToList();
        }

        var accessTokenLifetime = TimeSpan.FromSeconds(client.AccessTokenLifetimeSeconds);
        var accessTokenExpiresAt = timeProvider.GetUtcNow().Add(accessTokenLifetime);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, storedToken.SubjectId),
            new("client_id", client.ClientId)
        };

        if (grantedScopes.Count > 0)
        {
            claims.Add(new Claim("scope", string.Join(" ", grantedScopes)));
        }

        var userClaims = await userStore.GetClaimsAsync(storedToken.SubjectId, ct);
        claims.AddRange(userClaims);

        var claimsContext = new ClaimsContext
        {
            SubjectId = storedToken.SubjectId,
            ClientId = client.ClientId,
            Scopes = grantedScopes,
            GrantType = GrantTypes.RefreshToken
        };

        var customClaims = await customClaimsProvider.GetAccessTokenClaimsAsync(claimsContext, ct);
        claims.AddRange(customClaims);

        var accessToken = await tokenService.CreateJwtAsync(
            options.Issuer!,
            options.Audience!,
            claims,
            accessTokenExpiresAt,
            ct);

        var refreshTokenLifetime = TimeSpan.FromSeconds(client.RefreshTokenLifetimeSeconds);
        var newRefreshToken = new CoreIdentRefreshToken
        {
            Handle = GenerateRefreshTokenHandle(),
            SubjectId = storedToken.SubjectId,
            ClientId = client.ClientId,
            FamilyId = storedToken.FamilyId ?? Guid.NewGuid().ToString("N"),
            Scopes = grantedScopes,
            CreatedAt = now,
            ExpiresAt = now.Add(refreshTokenLifetime)
        };

        await refreshTokenStore.StoreAsync(newRefreshToken, ct);

        logger.LogInformation("Issued new tokens for subject {SubjectId} via refresh_token grant", storedToken.SubjectId);

        var elapsedMs = Stopwatch.GetElapsedTime(issuanceStart).TotalMilliseconds;
        metrics.TokenIssued("access_token", GrantTypes.RefreshToken, elapsedMs);
        metrics.TokenIssued("refresh_token", GrantTypes.RefreshToken, elapsedMs);

        return Results.Ok(new TokenResponse
        {
            AccessToken = accessToken,
            TokenType = "Bearer",
            ExpiresIn = (int)accessTokenLifetime.TotalSeconds,
            RefreshToken = newRefreshToken.Handle,
            Scope = grantedScopes.Count > 0 ? string.Join(" ", grantedScopes) : null
        });
    }

    private static TokenRequest ParseTokenRequest(IFormCollection form)
    {
        return new TokenRequest
        {
            GrantType = form["grant_type"].ToString(),
            ClientId = form["client_id"].ToString(),
            ClientSecret = form["client_secret"].ToString(),
            Scope = form["scope"].ToString(),
            RefreshToken = form["refresh_token"].ToString(),
            Code = form["code"].ToString(),
            RedirectUri = form["redirect_uri"].ToString(),
            CodeVerifier = form["code_verifier"].ToString(),
            Username = form["username"].ToString(),
            Password = form["password"].ToString()
        };
    }

    private static (string? ClientId, string? ClientSecret) ExtractClientCredentials(HttpRequest request, TokenRequest tokenRequest)
    {
        var authorization = request.Headers.Authorization.ToString();

        if (!string.IsNullOrWhiteSpace(authorization) && authorization.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var encoded = authorization["Basic ".Length..].Trim();
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                var colonIndex = decoded.IndexOf(':');

                if (colonIndex > 0)
                {
                    var clientId = Uri.UnescapeDataString(decoded[..colonIndex]);
                    var clientSecret = Uri.UnescapeDataString(decoded[(colonIndex + 1)..]);
                    return (clientId, clientSecret);
                }
            }
            catch
            {
            }
        }

        return (tokenRequest.ClientId, tokenRequest.ClientSecret);
    }

    private static List<string> ParseScopes(string? scope)
    {
        if (string.IsNullOrWhiteSpace(scope))
        {
            return [];
        }

        return scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
    }

    private static List<string> ValidateScopes(List<string> requestedScopes, ICollection<string> allowedScopes)
    {
        if (requestedScopes.Count == 0)
        {
            return allowedScopes.ToList();
        }

        return requestedScopes.Where(s => allowedScopes.Contains(s)).ToList();
    }

    private static string GenerateRefreshTokenHandle()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    }

    private static bool ValidatePkceS256(string codeVerifier, string expectedCodeChallenge)
    {
        try
        {
            var bytes = Encoding.ASCII.GetBytes(codeVerifier);
            var hashed = SHA256.HashData(bytes);
            var computed = Base64UrlEncode(hashed);
            return string.Equals(computed, expectedCodeChallenge, StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        var s = Convert.ToBase64String(bytes);
        s = s.TrimEnd('=');
        s = s.Replace('+', '-');
        s = s.Replace('/', '_');
        return s;
    }

    private static IResult TokenError(string error, string description, int statusCode = StatusCodes.Status400BadRequest)
    {
        return Results.Json(new TokenErrorResponse
        {
            Error = error,
            ErrorDescription = description
        }, statusCode: statusCode);
    }
}
