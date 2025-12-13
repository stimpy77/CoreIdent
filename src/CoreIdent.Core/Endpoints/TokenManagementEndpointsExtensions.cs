using System.IdentityModel.Tokens.Jwt;
using System.Text;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Core.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace CoreIdent.Core.Endpoints;

public static class TokenManagementEndpointsExtensions
{
    public static IEndpointRouteBuilder MapCoreIdentTokenManagementEndpoints(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapCoreIdentTokenManagementEndpoints("/auth/revoke", "/auth/introspect");
    }

    public static IEndpointRouteBuilder MapCoreIdentTokenManagementEndpoints(this IEndpointRouteBuilder endpoints, string revokePath, string introspectPath = "/auth/introspect")
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(revokePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(introspectPath);

        endpoints.MapPost(revokePath, async (
            HttpRequest request,
            ISigningKeyProvider signingKeyProvider,
            ITokenRevocationStore tokenRevocationStore,
            IClientStore clientStore,
            ILoggerFactory loggerFactory,
            IServiceProvider services,
            CancellationToken ct) =>
        {
            var logger = loggerFactory.CreateLogger("CoreIdent.TokenRevocation");

            if (!request.HasFormContentType)
            {
                return Results.BadRequest(new { error = "invalid_request", error_description = "Form content type is required." });
            }

            var form = await request.ReadFormAsync(ct);

            var token = form["token"].ToString();
            var tokenTypeHint = form["token_type_hint"].ToString();

            if (string.IsNullOrWhiteSpace(token))
            {
                return Results.BadRequest(new { error = "invalid_request", error_description = "The token parameter is required." });
            }

            var (clientId, clientSecret) = ExtractClientCredentials(request, form);

            if (string.IsNullOrWhiteSpace(clientId))
            {
                return Results.Json(new { error = "invalid_client", error_description = "Client authentication is required." }, statusCode: StatusCodes.Status401Unauthorized);
            }

            var client = await clientStore.FindByClientIdAsync(clientId, ct);
            if (client is null || !client.Enabled)
            {
                logger.LogWarning("Revocation request for unknown or disabled client: {ClientId}", clientId);
                return Results.Json(new { error = "invalid_client", error_description = "Client authentication failed." }, statusCode: StatusCodes.Status401Unauthorized);
            }

            if (client.ClientType == ClientType.Confidential)
            {
                if (string.IsNullOrWhiteSpace(clientSecret))
                {
                    return Results.Json(new { error = "invalid_client", error_description = "Client secret is required for confidential clients." }, statusCode: StatusCodes.Status401Unauthorized);
                }

                var secretValid = await clientStore.ValidateClientSecretAsync(clientId, clientSecret, ct);
                if (!secretValid)
                {
                    logger.LogWarning("Invalid client secret for revocation request from client: {ClientId}", clientId);
                    return Results.Json(new { error = "invalid_client", error_description = "Client authentication failed." }, statusCode: StatusCodes.Status401Unauthorized);
                }
            }

            try
            {
                if (string.Equals(tokenTypeHint, "refresh_token", StringComparison.Ordinal))
                {
                    await TryRevokeRefreshTokenAsync(token, clientId, services, logger, ct);
                    return Results.Ok();
                }

                if (string.Equals(tokenTypeHint, "access_token", StringComparison.Ordinal) || LooksLikeJwt(token))
                {
                    if (await TryGetValidatedJwtAsync(token, signingKeyProvider, ct) is { } validated)
                    {
                        var tokenClientId = validated.ClientId;
                        if (!string.IsNullOrWhiteSpace(tokenClientId) && tokenClientId != clientId)
                        {
                            logger.LogWarning("Client {ClientId} attempted to revoke token belonging to {TokenClientId}", clientId, tokenClientId);
                            return Results.Ok();
                        }

                        await tokenRevocationStore.RevokeTokenAsync(validated.Jti, tokenType: "access_token", expiry: validated.ExpiresAtUtc, ct);
                    }

                    return Results.Ok();
                }

                await TryRevokeRefreshTokenAsync(token, clientId, services, logger, ct);
                return Results.Ok();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error processing token revocation request.");
                return Results.Json(new { error = "server_error", error_description = "An error occurred processing the request." }, statusCode: StatusCodes.Status500InternalServerError);
            }
        });

        // Introspection endpoint (RFC 7662)
        endpoints.MapPost(introspectPath, async (
            HttpRequest request,
            ISigningKeyProvider signingKeyProvider,
            ITokenRevocationStore tokenRevocationStore,
            IClientStore clientStore,
            ILoggerFactory loggerFactory,
            IServiceProvider services,
            TimeProvider timeProvider,
            CancellationToken ct) =>
        {
            var logger = loggerFactory.CreateLogger("CoreIdent.TokenIntrospection");

            if (!request.HasFormContentType)
            {
                return Results.BadRequest(new { error = "invalid_request", error_description = "Form content type is required." });
            }

            var form = await request.ReadFormAsync(ct);

            var token = form["token"].ToString();
            var tokenTypeHint = form["token_type_hint"].ToString();

            if (string.IsNullOrWhiteSpace(token))
            {
                return Results.BadRequest(new { error = "invalid_request", error_description = "The token parameter is required." });
            }

            var (clientId, clientSecret) = ExtractClientCredentials(request, form);

            if (string.IsNullOrWhiteSpace(clientId))
            {
                return Results.Json(new { error = "invalid_client", error_description = "Client authentication is required." }, statusCode: StatusCodes.Status401Unauthorized);
            }

            var client = await clientStore.FindByClientIdAsync(clientId, ct);
            if (client is null || !client.Enabled)
            {
                logger.LogWarning("Introspection request for unknown or disabled client: {ClientId}", clientId);
                return Results.Json(new { error = "invalid_client", error_description = "Client authentication failed." }, statusCode: StatusCodes.Status401Unauthorized);
            }

            if (client.ClientType == ClientType.Confidential)
            {
                if (string.IsNullOrWhiteSpace(clientSecret))
                {
                    return Results.Json(new { error = "invalid_client", error_description = "Client secret is required for confidential clients." }, statusCode: StatusCodes.Status401Unauthorized);
                }

                var secretValid = await clientStore.ValidateClientSecretAsync(clientId, clientSecret, ct);
                if (!secretValid)
                {
                    logger.LogWarning("Invalid client secret for introspection request from client: {ClientId}", clientId);
                    return Results.Json(new { error = "invalid_client", error_description = "Client authentication failed." }, statusCode: StatusCodes.Status401Unauthorized);
                }
            }

            var now = timeProvider.GetUtcNow().UtcDateTime;

            // Check refresh token first if hinted
            if (string.Equals(tokenTypeHint, "refresh_token", StringComparison.Ordinal))
            {
                var refreshResult = await IntrospectRefreshTokenAsync(token, services, now, ct);
                if (refreshResult is not null)
                {
                    return Results.Json(refreshResult);
                }
                // Fall through to check as access token
            }

            // Try as access token (JWT)
            if (string.Equals(tokenTypeHint, "access_token", StringComparison.Ordinal) || LooksLikeJwt(token))
            {
                var accessResult = await IntrospectAccessTokenAsync(token, signingKeyProvider, tokenRevocationStore, now, ct);
                return Results.Json(accessResult);
            }

            // No hint and doesn't look like JWT - try refresh token
            var fallbackResult = await IntrospectRefreshTokenAsync(token, services, now, ct);
            if (fallbackResult is not null)
            {
                return Results.Json(fallbackResult);
            }

            // Unknown token
            return Results.Json(new TokenIntrospectionResponse { Active = false });
        });

        return endpoints;
    }

    private static async Task<TokenIntrospectionResponse?> IntrospectRefreshTokenAsync(
        string token,
        IServiceProvider services,
        DateTime now,
        CancellationToken ct)
    {
        var refreshTokenStore = services.GetService<IRefreshTokenStore>();
        if (refreshTokenStore is null)
        {
            return null;
        }

        var storedToken = await refreshTokenStore.GetAsync(token, ct);
        if (storedToken is null)
        {
            return null;
        }

        // Check if active
        var isActive = !storedToken.IsRevoked
            && !storedToken.ConsumedAt.HasValue
            && storedToken.ExpiresAt > now;

        if (!isActive)
        {
            return new TokenIntrospectionResponse { Active = false };
        }

        return new TokenIntrospectionResponse
        {
            Active = true,
            Scope = string.Join(" ", storedToken.Scopes),
            ClientId = storedToken.ClientId,
            TokenType = "refresh_token",
            Exp = new DateTimeOffset(storedToken.ExpiresAt, TimeSpan.Zero).ToUnixTimeSeconds(),
            Iat = new DateTimeOffset(storedToken.CreatedAt, TimeSpan.Zero).ToUnixTimeSeconds(),
            Sub = storedToken.SubjectId
        };
    }

    private static async Task<TokenIntrospectionResponse> IntrospectAccessTokenAsync(
        string token,
        ISigningKeyProvider signingKeyProvider,
        ITokenRevocationStore tokenRevocationStore,
        DateTime now,
        CancellationToken ct)
    {
        var validated = await TryGetValidatedJwtForIntrospectionAsync(token, signingKeyProvider, ct);
        if (validated is null)
        {
            return new TokenIntrospectionResponse { Active = false };
        }

        // Check expiry
        if (validated.ExpiresAtUtc <= now)
        {
            return new TokenIntrospectionResponse { Active = false };
        }

        // Check revocation
        if (!string.IsNullOrWhiteSpace(validated.Jti))
        {
            var isRevoked = await tokenRevocationStore.IsRevokedAsync(validated.Jti, ct);
            if (isRevoked)
            {
                return new TokenIntrospectionResponse { Active = false };
            }
        }

        return new TokenIntrospectionResponse
        {
            Active = true,
            Scope = validated.Scope,
            ClientId = validated.ClientId,
            TokenType = "Bearer",
            Exp = new DateTimeOffset(validated.ExpiresAtUtc, TimeSpan.Zero).ToUnixTimeSeconds(),
            Iat = validated.IssuedAtUnixTimeSeconds,
            Sub = validated.Subject,
            Aud = validated.Audience,
            Iss = validated.Issuer,
            Jti = validated.Jti
        };
    }

    private static async Task<IntrospectedJwt?> TryGetValidatedJwtForIntrospectionAsync(
        string token,
        ISigningKeyProvider signingKeyProvider,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return null;
        }

        try
        {
            var keys = (await signingKeyProvider.GetValidationKeysAsync(ct)).Select(k => k.Key).ToList();
            if (keys.Count == 0)
            {
                return null;
            }

            var handler = new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler();
            var result = await handler.ValidateTokenAsync(token, new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                RequireSignedTokens = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = keys
            });

            if (!result.IsValid)
            {
                return null;
            }

            var claims = result.ClaimsIdentity;
            var securityToken = result.SecurityToken;

            long? issuedAt = null;
            var iatValue = claims?.FindFirst(JwtRegisteredClaimNames.Iat)?.Value;
            if (!string.IsNullOrWhiteSpace(iatValue) && long.TryParse(iatValue, out var parsedIat))
            {
                issuedAt = parsedIat;
            }

            var aud = claims?.FindFirst(JwtRegisteredClaimNames.Aud)?.Value;
            if (string.IsNullOrWhiteSpace(aud) && securityToken is not null)
            {
                aud = securityToken switch
                {
                    Microsoft.IdentityModel.JsonWebTokens.JsonWebToken jwt => jwt.Audiences.FirstOrDefault(),
                    JwtSecurityToken jwt => jwt.Audiences.FirstOrDefault(),
                    _ => null
                };
            }

            return new IntrospectedJwt(
                Jti: claims?.FindFirst(JwtRegisteredClaimNames.Jti)?.Value,
                Subject: claims?.FindFirst(JwtRegisteredClaimNames.Sub)?.Value,
                ClientId: claims?.FindFirst("client_id")?.Value,
                Scope: claims?.FindFirst("scope")?.Value,
                Issuer: securityToken?.Issuer,
                Audience: aud,
                ExpiresAtUtc: securityToken?.ValidTo.ToUniversalTime() ?? DateTime.MinValue,
                IssuedAtUnixTimeSeconds: issuedAt
            );
        }
        catch
        {
            return null;
        }
    }

    private sealed record IntrospectedJwt(
        string? Jti,
        string? Subject,
        string? ClientId,
        string? Scope,
        string? Issuer,
        string? Audience,
        DateTime ExpiresAtUtc,
        long? IssuedAtUnixTimeSeconds);

    private static async Task TryRevokeRefreshTokenAsync(
        string token,
        string clientId,
        IServiceProvider services,
        ILogger logger,
        CancellationToken ct)
    {
        var refreshTokenStore = services.GetService<IRefreshTokenStore>();
        if (refreshTokenStore is null)
        {
            return;
        }

        var storedToken = await refreshTokenStore.GetAsync(token, ct);
        if (storedToken is null)
        {
            return;
        }

        if (storedToken.ClientId != clientId)
        {
            logger.LogWarning("Client {ClientId} attempted to revoke refresh token belonging to {TokenClientId}", clientId, storedToken.ClientId);
            return;
        }

        await refreshTokenStore.RevokeAsync(token, ct);
    }

    private static (string? ClientId, string? ClientSecret) ExtractClientCredentials(HttpRequest request, IFormCollection form)
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

        return (form["client_id"].ToString(), form["client_secret"].ToString());
    }

    private static bool LooksLikeJwt(string token) => token.Count(c => c == '.') == 2;

    private static async Task<ValidatedJwt?> TryGetValidatedJwtAsync(
        string token,
        ISigningKeyProvider signingKeyProvider,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return null;
        }

        try
        {
            var keys = (await signingKeyProvider.GetValidationKeysAsync(ct)).Select(k => k.Key).ToList();
            if (keys.Count == 0)
            {
                return null;
            }

            var handler = new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler();
            var result = await handler.ValidateTokenAsync(token, new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                RequireSignedTokens = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = keys
            });

            if (!result.IsValid)
            {
                return null;
            }

            var jti = result.ClaimsIdentity?.FindFirst(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti)?.Value;
            if (string.IsNullOrWhiteSpace(jti))
            {
                return null;
            }

            if (result.SecurityToken is null)
            {
                return null;
            }

            var expiresAtUtc = result.SecurityToken.ValidTo.ToUniversalTime();
            if (expiresAtUtc == DateTime.MinValue)
            {
                return null;
            }

            var clientId = result.ClaimsIdentity?.FindFirst("client_id")?.Value;

            return new ValidatedJwt(jti, expiresAtUtc, clientId);
        }
        catch
        {
            return null;
        }
    }

    private sealed record ValidatedJwt(string Jti, DateTime ExpiresAtUtc, string? ClientId);
}
