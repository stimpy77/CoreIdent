using System.IdentityModel.Tokens.Jwt;
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
        return endpoints.MapCoreIdentTokenManagementEndpoints("/auth/revoke");
    }

    public static IEndpointRouteBuilder MapCoreIdentTokenManagementEndpoints(this IEndpointRouteBuilder endpoints, string revokePath)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(revokePath);

        endpoints.MapPost(revokePath, async (
            HttpRequest request,
            ISigningKeyProvider signingKeyProvider,
            ITokenRevocationStore tokenRevocationStore,
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

            var authorization = request.Headers.Authorization.ToString();
            var clientId = form["client_id"].ToString();
            var clientSecret = form["client_secret"].ToString();

            if (string.IsNullOrWhiteSpace(authorization) && (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret)))
            {
                return Results.Json(new { error = "invalid_client", error_description = "Client authentication is required." }, statusCode: StatusCodes.Status401Unauthorized);
            }

            try
            {
                if (string.Equals(tokenTypeHint, "refresh_token", StringComparison.Ordinal))
                {
                    var refreshTokenStore = services.GetService<IRefreshTokenStore>();
                    if (refreshTokenStore is not null)
                    {
                        _ = await refreshTokenStore.RevokeAsync(token, ct);
                    }

                    return Results.Ok();
                }

                if (string.Equals(tokenTypeHint, "access_token", StringComparison.Ordinal) || LooksLikeJwt(token))
                {
                    if (await TryGetValidatedJwtJtiAndExpiryAsync(token, signingKeyProvider, ct) is { } validated)
                    {
                        await tokenRevocationStore.RevokeTokenAsync(validated.Jti, tokenType: "access_token", expiry: validated.ExpiresAtUtc, ct);
                    }

                    return Results.Ok();
                }

                var fallbackRefreshTokenStore = services.GetService<IRefreshTokenStore>();
                if (fallbackRefreshTokenStore is not null)
                {
                    _ = await fallbackRefreshTokenStore.RevokeAsync(token, ct);
                }

                return Results.Ok();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error processing token revocation request.");
                return Results.Json(new { error = "server_error", error_description = "An error occurred processing the request." }, statusCode: StatusCodes.Status500InternalServerError);
            }
        });

        return endpoints;
    }

    private static bool LooksLikeJwt(string token) => token.Count(c => c == '.') == 2;

    private static async Task<ValidatedJwt?> TryGetValidatedJwtJtiAndExpiryAsync(
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

            return new ValidatedJwt(jti, expiresAtUtc);
        }
        catch
        {
            return null;
        }
    }

    private sealed record ValidatedJwt(string Jti, DateTime ExpiresAtUtc);
}
