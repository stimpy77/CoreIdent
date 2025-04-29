using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models.Responses;
using CoreIdent.Core.Stores;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;

namespace CoreIdent.Core.Extensions
{
    /// <summary>
    /// Extension methods for mapping token management endpoints.
    /// </summary>
    public static class TokenManagementEndpointsExtensions
    {
        /// <summary>
        /// Maps token management endpoints including introspection and revocation.
        /// </summary>
        /// <param name="endpoints">The <see cref="IEndpointRouteBuilder"/> to add the routes to.</param>
        /// <param name="routeOptions">The <see cref="CoreIdentRouteOptions"/> to use for configuring the routes.</param>
        public static void MapTokenManagementEndpoints(
            this IEndpointRouteBuilder endpoints,
            CoreIdentRouteOptions routeOptions)
        {
            ArgumentNullException.ThrowIfNull(endpoints);
            ArgumentNullException.ThrowIfNull(routeOptions);

            var logger = endpoints.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("TokenManagementEndpoints");
            logger.LogInformation("Registering token management endpoints with base path: {BasePath}", routeOptions.BasePath);

            // Construct dynamic paths based on TokenPath
            var introspectPath = $"{routeOptions.TokenPath.TrimEnd('/')}/introspect";
            var revokePath = $"{routeOptions.TokenPath.TrimEnd('/')}/revoke";

            // Route for token introspection (RFC 7662)
            logger.LogInformation("Mapping token introspection endpoint: {Path}", routeOptions.Combine(introspectPath));
            endpoints.MapPost(introspectPath, async (
                HttpRequest request,
                HttpContext httpContext,
                IRefreshTokenStore refreshTokenStore,
                ILoggerFactory loggerFactory,
                IServiceProvider serviceProvider,
                CancellationToken cancellationToken) =>
            {
                var logger = loggerFactory.CreateLogger("TokenIntrospectionEndpoint");

                try
                {
                    // Read form data
                    var form = await request.ReadFormAsync(cancellationToken);
                    var token = form["token"].ToString();
                    var tokenTypeHint = form["token_type_hint"].ToString();

                    // Basic validation
                    if (string.IsNullOrEmpty(token))
                    {
                        logger.LogWarning("Token introspection request missing required 'token' parameter");
                        return Results.BadRequest(new ErrorResponse
                        {
                            Error = "invalid_request",
                            ErrorDescription = "The token parameter is required"
                        });
                    }

                    // If token_type_hint is not provided or is "refresh_token", check refresh token store
                    if (string.IsNullOrEmpty(tokenTypeHint) || tokenTypeHint == "refresh_token")
                    {
                        var refreshToken = await refreshTokenStore.GetRefreshTokenAsync(token, cancellationToken);
                        if (refreshToken != null)
                        {
                            var isActive = refreshToken.ConsumedTime == null &&
                                          refreshToken.ExpirationTime > DateTime.UtcNow;

                            return Results.Ok(new
                            {
                                active = isActive,
                                exp = new DateTimeOffset(refreshToken.ExpirationTime).ToUnixTimeSeconds(),
                                client_id = refreshToken.ClientId,
                                sub = refreshToken.SubjectId
                            });
                        }
                        else
                        {
                            // If token not found, return inactive
                            return Results.Ok(new { active = false });
                        }
                    }

                    // If token_type_hint is "access_token" or we didn't find a refresh token, check access tokens
                    // Note: This would require access to the token validation service
                    // For now, we'll return inactive since we don't store access tokens
                    return Results.Ok(new { active = false });
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error processing token introspection request");
                    return Results.BadRequest(new ErrorResponse
                    {
                        Error = "server_error",
                        ErrorDescription = "An error occurred processing the request"
                    });
                }
            });

            // Route for token revocation (RFC 7009)
            logger.LogInformation("Mapping token revocation endpoint: {Path}", routeOptions.Combine(revokePath));
            endpoints.MapPost(revokePath, async (
                HttpRequest request,
                HttpContext httpContext,
                IRefreshTokenStore refreshTokenStore,
                ILoggerFactory loggerFactory,
                CancellationToken cancellationToken) =>
            {
                var logger = loggerFactory.CreateLogger("TokenRevocationEndpoint");

                try
                {
                    // Read form data
                    var form = await request.ReadFormAsync(cancellationToken);
                    var token = form["token"].ToString();
                    var tokenTypeHint = form["token_type_hint"].ToString();

                    // Basic validation
                    if (string.IsNullOrEmpty(token))
                    {
                        logger.LogWarning("Token revocation request missing required 'token' parameter");
                        return Results.BadRequest(new ErrorResponse
                        {
                            Error = "invalid_request",
                            ErrorDescription = "The token parameter is required"
                        });
                    }

                    // If token_type_hint is not provided or is "refresh_token", revoke refresh token
                    if (string.IsNullOrEmpty(tokenTypeHint) || tokenTypeHint == "refresh_token")
                    {
                        var refreshToken = await refreshTokenStore.GetRefreshTokenAsync(token, cancellationToken);
                        if (refreshToken != null)
                        {
                            // Remove the token to revoke it (do not re-store)
                            await refreshTokenStore.RemoveRefreshTokenAsync(token, cancellationToken);
                            logger.LogInformation("Successfully revoked refresh token");
                            return Results.Ok();
                        }
                    }

                    // Even if we didn't find the token, the spec requires us to return OK
                    // RFC 7009 Section 2.2: Regardless of whether the token exists, the server MUST respond with HTTP status code 200
                    return Results.Ok();
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error processing token revocation request");
                    // RFC 7009 allows for error responses
                    return Results.BadRequest(new ErrorResponse
                    {
                        Error = "server_error",
                        ErrorDescription = "An error occurred processing the request"
                    });
                }
            });
        }
    }
}
