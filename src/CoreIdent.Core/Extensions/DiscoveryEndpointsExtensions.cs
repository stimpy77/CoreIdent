using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models.Responses; // Add if ErrorResponse is used, though not directly here
using CoreIdent.Core.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc; // For [FromServices]
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection; // For GetRequiredService
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Text.Json; // For Results.Json if needed, though Minimal APIs handle it

namespace CoreIdent.Core.Extensions
{
    /// <summary>
    /// Extension methods for mapping OIDC Discovery and JWKS endpoints.
    /// </summary>
    public static class DiscoveryEndpointsExtensions
    {
        /// <summary>
        /// Maps the OIDC Discovery (/.well-known/openid-configuration) and
        /// JWKS (/.well-known/jwks.json) endpoints.
        /// </summary>
        /// <param name="endpoints">The <see cref="IEndpointRouteBuilder"/> to add the routes to.</param>
        /// <param name="routeOptions">The CoreIdent route options.</param>
        public static void MapDiscoveryEndpoints(this IEndpointRouteBuilder endpoints, CoreIdentRouteOptions routeOptions)
        {
            ArgumentNullException.ThrowIfNull(endpoints);
            ArgumentNullException.ThrowIfNull(routeOptions);

            // Endpoint: GET /.well-known/openid-configuration
            endpoints.MapGet(routeOptions.DiscoveryPath, (
                IOptions<CoreIdentOptions> options,
                ILoggerFactory loggerFactory,
                LinkGenerator links,
                HttpContext httpContext,
                [FromServices] ITokenService tokenService) =>
            {
                 var logger = loggerFactory.CreateLogger("DiscoveryEndpoint");
                try
                {
                    logger.LogInformation("Discovery endpoint hit: {Path}", routeOptions.DiscoveryPath);
                    var opts = options.Value;
                    // Ensure Issuer is correctly determined (scheme + host)
                    var issuer = opts.Issuer ?? $"{httpContext.Request.Scheme}://{httpContext.Request.Host}";
                    var baseUrl = issuer.TrimEnd('/'); // Use the determined issuer

                    // Construct URIs relative to the issuer
                    var jwksUri = $"{baseUrl}{routeOptions.JwksPath}"; // Use configured path
                    var authorizationEndpoint = $"{baseUrl}{routeOptions.Combine(routeOptions.AuthorizePath)}"; // Combine base path
                    var tokenEndpoint = $"{baseUrl}{routeOptions.Combine(routeOptions.TokenPath)}";
                    //var userinfoEndpoint = $"{baseUrl}/auth/userinfo"; // TODO: Define UserInfoPath in options?

                    var discovery = new
                    {
                        issuer = issuer,
                        jwks_uri = jwksUri,
                        authorization_endpoint = authorizationEndpoint,
                        token_endpoint = tokenEndpoint,
                        //userinfo_endpoint = userinfoEndpoint,
                        // TODO: Make these dynamically configurable or based on registered features
                        response_types_supported = new[] { "code" }, // Only support code for now
                        subject_types_supported = new[] { "public" },
                        id_token_signing_alg_values_supported = new[] { "HS256" }, // Hardcode HS256 for now
                        scopes_supported = new[] { "openid", "profile", "email", "offline_access" }, // Example scopes
                        token_endpoint_auth_methods_supported = new[] { "client_secret_post", "client_secret_basic" }, // Configurable?
                        grant_types_supported = new[] { "authorization_code", "client_credentials", "refresh_token" } // Configurable?
                    };
                    return Results.Json(discovery, new JsonSerializerOptions { WriteIndented = true }); // Pretty print for readability
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Discovery endpoint error");
                    return Results.Problem("An error occurred generating discovery document.", statusCode: StatusCodes.Status500InternalServerError);
                }
            })
            .WithName("OidcDiscovery")
            .WithTags("CoreIdent", "Discovery")
            .Produces<object>(StatusCodes.Status200OK) // Be more specific? Produces<DiscoveryDocument>(...)
            .Produces(StatusCodes.Status500InternalServerError)
            .WithSummary("Provides OpenID Connect discovery information.");

            // Endpoint: GET /.well-known/jwks.json
            endpoints.MapGet(routeOptions.JwksPath, (
                 // Inject concrete JwtTokenService, as ITokenService lacks GetSecurityKey
                 [FromServices] JwtTokenService tokenService,
                 ILoggerFactory loggerFactory) =>
            {
                 var logger = loggerFactory.CreateLogger("JwksEndpoint");
                try
                {
                    logger.LogInformation("JWKS endpoint hit: {Path}", routeOptions.JwksPath);

                    // Get the security key and construct JWK based on its type
                    var securityKey = tokenService.GetSecurityKey(); // Now valid on concrete type

                    object? jwk = null;
                    if (securityKey is Microsoft.IdentityModel.Tokens.SymmetricSecurityKey symmetricKey)
                    {
                        jwk = new
                        {
                            kty = "oct",
                            k = Convert.ToBase64String(symmetricKey.Key).Replace("=", ""),
                            alg = "HS256", // Hardcode HS256 as it matches key type
                            use = "sig",
                            kid = symmetricKey.KeyId ?? "coreident-hs256-default"
                        };
                    }
                    // TODO: Add support for AsymmetricSecurityKey (RSA, ECDsa) if needed later
                    // else if (securityKey is Microsoft.IdentityModel.Tokens.RsaSecurityKey rsaKey) { ... }
                    // else if (securityKey is Microsoft.IdentityModel.Tokens.ECDsaSecurityKey ecdsaKey) { ... }

                    if (jwk == null)
                    {
                         logger.LogError("Failed to generate JWK from TokenService key type: {KeyType}", securityKey?.GetType().Name ?? "null");
                         return Results.Problem("Signing key not configured or incompatible.", statusCode: StatusCodes.Status500InternalServerError);
                    }

                    var jwks = new { keys = new[] { jwk } };
                    return Results.Json(jwks, new JsonSerializerOptions { WriteIndented = true });
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "JWKS endpoint error");
                    return Results.Problem("An error occurred generating the JWKS document.", statusCode: StatusCodes.Status500InternalServerError);
                }
            })
            .WithName("OidcJwks")
            .WithTags("CoreIdent", "Discovery")
            .Produces<object>(StatusCodes.Status200OK) // Be more specific? Produces<JsonWebKeySet>(...)
            .Produces(StatusCodes.Status500InternalServerError)
            .WithSummary("Provides the JSON Web Key Set (JWKS) for token validation.");
        }
    }
} 