using CoreIdent.Core.Configuration;
using CoreIdent.Core.Extensions;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Core.Services.Realms;
using CoreIdent.Core.Stores;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace CoreIdent.Core.Endpoints;

/// <summary>
/// Endpoint mapping for discovery and metadata endpoints.
/// </summary>
public static class DiscoveryEndpointsExtensions
{
    /// <summary>
    /// Maps the OpenID Connect discovery document endpoint.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="coreOptions">CoreIdent options.</param>
    /// <param name="routeOptions">Route options.</param>
    /// <returns>The endpoint route builder.</returns>
    public static IEndpointRouteBuilder MapCoreIdentOpenIdConfigurationEndpoint(
        this IEndpointRouteBuilder endpoints,
        CoreIdentOptions coreOptions,
        CoreIdentRouteOptions routeOptions)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(coreOptions);
        ArgumentNullException.ThrowIfNull(routeOptions);

        var discoveryPath = routeOptions.GetDiscoveryPath(coreOptions);

        endpoints.MapGet(discoveryPath, async (
            HttpRequest request,
            ICoreIdentRealmContext realmContext,
            ICoreIdentIssuerAudienceProvider issuerAudienceProvider,
            IRealmSigningKeyProviderResolver signingKeyProviderResolver,
            IRealmScopeStore scopeStore,
            IEnumerable<EndpointDataSource> endpointDataSources,
            ILoggerFactory loggerFactory,
            CancellationToken ct) =>
        {
            var logger = loggerFactory.CreateLogger("CoreIdent.OpenIdConfiguration");
            using var _ = CoreIdentCorrelation.BeginScope(logger, request.HttpContext);

            var (issuer, _) = await issuerAudienceProvider.GetIssuerAndAudienceAsync(ct);
            var issuerUri = new Uri(issuer, UriKind.Absolute);

            var realmId = realmContext.RealmId;
            var signingKeyProvider = await signingKeyProviderResolver.GetSigningKeyProviderAsync(realmId, ct);

            var jwksUri = new Uri(issuerUri, routeOptions.GetJwksPath(coreOptions)).ToString();
            var tokenEndpoint = new Uri(issuerUri, routeOptions.CombineWithBase(routeOptions.TokenPath)).ToString();
            var revocationEndpoint = new Uri(issuerUri, routeOptions.CombineWithBase(routeOptions.RevocationPath)).ToString();
            var introspectionEndpoint = new Uri(issuerUri, routeOptions.CombineWithBase(routeOptions.IntrospectionPath)).ToString();

            var mappedRoutes = endpointDataSources
                .SelectMany(x => x.Endpoints)
                .OfType<RouteEndpoint>()
                .Select(x => x.RoutePattern.RawText)
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .ToHashSet(StringComparer.Ordinal);

            var tokenPath = routeOptions.CombineWithBase(routeOptions.TokenPath);
            var authorizePath = routeOptions.CombineWithBase(routeOptions.AuthorizePath);

            var tokenEndpointMapped = mappedRoutes.Contains(tokenPath);
            var authorizeEndpointMapped = mappedRoutes.Contains(authorizePath);

            var grantTypesSupported = new List<string>(capacity: 4);
            if (tokenEndpointMapped)
            {
                grantTypesSupported.Add(GrantTypes.ClientCredentials);
                grantTypesSupported.Add(GrantTypes.RefreshToken);

                if (authorizeEndpointMapped)
                {
                    grantTypesSupported.Add(GrantTypes.AuthorizationCode);
                }

                grantTypesSupported.Add(GrantTypes.Password);
            }

            IReadOnlyList<string>? responseTypesSupported = authorizeEndpointMapped
                ? ["code"]
                : null;

            IReadOnlyList<string>? tokenEndpointAuthMethodsSupported = tokenEndpointMapped
                ? ["client_secret_basic", "client_secret_post"]
                : null;

            var scopes = (await scopeStore.GetAllAsync(realmId, ct))
                .Where(s => s.ShowInDiscoveryDocument)
                .Select(s => s.Name)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(s => s, StringComparer.Ordinal)
                .ToList();

            var document = new OpenIdConfigurationDocument(
                Issuer: issuer,
                JwksUri: jwksUri,
                TokenEndpoint: tokenEndpoint,
                RevocationEndpoint: revocationEndpoint,
                IntrospectionEndpoint: introspectionEndpoint,
                GrantTypesSupported: grantTypesSupported,
                ScopesSupported: scopes,
                IdTokenSigningAlgValuesSupported: [signingKeyProvider.Algorithm],
                ResponseTypesSupported: responseTypesSupported,
                TokenEndpointAuthMethodsSupported: tokenEndpointAuthMethodsSupported);

            return Results.Json(document);
        });

        return endpoints;
    }

    /// <summary>
    /// Maps discovery endpoints using the default JWKS path.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <returns>The endpoint route builder.</returns>
    public static IEndpointRouteBuilder MapCoreIdentDiscoveryEndpoints(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapCoreIdentDiscoveryEndpoints("/.well-known/jwks.json");
    }

    /// <summary>
    /// Maps discovery endpoints using the specified JWKS path.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="jwksPath">JWKS endpoint path.</param>
    /// <returns>The endpoint route builder.</returns>
    public static IEndpointRouteBuilder MapCoreIdentDiscoveryEndpoints(this IEndpointRouteBuilder endpoints, string jwksPath)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(jwksPath);

        endpoints.MapGet(jwksPath, async (
            HttpContext httpContext,
            CancellationToken ct) =>
        {
            var request = httpContext.Request;
            var loggerFactory = httpContext.RequestServices.GetRequiredService<ILoggerFactory>();
            var logger = loggerFactory.CreateLogger("CoreIdent.Jwks");
            using var _ = CoreIdentCorrelation.BeginScope(logger, httpContext);

            var realmId = "default";
            if (httpContext.RequestServices.GetService<ICoreIdentRealmContext>() is { } realmContext)
            {
                realmId = realmContext.RealmId;
            }

            ISigningKeyProvider signingKeyProvider;
            if (httpContext.RequestServices.GetService<IRealmSigningKeyProviderResolver>() is { } signingKeyProviderResolver)
            {
                signingKeyProvider = await signingKeyProviderResolver.GetSigningKeyProviderAsync(realmId, ct);
            }
            else
            {
                signingKeyProvider = httpContext.RequestServices.GetRequiredService<ISigningKeyProvider>();
            }

            var keys = (await signingKeyProvider.GetValidationKeysAsync(ct)).ToList();

            // Do not publish symmetric keys via JWKS.
            var jwksKeys = new List<object>(capacity: keys.Count);

            foreach (var keyInfo in keys)
            {
                if (keyInfo.Key is SymmetricSecurityKey)
                {
                    continue;
                }

                switch (keyInfo.Key)
                {
                    case RsaSecurityKey rsaKey:
                        {
                            var parameters = rsaKey.Rsa?.ExportParameters(includePrivateParameters: false)
                                ?? rsaKey.Parameters;
                            jwksKeys.Add(new
                            {
                                kty = "RSA",
                                kid = keyInfo.KeyId,
                                use = "sig",
                                alg = SecurityAlgorithms.RsaSha256,
                                n = Base64UrlEncoder.Encode(parameters.Modulus),
                                e = Base64UrlEncoder.Encode(parameters.Exponent)
                            });
                            break;
                        }

                    case ECDsaSecurityKey ecKey:
                        {
                            if (ecKey.ECDsa is null)
                            {
                                logger.LogWarning("EC key did not contain an ECDsa instance; skipping JWKS output for kid {Kid}.", keyInfo.KeyId);
                                break;
                            }

                            var parameters = ecKey.ECDsa.ExportParameters(includePrivateParameters: false);

                            var crv = parameters.Curve.Oid.Value switch
                            {
                                "1.2.840.10045.3.1.7" => "P-256",  // secp256r1 / prime256v1
                                "1.3.132.0.34" => "P-384",         // secp384r1
                                "1.3.132.0.35" => "P-521",         // secp521r1
                                _ => throw new NotSupportedException($"Unsupported EC curve OID: {parameters.Curve.Oid.Value}")
                            };

                            jwksKeys.Add(new
                            {
                                kty = "EC",
                                kid = keyInfo.KeyId,
                                use = "sig",
                                alg = SecurityAlgorithms.EcdsaSha256,
                                crv,
                                x = Base64UrlEncoder.Encode(parameters.Q.X),
                                y = Base64UrlEncoder.Encode(parameters.Q.Y)
                            });
                            break;
                        }

                    default:
                        logger.LogWarning("Unsupported key type {KeyType} in validation keys; skipping.", keyInfo.Key.GetType().FullName);
                        break;
                }
            }

            return Results.Json(new { keys = jwksKeys });
        });

        return endpoints;
    }
}
