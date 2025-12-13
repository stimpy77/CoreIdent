using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace CoreIdent.Core.Endpoints;

public static class DiscoveryEndpointsExtensions
{
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
            ISigningKeyProvider signingKeyProvider,
            IScopeStore scopeStore,
            CancellationToken ct) =>
        {
            if (string.IsNullOrWhiteSpace(coreOptions.Issuer))
            {
                return Results.Problem(title: "Configuration error", detail: "Issuer is not configured.", statusCode: StatusCodes.Status500InternalServerError);
            }

            var issuerUri = new Uri(coreOptions.Issuer, UriKind.Absolute);

            var jwksUri = new Uri(issuerUri, routeOptions.GetJwksPath(coreOptions)).ToString();
            var tokenEndpoint = new Uri(issuerUri, routeOptions.CombineWithBase(routeOptions.TokenPath)).ToString();
            var revocationEndpoint = new Uri(issuerUri, routeOptions.CombineWithBase(routeOptions.RevocationPath)).ToString();
            var introspectionEndpoint = new Uri(issuerUri, routeOptions.CombineWithBase(routeOptions.IntrospectionPath)).ToString();

            var scopes = (await scopeStore.GetAllAsync(ct))
                .Where(s => s.ShowInDiscoveryDocument)
                .Select(s => s.Name)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(s => s, StringComparer.Ordinal)
                .ToList();

            var document = new OpenIdConfigurationDocument(
                Issuer: coreOptions.Issuer,
                JwksUri: jwksUri,
                TokenEndpoint: tokenEndpoint,
                RevocationEndpoint: revocationEndpoint,
                IntrospectionEndpoint: introspectionEndpoint,
                GrantTypesSupported: [],
                ScopesSupported: scopes,
                IdTokenSigningAlgValuesSupported: [signingKeyProvider.Algorithm]);

            return Results.Json(document);
        });

        return endpoints;
    }

    public static IEndpointRouteBuilder MapCoreIdentDiscoveryEndpoints(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapCoreIdentDiscoveryEndpoints("/.well-known/jwks.json");
    }

    public static IEndpointRouteBuilder MapCoreIdentDiscoveryEndpoints(this IEndpointRouteBuilder endpoints, string jwksPath)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(jwksPath);

        endpoints.MapGet(jwksPath, async (
            ISigningKeyProvider signingKeyProvider,
            ILoggerFactory loggerFactory,
            CancellationToken ct) =>
        {
            var logger = loggerFactory.CreateLogger("CoreIdent.Jwks");

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
