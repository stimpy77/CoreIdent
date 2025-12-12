using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using CoreIdent.Core.Services;

namespace CoreIdent.Core.Endpoints;

public static class DiscoveryEndpointsExtensions
{
    public static IEndpointRouteBuilder MapCoreIdentDiscoveryEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/.well-known/jwks.json", async (
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
                            "1.2.840.10045.3.1.7" => "P-256",
                            _ => "P-256"
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
