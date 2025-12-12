using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace CoreIdent.Core.Services;

public interface ITokenService
{
    Task<string> CreateJwtAsync(
        string issuer,
        string audience,
        IEnumerable<Claim> claims,
        DateTimeOffset expiresAt,
        CancellationToken ct = default);
}

public class JwtTokenService : ITokenService
{
    private readonly ISigningKeyProvider _signingKeyProvider;
    private readonly ILogger<JwtTokenService> _logger;
    private readonly JsonWebTokenHandler _handler = new();

    public JwtTokenService(ISigningKeyProvider signingKeyProvider, ILogger<JwtTokenService> logger)
    {
        _signingKeyProvider = signingKeyProvider ?? throw new ArgumentNullException(nameof(signingKeyProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<string> CreateJwtAsync(
        string issuer,
        string audience,
        IEnumerable<Claim> claims,
        DateTimeOffset expiresAt,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(issuer))
        {
            throw new ArgumentException("Issuer is required.", nameof(issuer));
        }

        if (string.IsNullOrWhiteSpace(audience))
        {
            throw new ArgumentException("Audience is required.", nameof(audience));
        }

        var signingCredentials = await _signingKeyProvider.GetSigningCredentialsAsync(ct);

        if (string.IsNullOrWhiteSpace(signingCredentials.Key.KeyId))
        {
            throw new InvalidOperationException("Signing key must have a non-empty KeyId (kid).");
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Subject = new ClaimsIdentity(claims ?? throw new ArgumentNullException(nameof(claims))),
            Expires = expiresAt.UtcDateTime,
            SigningCredentials = signingCredentials
        };

        var token = _handler.CreateToken(descriptor);

        _logger.LogDebug("JWT created using alg {Alg} and kid {Kid}", signingCredentials.Algorithm, signingCredentials.Key.KeyId);

        return token;
    }
}
