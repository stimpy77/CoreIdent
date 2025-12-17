using System.Security.Claims;
using CoreIdent.Core.Services.Realms;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace CoreIdent.Core.Services;

public class JwtTokenService : ITokenService
{
    private readonly ICoreIdentRealmContext _realmContext;
    private readonly IRealmSigningKeyProviderResolver _signingKeyProviderResolver;
    private readonly ILogger<JwtTokenService> _logger;
    private readonly JsonWebTokenHandler _handler = new();

    public JwtTokenService(
        ICoreIdentRealmContext realmContext,
        IRealmSigningKeyProviderResolver signingKeyProviderResolver,
        ILogger<JwtTokenService> logger)
    {
        _realmContext = realmContext ?? throw new ArgumentNullException(nameof(realmContext));
        _signingKeyProviderResolver = signingKeyProviderResolver ?? throw new ArgumentNullException(nameof(signingKeyProviderResolver));
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

        ArgumentNullException.ThrowIfNull(claims);

        var realmId = _realmContext.RealmId;
        var signingKeyProvider = await _signingKeyProviderResolver.GetSigningKeyProviderAsync(realmId, ct);
        var signingCredentials = await signingKeyProvider.GetSigningCredentialsAsync(ct);

        if (string.IsNullOrWhiteSpace(signingCredentials.Key.KeyId))
        {
            throw new InvalidOperationException("Signing key must have a non-empty KeyId (kid).");
        }

        // Ensure jti claim is present for revocation support
        var claimsList = claims.ToList();
        if (!claimsList.Any(c => c.Type == JwtRegisteredClaimNames.Jti))
        {
            claimsList.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")));
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Subject = new ClaimsIdentity(claimsList),
            Expires = expiresAt.UtcDateTime,
            SigningCredentials = signingCredentials
        };

        var token = _handler.CreateToken(descriptor);

        _logger.LogDebug("JWT created using alg {Alg} and kid {Kid}", signingCredentials.Algorithm, signingCredentials.Key.KeyId);

        return token;
    }
}
