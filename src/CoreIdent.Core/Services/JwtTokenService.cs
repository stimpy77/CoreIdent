using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens; // Required for SecurityKey, SigningCredentials
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt; // Required for JwtSecurityTokenHandler
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography; // Required for RandomNumberGenerator
using System.Text; // Required for Encoding
using System.Threading.Tasks;

namespace CoreIdent.Core.Services;

/// <summary>
/// Default implementation of ITokenService using JWT.
/// </summary>
public class JwtTokenService : ITokenService
{
    private readonly CoreIdentOptions _options;
    private readonly SymmetricSecurityKey _signingKey; // Store the key for reuse
    private readonly IUserStore _userStore;
    private const int MinSigningKeyLengthBytes = 32; // HS256 minimum key size

    public JwtTokenService(IOptions<CoreIdentOptions> options, IUserStore userStore)
    {
        _options = options.Value ?? throw new ArgumentNullException(nameof(options), "CoreIdentOptions cannot be null.");
        _userStore = userStore ?? throw new ArgumentNullException(nameof(userStore));

        // Validate options critical for the service to function
        if (string.IsNullOrWhiteSpace(_options.SigningKeySecret))
        {
             // This should ideally be caught by IValidateOptions, but good to double-check
            throw new ArgumentNullException(nameof(_options.SigningKeySecret), "Signing key secret cannot be null or empty.");
        }

        // Validate key length for HS256 (required for SymmetricSecurityKey with HS256)
        if (Encoding.UTF8.GetBytes(_options.SigningKeySecret).Length < MinSigningKeyLengthBytes)
        {
            throw new ArgumentException($"SigningKeySecret must be at least {MinSigningKeyLengthBytes} bytes (e.g., 32 ASCII characters) for HS256.", nameof(_options.SigningKeySecret));
        }

        // Create the key once in the constructor after validation
        _signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SigningKeySecret));
    }

    public async Task<string> GenerateAccessTokenAsync(CoreIdentUser user)
    {
        ArgumentNullException.ThrowIfNull(user);

        var tokenHandler = new JwtSecurityTokenHandler();
        var now = DateTime.UtcNow;
        var expires = now.Add(_options.AccessTokenLifetime);

        // Get claims from the store
        var userClaims = await _userStore.GetClaimsAsync(user, CancellationToken.None);

        // Combine standard JWT claims with user claims
        var allClaims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Unique Token ID
            new Claim(JwtRegisteredClaimNames.Iat, new DateTimeOffset(now).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64) // Issued At
        };

        // Add user claims, ensuring essential ones like NameIdentifier (sub) are present
        if (!userClaims.Any(c => c.Type == ClaimTypes.NameIdentifier) && user.Id != null)
        {
            allClaims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id));
        }
        if (!userClaims.Any(c => c.Type == ClaimTypes.Name) && user.UserName != null)
        {
            allClaims.Add(new Claim(ClaimTypes.Name, user.UserName));
        }
        
        allClaims.AddRange(userClaims.Where(uc => uc.Type != ClaimTypes.NameIdentifier && uc.Type != ClaimTypes.Name)); // Add others, avoiding duplicates of basic ones

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(allClaims),
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            Expires = expires,
            SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256Signature)
        };

        var securityToken = tokenHandler.CreateToken(tokenDescriptor);
        var accessToken = tokenHandler.WriteToken(securityToken);

        return accessToken;
    }

    // Phase 1: Return only refresh token string
    public Task<string> GenerateRefreshTokenAsync(CoreIdentUser user)
    {
        // Generate a cryptographically secure random string for the refresh token handle
        // Phase 1: Just the handle. Phase 2 will involve storing metadata alongside it.
        var randomNumber = new byte[32]; // 256 bits
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        var refreshToken = Convert.ToBase64String(randomNumber);

        return Task.FromResult(refreshToken);
    }
}
