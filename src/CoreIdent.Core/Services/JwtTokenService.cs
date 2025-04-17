using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using Microsoft.Extensions.Logging;
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
/// Default implementation of <see cref="ITokenService"/> using JWT.
/// </summary>
public class JwtTokenService : ITokenService
{
    private readonly CoreIdentOptions _options;
    private readonly IUserStore _userStore;
    private readonly IRefreshTokenStore _refreshTokenStore; // Needed for storing refresh tokens
    private readonly IScopeStore _scopeStore; // Needed to get claims for scopes
    private readonly ILogger<JwtTokenService> _logger;
    private const int MinSigningKeyLengthBytes = 32; // HS256 minimum key size

    public JwtTokenService(
        IOptions<CoreIdentOptions> options,
        IUserStore userStore,
        IRefreshTokenStore refreshTokenStore, // Inject IRefreshTokenStore
        IScopeStore scopeStore, // Inject IScopeStore
        ILogger<JwtTokenService> logger)
    {
        // Constructor argument validation
        if (options == null) throw new ArgumentNullException(nameof(options));
        _options = options.Value ?? throw new ArgumentNullException(nameof(options), "Options.Value cannot be null.");
        _userStore = userStore ?? throw new ArgumentNullException(nameof(userStore));
        _refreshTokenStore = refreshTokenStore ?? throw new ArgumentNullException(nameof(refreshTokenStore));
        _scopeStore = scopeStore ?? throw new ArgumentNullException(nameof(scopeStore));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

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
    }

    /// <inheritdoc />
    public async Task<string> GenerateAccessTokenAsync(CoreIdentUser user, IEnumerable<string>? scopes = null)
    {
        if (user == null) throw new ArgumentNullException(nameof(user));

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Unique token identifier
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            // Add username/email if available
            // Name claim should come from profile scope usually
            // new Claim(JwtRegisteredClaimNames.Name, user.UserName ?? "")
        };

        // Add user claims based on requested scopes
        if (scopes != null && scopes.Any())
        {
            var userClaims = await _userStore.GetClaimsAsync(user, CancellationToken.None);
            var scopesFromStore = await _scopeStore.FindScopesByNameAsync(scopes, CancellationToken.None);

            var allowedClaimTypes = scopesFromStore
                .SelectMany(s => s.UserClaims.Select(uc => uc.Type))
                .Distinct()
                .ToList();

            // Include standard OIDC claims based on standard scopes
            if (scopes.Contains("profile"))
            {
                 allowedClaimTypes.AddRange(new[] { "name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at" });
            }
             if (scopes.Contains("email"))
            {
                allowedClaimTypes.AddRange(new[] { "email", "email_verified" });
            }
            if (scopes.Contains("address"))
            {
                 allowedClaimTypes.Add("address");
            }
            if (scopes.Contains("phone"))
            {
                 allowedClaimTypes.AddRange(new[] { "phone_number", "phone_number_verified" });
            }

            allowedClaimTypes = allowedClaimTypes.Distinct().ToList();

            claims.AddRange(userClaims.Where(uc => allowedClaimTypes.Contains(uc.Type)));
        }

        // Issuer & Audience
        var issuer = _options.Issuer ?? throw new InvalidOperationException("Issuer not configured.");
        var audience = _options.Audience ?? throw new InvalidOperationException("Audience not configured.");

        claims.Add(new Claim(JwtRegisteredClaimNames.Iss, issuer));
        claims.Add(new Claim(JwtRegisteredClaimNames.Aud, audience)); // Access token audience is typically the resource server

        // Signing Key
        var securityKey = GetSecurityKey();
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256); // Ensure algorithm matches key type

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.Add(_options.AccessTokenLifetime),
            Issuer = issuer,
            Audience = audience,
            SigningCredentials = credentials
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);

        return tokenHandler.WriteToken(token);
    }

    /// <inheritdoc />
    public async Task<string> GenerateIdTokenAsync(CoreIdentUser user, string clientId, string? nonce, IEnumerable<string> scopes)
    {
        if (user == null) throw new ArgumentNullException(nameof(user));
        if (string.IsNullOrEmpty(clientId)) throw new ArgumentNullException(nameof(clientId));
        if (scopes == null) throw new ArgumentNullException(nameof(scopes));

        var now = DateTimeOffset.UtcNow;
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
             // TODO: Add auth_time claim - requires storing user's last login time
            // new Claim("auth_time", user.LastLoginTime?.ToUnixTimeSeconds().ToString() ?? now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
        };

        if (!string.IsNullOrWhiteSpace(nonce))
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce));
        }

        // Add user claims based on requested scopes (similar logic to access token, but tailored for ID token)
        var userClaims = await _userStore.GetClaimsAsync(user, CancellationToken.None);
        var scopesFromStore = await _scopeStore.FindScopesByNameAsync(scopes, CancellationToken.None);

        var allowedClaimTypes = scopesFromStore
            .SelectMany(s => s.UserClaims.Select(uc => uc.Type))
            .Distinct()
            .ToList();

        // Include standard OIDC claims based on standard scopes
         if (scopes.Contains("profile"))
        {
            allowedClaimTypes.AddRange(new[] { "name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at" });
        }
        if (scopes.Contains("email"))
        {
            allowedClaimTypes.AddRange(new[] { "email", "email_verified" });
        }
         if (scopes.Contains("address"))
        {
            allowedClaimTypes.Add("address");
        }
        if (scopes.Contains("phone"))
        {
            allowedClaimTypes.AddRange(new[] { "phone_number", "phone_number_verified" });
        }

        allowedClaimTypes = allowedClaimTypes.Distinct().ToList();
        claims.AddRange(userClaims.Where(uc => allowedClaimTypes.Contains(uc.Type)));

        // Issuer & Audience
        var issuer = _options.Issuer ?? throw new InvalidOperationException("Issuer not configured.");
        // ID token audience is the Client ID
        claims.Add(new Claim(JwtRegisteredClaimNames.Iss, issuer));
        claims.Add(new Claim(JwtRegisteredClaimNames.Aud, clientId));

        // Signing Key
        var securityKey = GetSecurityKey();
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256); // Ensure algorithm matches key type

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.Add(_options.AccessTokenLifetime), // ID token lifetime typically matches access token or shorter
            Issuer = issuer,
            Audience = clientId,
            SigningCredentials = credentials
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);

        return tokenHandler.WriteToken(token);
    }

    /// <inheritdoc />
    public async Task<string> GenerateAndStoreRefreshTokenAsync(CoreIdentUser user, string clientId)
    {
        if (user == null) throw new ArgumentNullException(nameof(user));
        if (string.IsNullOrEmpty(clientId)) throw new ArgumentNullException(nameof(clientId));

        // Generate a cryptographically secure random string for the handle
        var refreshTokenHandleBytes = RandomNumberGenerator.GetBytes(32); // 256 bits
        var refreshTokenHandle = Convert.ToBase64String(refreshTokenHandleBytes)
                                    .Replace("+", "-").Replace("/", "_").TrimEnd('='); // URL-safe

        // Generate a new family ID for this token (will be reused for descendants)
        var familyIdBytes = RandomNumberGenerator.GetBytes(16); // 128 bits
        var familyId = Convert.ToBase64String(familyIdBytes)
                        .Replace("+", "-").Replace("/", "_").TrimEnd('='); // URL-safe

        // Hash the token handle before storing
        var hashedHandle = TokenHasher.HashToken(refreshTokenHandle, user.Id, clientId);

        var refreshTokenEntity = new CoreIdentRefreshToken
        {
            Handle = hashedHandle, // Store the hashed handle for lookups
            HashedHandle = hashedHandle, // Also set the HashedHandle property for future compatibility
            SubjectId = user.Id,
            ClientId = clientId,
            CreationTime = DateTime.UtcNow,
            ExpirationTime = DateTime.UtcNow.Add(_options.RefreshTokenLifetime),
            ConsumedTime = null,
            FamilyId = familyId,
            PreviousTokenId = null // This is a root token, no parent
        };

        try
        {
            await _refreshTokenStore.StoreRefreshTokenAsync(refreshTokenEntity, CancellationToken.None);
            _logger.LogDebug("Stored new refresh token for user {UserId}, client {ClientId}. Raw handle starts with: {HandlePrefix}, Hashed: {HashedHandlePrefix}, Family: {FamilyId}", 
                user.Id, clientId, refreshTokenHandle.Substring(0, Math.Min(6, refreshTokenHandle.Length)), 
                hashedHandle.Substring(0, Math.Min(6, hashedHandle.Length)), familyId);
            return refreshTokenHandle; // Return the raw handle to the client
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to store refresh token for user {UserId}, client {ClientId}", user.Id, clientId);
            // Re-throw or handle appropriately - failing to store means the refresh token isn't valid
            throw new InvalidOperationException("Failed to store the refresh token.", ex);
        }
    }

    /// <summary>
    /// Generates and stores a refresh token that is a descendant of a previous token.
    /// Used during token rotation to maintain the token family lineage.
    /// </summary>
    /// <param name="user">The user to generate the token for.</param>
    /// <param name="clientId">The client ID the token is for.</param>
    /// <param name="previousToken">The previous token that is being rotated out.</param>
    /// <returns>A task with the token handle.</returns>
    public async Task<string> GenerateAndStoreRefreshTokenAsync(CoreIdentUser user, string clientId, CoreIdentRefreshToken previousToken)
    {
        if (user == null) throw new ArgumentNullException(nameof(user));
        if (string.IsNullOrEmpty(clientId)) throw new ArgumentNullException(nameof(clientId));
        if (previousToken == null) throw new ArgumentNullException(nameof(previousToken));
        if (string.IsNullOrEmpty(previousToken.FamilyId)) throw new ArgumentException("Previous token must have a family ID", nameof(previousToken));

        // Generate a cryptographically secure random string for the handle
        var refreshTokenHandleBytes = RandomNumberGenerator.GetBytes(32); // 256 bits
        var refreshTokenHandle = Convert.ToBase64String(refreshTokenHandleBytes)
                                    .Replace("+", "-").Replace("/", "_").TrimEnd('='); // URL-safe

        // Hash the token handle before storing
        var hashedHandle = TokenHasher.HashToken(refreshTokenHandle, user.Id, clientId);

        var refreshTokenEntity = new CoreIdentRefreshToken
        {
            Handle = hashedHandle, // Store the hashed handle for lookups
            HashedHandle = hashedHandle, // Also set the HashedHandle property for future compatibility
            SubjectId = user.Id,
            ClientId = clientId,
            CreationTime = DateTime.UtcNow,
            ExpirationTime = DateTime.UtcNow.Add(_options.RefreshTokenLifetime),
            ConsumedTime = null,
            FamilyId = previousToken.FamilyId, // Keep the same family ID to maintain lineage
            PreviousTokenId = previousToken.Handle // Store the parent token ID for tracking
        };

        try
        {
            await _refreshTokenStore.StoreRefreshTokenAsync(refreshTokenEntity, CancellationToken.None);
            _logger.LogDebug("Stored descendant refresh token for user {UserId}, client {ClientId}. Raw handle starts with: {HandlePrefix}, Hashed: {HashedHandlePrefix}, Family: {FamilyId}", 
                user.Id, clientId, refreshTokenHandle.Substring(0, Math.Min(6, refreshTokenHandle.Length)),
                hashedHandle.Substring(0, Math.Min(6, hashedHandle.Length)), previousToken.FamilyId);
            return refreshTokenHandle; // Return the raw handle to the client
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to store descendant refresh token for user {UserId}, client {ClientId}", user.Id, clientId);
            throw new InvalidOperationException("Failed to store the refresh token.", ex);
        }
    }

    private SecurityKey GetSecurityKey()
    {
        if (string.IsNullOrWhiteSpace(_options.SigningKeySecret))
        {
            throw new InvalidOperationException("SigningKeySecret not configured.");
        }
        // TODO: Add support for asymmetric keys (reading from config/file)
        return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SigningKeySecret));
    }

    // // DEPRECATED: Original simple refresh token generation
    // public Task<string> GenerateRefreshTokenAsync(CoreIdentUser user)
    // {
    //     // Simple, less secure refresh token (replace with opaque handle and storage)
    //     var randomNumber = new byte[32];
    //     using var rng = RandomNumberGenerator.Create();
    //     rng.GetBytes(randomNumber);
    //     return Task.FromResult(Convert.ToBase64String(randomNumber));
    // }
}
