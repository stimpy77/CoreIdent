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
    private readonly IEnumerable<ICustomClaimsProvider> _customClaimsProviders;
    private const int MinSigningKeyLengthBytes = 32; // HS256 minimum key size

    public JwtTokenService(
        IOptions<CoreIdentOptions> options,
        IUserStore userStore,
        IRefreshTokenStore refreshTokenStore, // Inject IRefreshTokenStore
        IScopeStore scopeStore, // Inject IScopeStore
        ILogger<JwtTokenService> logger,
        IEnumerable<ICustomClaimsProvider> customClaimsProviders // Inject custom claims providers
    )
    {
        // Constructor argument validation
        if (options == null) throw new ArgumentNullException(nameof(options));
        _options = options.Value ?? throw new ArgumentNullException(nameof(options), "Options.Value cannot be null.");
        _userStore = userStore ?? throw new ArgumentNullException(nameof(userStore));
        _refreshTokenStore = refreshTokenStore ?? throw new ArgumentNullException(nameof(refreshTokenStore));
        _scopeStore = scopeStore ?? throw new ArgumentNullException(nameof(scopeStore));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _customClaimsProviders = customClaimsProviders ?? throw new ArgumentNullException(nameof(customClaimsProviders));

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
    public async Task<string> GenerateAccessTokenAsync(CoreIdentUser user, IEnumerable<string>? allowedScopes = null)
    {
        _logger.LogDebug("Generating access token for user {UserId} with scopes: {Scopes}", user.Id, allowedScopes);
        var userClaims = await _userStore.GetClaimsAsync(user, CancellationToken.None);
        var claims = await GetClaimsForTokenAsync(user, userClaims, allowedScopes);

        // Ensure standard claims are present before final generation
        claims.AddIfNotExist(new Claim(JwtRegisteredClaimNames.Sub, user.Id));
        claims.AddIfNotExist(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
        claims.AddIfNotExist(new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64));

        // Issuer and Audience are added in GetClaimsForTokenAsync or GenerateJwtTokenInternal

        return GenerateJwtTokenInternal(claims, user.Id);
    }

    /// <inheritdoc />
    public Task<string> GenerateAccessTokenAsync(CoreIdentClient client, IEnumerable<string> grantedScopes)
    {
        _logger.LogDebug("Generating access token for client {ClientId} with scopes: {Scopes}", client.ClientId, grantedScopes);

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, client.ClientId), // Subject is the Client ID
            new Claim("client_id", client.ClientId), // Explicit client_id claim
            // Add Jti and Iat which are standard
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
        };

        if (grantedScopes != null && grantedScopes.Any())
        {
            claims.Add(new Claim("scope", string.Join(" ", grantedScopes)));
        }

        // Issuer and Audience are standard for access tokens
        claims.Add(new Claim(JwtRegisteredClaimNames.Iss, _options.Issuer ?? throw new InvalidOperationException("Issuer not configured.")));
        if (!string.IsNullOrEmpty(_options.Audience))
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Aud, _options.Audience));
        }

        // Use the existing internal helper method
        return Task.FromResult(GenerateJwtTokenInternal(claims, client.ClientId));
    }

    /// <inheritdoc />
    public async Task<string?> GenerateIdTokenAsync(CoreIdentUser user, string clientId, string? nonce, IEnumerable<string>? scopes = null)
    {
        _logger.LogDebug("Generating ID token for user {UserId}, client {ClientId}, nonce: {Nonce}, scopes: {Scopes}",
            user.Id, clientId, nonce, scopes);

        if (user == null) throw new ArgumentNullException(nameof(user));
        if (string.IsNullOrEmpty(clientId)) throw new ArgumentNullException(nameof(clientId));
        // Nonce is optional, scopes might be optional depending on context, but usually required for openid
        if (scopes == null || !scopes.Contains("openid"))
        {
            _logger.LogDebug("ID token not generated: 'openid' scope missing.");
            return null; // ID token requires 'openid' scope
        }

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

        // Add user claims based on requested scopes
        var userClaims = await _userStore.GetClaimsAsync(user, CancellationToken.None);
        var scopesFromStore = await _scopeStore.FindScopesByNameAsync(scopes, CancellationToken.None);

        // Get claim types allowed by the requested scopes
        var allowedClaimTypes = scopesFromStore
            .SelectMany(s => s.UserClaims.Select(uc => uc.Type))
            .Distinct()
            .ToHashSet(); // Use HashSet for faster lookups

        // Include standard OIDC claims based on standard scopes requested
        foreach (var scopeName in scopes)
        {
            _logger.LogDebug("Adding claims based on scope: {ScopeName}", scopeName);
            if (scopeName == "profile")
            {
                 // Add claims allowed by the 'profile' scope definition
                 if (allowedClaimTypes.Contains(JwtRegisteredClaimNames.Name))
                 {
                     var nameClaim = userClaims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Name)?.Value;
                     if (!string.IsNullOrEmpty(nameClaim))
                         claims.AddIfNotExist(new Claim(JwtRegisteredClaimNames.Name, nameClaim));
                     else if (!string.IsNullOrEmpty(user.UserName))
                         claims.AddIfNotExist(new Claim(JwtRegisteredClaimNames.Name, user.UserName));
                 }
                 if (allowedClaimTypes.Contains(JwtRegisteredClaimNames.FamilyName) && userClaims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.FamilyName)?.Value is string familyName)
                     claims.AddIfNotExist(new Claim(JwtRegisteredClaimNames.FamilyName, familyName));
                 if (allowedClaimTypes.Contains(JwtRegisteredClaimNames.GivenName) && userClaims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.GivenName)?.Value is string givenName)
                     claims.AddIfNotExist(new Claim(JwtRegisteredClaimNames.GivenName, givenName));
                 // Add other profile claims (middle_name, nickname, preferred_username, profile, picture, website, gender, birthdate, zoneinfo, locale, updated_at)
             }
             else if (scopeName == "email")
             {
                  // Add claims allowed by the 'email' scope definition
                  if (allowedClaimTypes.Contains(JwtRegisteredClaimNames.Email))
                  {
                      var emailClaim = userClaims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Email)?.Value;
                      if (!string.IsNullOrEmpty(emailClaim))
                          claims.AddIfNotExist(new Claim(JwtRegisteredClaimNames.Email, emailClaim));
                      else if (!string.IsNullOrEmpty(user.UserName))
                          claims.AddIfNotExist(new Claim(JwtRegisteredClaimNames.Email, user.UserName));
                  }
                  // if (allowedClaimTypes.Contains("email_verified") && userClaims.FirstOrDefault(c => c.Type == "email_verified")?.Value is string emailVerified)
                  //    claims.AddIfNotExist(new Claim("email_verified", emailVerified));
             }
             else if (scopeName == "address")
             {
                // Add claims allowed by the 'address' scope definition
                // if (allowedClaimTypes.Contains("address") && userClaims.FirstOrDefault(c => c.Type == "address")?.Value is string addressJson)
                //    claims.AddIfNotExist(new Claim("address", addressJson, JsonClaimValueTypes.Json));
            }
             else if (scopeName == "phone")
            {
                // Add claims allowed by the 'phone' scope definition
                // if (allowedClaimTypes.Contains("phone_number") && userClaims.FirstOrDefault(c => c.Type == "phone_number")?.Value is string phone)
                //    claims.AddIfNotExist(new Claim("phone_number", phone));
                // if (allowedClaimTypes.Contains("phone_number_verified") && userClaims.FirstOrDefault(c => c.Type == "phone_number_verified")?.Value is string phoneVerified)
                //    claims.AddIfNotExist(new Claim("phone_number_verified", phoneVerified));
            }
            // Add other scope-to-claim mappings here for custom scopes
        }

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
            Handle = refreshTokenHandle, // Store the RAW handle (PK)
            HashedHandle = hashedHandle, // Store the HASHED handle
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
            Handle = refreshTokenHandle, // Store the RAW handle (PK)
            HashedHandle = hashedHandle, // Store the HASHED handle
            SubjectId = user.Id,
            ClientId = clientId,
            CreationTime = DateTime.UtcNow,
            ExpirationTime = DateTime.UtcNow.Add(_options.RefreshTokenLifetime),
            ConsumedTime = null,
            FamilyId = previousToken.FamilyId, // Keep the same family ID
            PreviousTokenId = previousToken.Handle // Store the parent token's RAW handle
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

    // Make the security key accessible for JWKS endpoint
    public SecurityKey GetSecurityKey()
    {
        if (string.IsNullOrWhiteSpace(_options.SigningKeySecret))
        {
            throw new InvalidOperationException("SigningKeySecret not configured.");
        }
        // TODO: Add support for asymmetric keys (RS256 etc.) based on config
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

    private async Task<List<Claim>> GetClaimsForTokenAsync(CoreIdentUser user, IEnumerable<Claim> userClaims, IEnumerable<string>? allowedScopes = null)
    {
        var claims = new List<Claim>();

        // Add user claims based on requested scopes
        if (allowedScopes != null && allowedScopes.Any())
        {
            var scopesFromStore = await _scopeStore.FindScopesByNameAsync(allowedScopes, CancellationToken.None);

            var allowedClaimTypes = scopesFromStore
                .SelectMany(s => s.UserClaims.Select(uc => uc.Type))
                .Distinct()
                .ToList();

            // Include standard OIDC claims based on standard scopes
            if (allowedScopes.Contains("profile"))
            {
                 allowedClaimTypes.AddRange(new[] { "name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at" });
            }
             if (allowedScopes.Contains("email"))
            {
                allowedClaimTypes.AddRange(new[] { "email", "email_verified" });
            }
            if (allowedScopes.Contains("address"))
            {
                 allowedClaimTypes.Add("address");
            }
            if (allowedScopes.Contains("phone"))
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

        // Add Subject claim here as it's fundamental
        claims.AddIfNotExist(new Claim(JwtRegisteredClaimNames.Sub, user.Id));

        // Add scope claim if scopes were requested and processed
        if (allowedScopes != null && allowedScopes.Any())
        {
            claims.Add(new Claim("scope", string.Join(" ", allowedScopes)));
        }

        // === Custom Claims Extensibility ===
        // Build TokenRequestContext
        var context = new TokenRequestContext
        {
            User = user,
            Client = null, // If client is available, set here
            Scopes = allowedScopes,
            TokenType = "access_token"
        };
        foreach (var provider in _customClaimsProviders)
        {
            var customClaims = await provider.GetCustomClaimsAsync(context, CancellationToken.None);
            if (customClaims != null)
                claims.AddRange(customClaims);
        }
        // === End Custom Claims Extensibility ===

        return claims;
    }

    private string GenerateJwtTokenInternal(List<Claim> claims, string subject)
    {
        // Signing Key
        var securityKey = GetSecurityKey();
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256); // Ensure algorithm matches key type

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.Add(_options.AccessTokenLifetime),
            Issuer = _options.Issuer ?? throw new InvalidOperationException("Issuer not configured."),
            Audience = _options.Audience ?? throw new InvalidOperationException("Audience not configured."),
            SigningCredentials = credentials
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var tokenString = tokenHandler.WriteToken(token);
         _logger.LogDebug("Generated JWT for principal {PrincipalId}. Issuer: {Issuer}, Audience: {Audience}, Expires: {Expiry}",
            subject, tokenDescriptor.Issuer, tokenDescriptor.Audience, tokenDescriptor.Expires);
        return tokenString;
    }
}

internal static class ClaimsExtensions
{
    internal static void AddIfNotExist(this List<Claim> claims, Claim claimToAdd)
    {
        if (!claims.Any(c => c.Type == claimToAdd.Type /* && c.Value == claimToAdd.Value */)) // Allow multiple claims of same type (e.g., roles)
        {
            claims.Add(claimToAdd);
        }
    }
}
