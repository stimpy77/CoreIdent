using System.Diagnostics;
using System.Security.Claims;
using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Observability;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;

namespace CoreIdent.Legacy.PasswordGrant;

/// <summary>
/// Handles the OAuth 2.0 Resource Owner Password Credentials (ROPC) grant type.
/// <para>
/// <strong>Deprecated in OAuth 2.1 (RFC 9725).</strong> Use authorization code flow with PKCE instead.
/// This handler is provided for migration support only.
/// </para>
/// </summary>
public sealed class PasswordGrantHandler : IGrantTypeHandler
{
    /// <inheritdoc />
#pragma warning disable CS0618 // Intentional use of obsolete GrantTypes.Password
    public string GrantType => GrantTypes.Password;
#pragma warning restore CS0618

    /// <inheritdoc />
    public async Task<IResult> HandleAsync(
        CoreIdentClient client,
        TokenRequest request,
        HttpContext httpContext,
        CancellationToken ct)
    {
        var services = httpContext.RequestServices;
        var tokenService = services.GetRequiredService<ITokenService>();
        var refreshTokenStore = services.GetRequiredService<IRefreshTokenStore>();
        var userStore = services.GetRequiredService<IUserStore>();
        var passwordHasher = services.GetRequiredService<IPasswordHasher>();
        var customClaimsProvider = services.GetRequiredService<ICustomClaimsProvider>();
        var metrics = services.GetRequiredService<ICoreIdentMetrics>();
        var options = services.GetRequiredService<IOptions<CoreIdentOptions>>().Value;
        var timeProvider = services.GetRequiredService<TimeProvider>();
        var loggerFactory = services.GetRequiredService<ILoggerFactory>();
        var logger = loggerFactory.CreateLogger("CoreIdent.Legacy.PasswordGrant");

        var issuanceStart = Stopwatch.GetTimestamp();
        logger.LogWarning("Password grant (ROPC) is deprecated in OAuth 2.1 (RFC 9725). Consider using authorization code flow with PKCE.");

#pragma warning disable CS0618 // Intentional access to obsolete properties
        var username = request.Username;
        var password = request.Password;
#pragma warning restore CS0618

        if (string.IsNullOrWhiteSpace(username))
        {
            return TokenError("invalid_request", "The username parameter is required.");
        }

        if (string.IsNullOrWhiteSpace(password))
        {
            return TokenError("invalid_request", "The password parameter is required.");
        }

        var user = await userStore.FindByUsernameAsync(username, ct);
        if (user is null)
        {
            return TokenError("invalid_grant", "Invalid resource owner credentials.");
        }

        if (string.IsNullOrWhiteSpace(user.PasswordHash) || !passwordHasher.VerifyHashedPassword(user, user.PasswordHash, password))
        {
            return TokenError("invalid_grant", "Invalid resource owner credentials.");
        }

        var requestedScopes = ParseScopes(request.Scope);
        var grantedScopes = ValidateScopes(requestedScopes, client.AllowedScopes);

        if (requestedScopes.Count > 0 && grantedScopes.Count == 0)
        {
            return TokenError("invalid_scope", "None of the requested scopes are allowed for this client.");
        }

        var accessTokenLifetime = TimeSpan.FromSeconds(client.AccessTokenLifetimeSeconds);
        var accessTokenExpiresAt = timeProvider.GetUtcNow().Add(accessTokenLifetime);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new("client_id", client.ClientId)
        };

        if (grantedScopes.Count > 0)
        {
            claims.Add(new Claim("scope", string.Join(" ", grantedScopes)));
        }

        var userClaims = await userStore.GetClaimsAsync(user.Id, ct);
        claims.AddRange(userClaims);

#pragma warning disable CS0618
        var claimsContext = new ClaimsContext
        {
            SubjectId = user.Id,
            ClientId = client.ClientId,
            Scopes = grantedScopes,
            GrantType = GrantTypes.Password
        };
#pragma warning restore CS0618

        var customClaims = await customClaimsProvider.GetAccessTokenClaimsAsync(claimsContext, ct);
        claims.AddRange(customClaims);

        var accessToken = await tokenService.CreateJwtAsync(
            options.Issuer!,
            options.Audience!,
            claims,
            accessTokenExpiresAt,
            ct);

        string? refreshTokenHandle = null;
        if (client.AllowOfflineAccess && grantedScopes.Contains(StandardScopes.OfflineAccess, StringComparer.Ordinal))
        {
            var now = timeProvider.GetUtcNow().UtcDateTime;
            var refreshTokenLifetime = TimeSpan.FromSeconds(client.RefreshTokenLifetimeSeconds);
            refreshTokenHandle = GenerateRefreshTokenHandle();

            var refreshToken = new CoreIdentRefreshToken
            {
                Handle = refreshTokenHandle,
                SubjectId = user.Id,
                ClientId = client.ClientId,
                FamilyId = Guid.NewGuid().ToString("N"),
                Scopes = grantedScopes,
                CreatedAt = now,
                ExpiresAt = now.Add(refreshTokenLifetime)
            };

            await refreshTokenStore.StoreAsync(refreshToken, ct);
        }

        logger.LogInformation("Issued tokens for subject {SubjectId} via password grant (legacy)", user.Id);

#pragma warning disable CS0618
        var elapsedMs = Stopwatch.GetElapsedTime(issuanceStart).TotalMilliseconds;
        metrics.TokenIssued("access_token", GrantTypes.Password, elapsedMs);

        if (!string.IsNullOrWhiteSpace(refreshTokenHandle))
        {
            metrics.TokenIssued("refresh_token", GrantTypes.Password, elapsedMs);
        }
#pragma warning restore CS0618

        return Results.Ok(new TokenResponse
        {
            AccessToken = accessToken,
            TokenType = "Bearer",
            ExpiresIn = (int)accessTokenLifetime.TotalSeconds,
            RefreshToken = refreshTokenHandle,
            Scope = grantedScopes.Count > 0 ? string.Join(" ", grantedScopes) : null
        });
    }

    private static IResult TokenError(string error, string description) =>
        Results.Json(
            new TokenErrorResponse { Error = error, ErrorDescription = description },
            statusCode: error == "invalid_client" ? StatusCodes.Status401Unauthorized : StatusCodes.Status400BadRequest,
            contentType: "application/json");

    private static List<string> ParseScopes(string? scope) =>
        string.IsNullOrWhiteSpace(scope)
            ? []
            : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

    private static List<string> ValidateScopes(List<string> requested, ICollection<string> allowed) =>
        requested.Count == 0
            ? allowed.ToList()
            : requested.Where(s => allowed.Contains(s, StringComparer.Ordinal)).ToList();

    private static string GenerateRefreshTokenHandle()
    {
        var bytes = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes);
    }
}
