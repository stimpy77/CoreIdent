using System.Security.Claims;
using CoreIdent.Core.Configuration;
using CoreIdent.Core.Extensions;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace CoreIdent.Core.Endpoints;

/// <summary>
/// Endpoint mapping for the OpenID Connect user info endpoint.
/// </summary>
public static class UserInfoEndpointExtensions
{
    /// <summary>
    /// Maps the user info endpoint using route options resolved from DI.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <returns>The endpoint route builder.</returns>
    public static IEndpointRouteBuilder MapCoreIdentUserInfoEndpoint(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var routeOptions = endpoints.ServiceProvider.GetRequiredService<IOptions<CoreIdentRouteOptions>>().Value;
        var userInfoPath = routeOptions.CombineWithBase(routeOptions.UserInfoPath);

        return endpoints.MapCoreIdentUserInfoEndpoint(userInfoPath);
    }

    /// <summary>
    /// Maps the user info endpoint at the specified path.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="userInfoPath">User info endpoint path.</param>
    /// <returns>The endpoint route builder.</returns>
    public static IEndpointRouteBuilder MapCoreIdentUserInfoEndpoint(this IEndpointRouteBuilder endpoints, string userInfoPath)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(userInfoPath);

        endpoints.MapGet(userInfoPath, HandleUserInfoAsync);

        return endpoints;
    }

    private static async Task<IResult> HandleUserInfoAsync(
        HttpContext httpContext,
        IUserStore userStore,
        ICustomClaimsProvider customClaimsProvider,
        ISigningKeyProvider signingKeyProvider,
        IOptions<CoreIdentOptions> coreOptions,
        CancellationToken ct)
    {
        var logger = httpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("CoreIdent.UserInfo");
        using var _ = CoreIdentCorrelation.BeginScope(logger, httpContext);

        var principal = await TryValidateBearerTokenAsync(httpContext.Request, signingKeyProvider, coreOptions.Value, ct);
        if (principal is null)
        {
            return Results.Unauthorized();
        }

        var subjectId = principal.FindFirstValue(JwtRegisteredClaimNames.Sub)
            ?? principal.FindFirstValue(ClaimTypes.NameIdentifier);

        if (string.IsNullOrWhiteSpace(subjectId))
        {
            return Results.Unauthorized();
        }

        var user = await userStore.FindByIdAsync(subjectId, ct);
        if (user is null)
        {
            return Results.Unauthorized();
        }

        var scopeClaim = principal.FindFirst("scope")?.Value;
        var scopes = ParseScopes(scopeClaim);

        if (!scopes.Contains(StandardScopes.OpenId, StringComparer.Ordinal))
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        var response = new UserInfoResponse
        {
            ["sub"] = subjectId
        };

        var userClaims = await userStore.GetClaimsAsync(subjectId, ct);

        var clientId = principal.FindFirst("client_id")?.Value ?? string.Empty;

        var claimsContext = new ClaimsContext
        {
            SubjectId = subjectId,
            ClientId = clientId,
            Scopes = scopes,
            GrantType = "userinfo"
        };

        var customClaims = await customClaimsProvider.GetIdTokenClaimsAsync(claimsContext, ct);

        var allowed = GetAllowedUserInfoClaimNames(scopes);

        foreach (var claim in userClaims.Concat(customClaims))
        {
            var name = NormalizeClaimName(claim.Type);
            if (!allowed.Contains(name))
            {
                continue;
            }

            AddClaimValue(response, name, claim.Value);
        }

        if (allowed.Contains("email") && !response.ContainsKey("email") && LooksLikeEmail(user.UserName))
        {
            response["email"] = user.UserName;
        }

        return Results.Ok(response);
    }

    private static IReadOnlyList<string> ParseScopes(string? scope)
    {
        if (string.IsNullOrWhiteSpace(scope))
        {
            return Array.Empty<string>();
        }

        return scope
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.Ordinal)
            .ToList();
    }

    private static HashSet<string> GetAllowedUserInfoClaimNames(IReadOnlyList<string> scopes)
    {
        var allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            "sub"
        };

        if (scopes.Contains("profile", StringComparer.Ordinal))
        {
            allowed.Add("name");
            allowed.Add("family_name");
            allowed.Add("given_name");
            allowed.Add("middle_name");
            allowed.Add("nickname");
            allowed.Add("preferred_username");
            allowed.Add("profile");
            allowed.Add("picture");
            allowed.Add("website");
            allowed.Add("gender");
            allowed.Add("birthdate");
            allowed.Add("zoneinfo");
            allowed.Add("locale");
            allowed.Add("updated_at");
        }

        if (scopes.Contains("email", StringComparer.Ordinal))
        {
            allowed.Add("email");
            allowed.Add("email_verified");
        }

        if (scopes.Contains("address", StringComparer.Ordinal))
        {
            allowed.Add("address");
        }

        if (scopes.Contains("phone", StringComparer.Ordinal))
        {
            allowed.Add("phone_number");
            allowed.Add("phone_number_verified");
        }

        return allowed;
    }

    private static string NormalizeClaimName(string claimType)
    {
        return claimType switch
        {
            JwtRegisteredClaimNames.Sub => "sub",
            ClaimTypes.NameIdentifier => "sub",
            ClaimTypes.Email => "email",
            ClaimTypes.Name => "name",
            ClaimTypes.GivenName => "given_name",
            ClaimTypes.Surname => "family_name",
            _ => claimType
        };
    }

    private static void AddClaimValue(IDictionary<string, object?> dest, string name, string value)
    {
        if (!dest.TryGetValue(name, out var existing) || existing is null)
        {
            dest[name] = value;
            return;
        }

        if (existing is string s)
        {
            dest[name] = new[] { s, value };
            return;
        }

        if (existing is string[] arr)
        {
            dest[name] = arr.Concat(new[] { value }).ToArray();
            return;
        }

        dest[name] = value;
    }

    private static bool LooksLikeEmail(string value)
    {
        return !string.IsNullOrWhiteSpace(value) && value.Contains('@', StringComparison.Ordinal);
    }

    private static async Task<ClaimsPrincipal?> TryValidateBearerTokenAsync(
        HttpRequest request,
        ISigningKeyProvider signingKeyProvider,
        CoreIdentOptions options,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(signingKeyProvider);
        ArgumentNullException.ThrowIfNull(options);

        var auth = request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(auth) || !auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var token = auth["Bearer ".Length..].Trim();
        if (string.IsNullOrWhiteSpace(token))
        {
            return null;
        }

        var keys = (await signingKeyProvider.GetValidationKeysAsync(ct)).Select(x => x.Key).ToList();
        if (keys.Count == 0)
        {
            return null;
        }

        var handler = new JsonWebTokenHandler();

        var result = await handler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = options.Issuer,
            ValidateAudience = true,
            ValidAudience = options.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(1),
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = keys
        });

        if (!result.IsValid || result.ClaimsIdentity is null)
        {
            return null;
        }

        return new ClaimsPrincipal(result.ClaimsIdentity);
    }
}
