using System.Net.Mime;
using System.Security.Claims;
using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using CoreIdent.Passkeys.Configuration;
using CoreIdent.Passkeys.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace CoreIdent.Passkeys.AspNetIdentity.Endpoints;

public static class PasskeyEndpointsExtensions
{
    public static IEndpointRouteBuilder MapCoreIdentPasskeyEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var routeOptions = endpoints.ServiceProvider.GetRequiredService<IOptions<CoreIdentRouteOptions>>().Value;

        var registerOptionsPath = routeOptions.CombineWithBase(routeOptions.PasskeyRegisterOptionsPath);
        var registerCompletePath = routeOptions.CombineWithBase(routeOptions.PasskeyRegisterCompletePath);
        var authenticateOptionsPath = routeOptions.CombineWithBase(routeOptions.PasskeyAuthenticateOptionsPath);
        var authenticateCompletePath = routeOptions.CombineWithBase(routeOptions.PasskeyAuthenticateCompletePath);

        return endpoints.MapCoreIdentPasskeyEndpoints(
            registerOptionsPath,
            registerCompletePath,
            authenticateOptionsPath,
            authenticateCompletePath);
    }

    public static IEndpointRouteBuilder MapCoreIdentPasskeyEndpoints(
        this IEndpointRouteBuilder endpoints,
        string registerOptionsPath,
        string registerCompletePath,
        string authenticateOptionsPath,
        string authenticateCompletePath)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints.MapPost(registerOptionsPath, HandleRegisterOptionsAsync);
        endpoints.MapPost(registerCompletePath, HandleRegisterCompleteAsync);
        endpoints.MapPost(authenticateOptionsPath, HandleAuthenticateOptionsAsync);
        endpoints.MapPost(authenticateCompletePath, HandleAuthenticateCompleteAsync);

        return endpoints;
    }

    private static async Task<IResult> HandleRegisterOptionsAsync(
        HttpRequest request,
        IUserStore userStore,
        IPasskeyService passkeyService,
        ISigningKeyProvider signingKeyProvider,
        IOptions<CoreIdentOptions> coreOptions,
        CancellationToken ct)
    {
        var principal = await TryValidateBearerTokenAsync(request, signingKeyProvider, coreOptions.Value, ct);
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

        var optionsJson = await passkeyService.GetRegistrationOptionsJsonAsync(user, ct);
        return Results.Text(optionsJson, MediaTypeNames.Application.Json);
    }

    private sealed record RegisterCompleteRequest(string CredentialJson);

    private static async Task<IResult> HandleRegisterCompleteAsync(
        HttpRequest request,
        IUserStore userStore,
        IPasskeyService passkeyService,
        ISigningKeyProvider signingKeyProvider,
        IOptions<CoreIdentOptions> coreOptions,
        RegisterCompleteRequest body,
        CancellationToken ct)
    {
        var principal = await TryValidateBearerTokenAsync(request, signingKeyProvider, coreOptions.Value, ct);
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

        try
        {
            await passkeyService.CompleteRegistrationAsync(user, body.CredentialJson, ct);
            return Results.Ok(new { message = "Passkey registered" });
        }
        catch (InvalidOperationException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private sealed record AuthenticateOptionsRequest(string? Username);

    private static async Task<IResult> HandleAuthenticateOptionsAsync(
        IPasskeyService passkeyService,
        AuthenticateOptionsRequest body,
        CancellationToken ct)
    {
        var optionsJson = await passkeyService.GetAuthenticationOptionsJsonAsync(body.Username, ct);
        return Results.Text(optionsJson, MediaTypeNames.Application.Json);
    }

    private sealed record AuthenticateCompleteRequest(string CredentialJson);

    private static async Task<IResult> HandleAuthenticateCompleteAsync(
        HttpRequest request,
        IPasskeyService passkeyService,
        ITokenService tokenService,
        IRefreshTokenStore refreshTokenStore,
        ICustomClaimsProvider customClaimsProvider,
        IOptions<CoreIdentOptions> coreOptions,
        IOptions<CoreIdentPasskeyOptions> passkeyOptions,
        TimeProvider timeProvider,
        AuthenticateCompleteRequest body,
        CancellationToken ct)
    {
        var user = await passkeyService.AuthenticateAsync(body.CredentialJson, ct);
        if (user is null)
        {
            return Results.Unauthorized();
        }

        var options = coreOptions.Value;
        var passkeyClientId = passkeyOptions.Value.ClientId;
        var now = timeProvider.GetUtcNow();
        var accessTokenExpiresAt = now.Add(options.AccessTokenLifetime);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(ClaimTypes.NameIdentifier, user.Id),
            new(ClaimTypes.Email, user.UserName),
            new("client_id", passkeyClientId)
        };

        var claimsContext = new ClaimsContext
        {
            SubjectId = user.Id,
            ClientId = passkeyClientId,
            Scopes = [],
            GrantType = "passkey",
        };

        var customClaims = await customClaimsProvider.GetAccessTokenClaimsAsync(claimsContext, ct);
        claims.AddRange(customClaims);

        var accessToken = await tokenService.CreateJwtAsync(
            options.Issuer!,
            options.Audience!,
            claims,
            accessTokenExpiresAt,
            ct);

        var refreshTokenHandle = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
        var refreshToken = new CoreIdentRefreshToken
        {
            Handle = refreshTokenHandle,
            SubjectId = user.Id,
            ClientId = passkeyClientId,
            FamilyId = Guid.NewGuid().ToString("N"),
            Scopes = [],
            CreatedAt = now.UtcDateTime,
            ExpiresAt = now.Add(options.RefreshTokenLifetime).UtcDateTime
        };

        await refreshTokenStore.StoreAsync(refreshToken, ct);

        var tokenResponse = new TokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshTokenHandle,
            ExpiresIn = (int)options.AccessTokenLifetime.TotalSeconds,
            TokenType = "Bearer"
        };

        return Results.Ok(tokenResponse);
    }

    private static async Task<ClaimsPrincipal?> TryValidateBearerTokenAsync(
        HttpRequest request,
        ISigningKeyProvider signingKeyProvider,
        CoreIdentOptions options,
        CancellationToken ct)
    {
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
