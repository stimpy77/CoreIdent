using System.Net.Mime;
using System.Security.Claims;
using System.Text.Encodings.Web;
using CoreIdent.Core.Configuration;
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

public static class ResourceOwnerEndpointsExtensions
{
    public static IEndpointRouteBuilder MapCoreIdentResourceOwnerEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var routeOptions = endpoints.ServiceProvider.GetRequiredService<IOptions<CoreIdentRouteOptions>>().Value;

        var registerPath = routeOptions.CombineWithBase(routeOptions.RegisterPath);
        var loginPath = routeOptions.CombineWithBase(routeOptions.LoginPath);
        var profilePath = routeOptions.CombineWithBase(routeOptions.ProfilePath);

        return endpoints.MapCoreIdentResourceOwnerEndpoints(registerPath, loginPath, profilePath);
    }

    public static IEndpointRouteBuilder MapCoreIdentResourceOwnerEndpoints(
        this IEndpointRouteBuilder endpoints,
        string registerPath,
        string loginPath,
        string profilePath)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(registerPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(loginPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(profilePath);

        endpoints.MapGet(registerPath, static () =>
            Results.Text(BuildRegisterFormHtml(), MediaTypeNames.Text.Html));

        endpoints.MapPost(registerPath, HandleRegisterAsync);

        endpoints.MapGet(loginPath, static () =>
            Results.Text(BuildLoginFormHtml(), MediaTypeNames.Text.Html));

        endpoints.MapPost(loginPath, HandleLoginAsync);

        endpoints.MapGet(profilePath, HandleProfileAsync);

        return endpoints;
    }

    private static async Task<IResult> HandleRegisterAsync(
        HttpContext httpContext,
        IUserStore userStore,
        IPasswordHasher passwordHasher,
        IOptions<CoreIdentResourceOwnerOptions> resourceOwnerOptions,
        TimeProvider timeProvider,
        ILoggerFactory loggerFactory,
        CancellationToken ct)
    {
        var logger = loggerFactory.CreateLogger("CoreIdent.ResourceOwner.Register");

        var request = httpContext.Request;

        var (email, password) = await ReadEmailAndPasswordAsync(request, ct);

        if (!TryValidateEmail(email, out var normalizedEmail))
        {
            return CreateErrorResult(request, statusCode: StatusCodes.Status400BadRequest, message: "Invalid email.");
        }

        if (!TryValidatePassword(password))
        {
            return CreateErrorResult(request, statusCode: StatusCodes.Status400BadRequest, message: "Invalid password.");
        }

        var existing = await userStore.FindByUsernameAsync(normalizedEmail, ct);
        if (existing is not null)
        {
            return CreateErrorResult(request, statusCode: StatusCodes.Status400BadRequest, message: "User already exists.");
        }

        var user = new CoreIdentUser
        {
            UserName = normalizedEmail,
            NormalizedUserName = normalizedEmail.ToUpperInvariant(),
            CreatedAt = timeProvider.GetUtcNow().UtcDateTime
        };

        user.PasswordHash = passwordHasher.HashPassword(user, password);

        await userStore.CreateAsync(user, ct);

        logger.LogInformation("User registered: {UserId}", user.Id);

        var handler = resourceOwnerOptions.Value.RegisterHandler;
        if (handler is not null)
        {
            var overridden = await handler(httpContext, user, ct);
            if (overridden is not null)
            {
                return overridden;
            }
        }

        if (WantsJson(request))
        {
            return Results.Json(new { userId = user.Id, message = "Registered successfully" });
        }

        var escapedId = HtmlEncoder.Default.Encode(user.Id);
        return Results.Text($"<!doctype html><html><body><h1>Registered</h1><p>User ID: {escapedId}</p></body></html>", MediaTypeNames.Text.Html);
    }

    private static async Task<IResult> HandleLoginAsync(
        HttpContext httpContext,
        IUserStore userStore,
        IPasswordHasher passwordHasher,
        ITokenService tokenService,
        IRefreshTokenStore refreshTokenStore,
        ICustomClaimsProvider customClaimsProvider,
        IOptions<CoreIdentOptions> coreOptions,
        IOptions<CoreIdentResourceOwnerOptions> resourceOwnerOptions,
        TimeProvider timeProvider,
        ILoggerFactory loggerFactory,
        CancellationToken ct)
    {
        var logger = loggerFactory.CreateLogger("CoreIdent.ResourceOwner.Login");

        var request = httpContext.Request;

        var (email, password) = await ReadEmailAndPasswordAsync(request, ct);

        if (!TryValidateEmail(email, out var normalizedEmail) || !TryValidatePassword(password))
        {
            return CreateErrorResult(request, statusCode: StatusCodes.Status400BadRequest, message: "Invalid credentials.");
        }

        var user = await userStore.FindByUsernameAsync(normalizedEmail, ct);
        if (user is null)
        {
            return CreateErrorResult(request, statusCode: StatusCodes.Status401Unauthorized, message: "Invalid credentials.");
        }

        if (string.IsNullOrWhiteSpace(user.PasswordHash) || !passwordHasher.VerifyHashedPassword(user, user.PasswordHash, password))
        {
            return CreateErrorResult(request, statusCode: StatusCodes.Status401Unauthorized, message: "Invalid credentials.");
        }

        var options = coreOptions.Value;

        var now = timeProvider.GetUtcNow();
        var accessTokenExpiresAt = now.Add(options.AccessTokenLifetime);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(ClaimTypes.NameIdentifier, user.Id),
            new(ClaimTypes.Email, user.UserName),
            new("client_id", "resource_owner")
        };

        var userClaims = await userStore.GetClaimsAsync(user.Id, ct);
        claims.AddRange(userClaims);

        var claimsContext = new ClaimsContext
        {
            SubjectId = user.Id,
            ClientId = "resource_owner",
            Scopes = [],
            GrantType = GrantTypes.Password
        };

        var customClaims = await customClaimsProvider.GetAccessTokenClaimsAsync(claimsContext, ct);
        claims.AddRange(customClaims);

        var accessToken = await tokenService.CreateJwtAsync(
            options.Issuer!,
            options.Audience!,
            claims,
            accessTokenExpiresAt,
            ct);

        var refreshTokenHandle = GenerateRefreshTokenHandle();
        var refreshToken = new CoreIdentRefreshToken
        {
            Handle = refreshTokenHandle,
            SubjectId = user.Id,
            ClientId = "resource_owner",
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

        logger.LogInformation("User login succeeded: {UserId}", user.Id);

        var handler = resourceOwnerOptions.Value.LoginHandler;
        if (handler is not null)
        {
            var overridden = await handler(httpContext, user, tokenResponse, ct);
            if (overridden is not null)
            {
                return overridden;
            }
        }

        if (WantsJson(request))
        {
            return Results.Ok(tokenResponse);
        }

        var redirectUri = request.Query["redirect_uri"].ToString();
        if (!string.IsNullOrWhiteSpace(redirectUri))
        {
            return Results.Redirect(redirectUri);
        }

        return Results.Text("<!doctype html><html><body><h1>Logged in</h1><p>Login successful.</p></body></html>", MediaTypeNames.Text.Html);
    }

    private static async Task<IResult> HandleProfileAsync(
        HttpContext httpContext,
        IUserStore userStore,
        ISigningKeyProvider signingKeyProvider,
        IOptions<CoreIdentOptions> coreOptions,
        IOptions<CoreIdentResourceOwnerOptions> resourceOwnerOptions,
        ILoggerFactory loggerFactory,
        CancellationToken ct)
    {
        var logger = loggerFactory.CreateLogger("CoreIdent.ResourceOwner.Profile");

        var request = httpContext.Request;

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

        var claims = await userStore.GetClaimsAsync(user.Id, ct);

        var handler = resourceOwnerOptions.Value.ProfileHandler;
        if (handler is not null)
        {
            var overridden = await handler(httpContext, user, claims, ct);
            if (overridden is not null)
            {
                return overridden;
            }
        }

        if (WantsJson(request))
        {
            return Results.Json(new
            {
                id = user.Id,
                email = user.UserName,
                claims = claims.ToDictionary(c => c.Type, c => c.Value)
            });
        }

        var escapedEmail = HtmlEncoder.Default.Encode(user.UserName);
        return Results.Text($"<!doctype html><html><body><h1>Profile</h1><p>{escapedEmail}</p></body></html>", MediaTypeNames.Text.Html);
    }

    private static bool WantsJson(HttpRequest request)
    {
        if (request is null)
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(request.ContentType) && request.ContentType.Contains("application/json", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var accept = request.Headers.Accept.ToString();
        return !string.IsNullOrWhiteSpace(accept) && accept.Contains("application/json", StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<(string Email, string Password)> ReadEmailAndPasswordAsync(HttpRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!string.IsNullOrWhiteSpace(request.ContentType) && request.ContentType.Contains("application/json", StringComparison.OrdinalIgnoreCase))
        {
            var body = await request.ReadFromJsonAsync<EmailPasswordRequest>(cancellationToken: ct);
            return (body?.Email ?? string.Empty, body?.Password ?? string.Empty);
        }

        if (request.HasFormContentType)
        {
            var form = await request.ReadFormAsync(ct);
            return (form["email"].ToString(), form["password"].ToString());
        }

        return (string.Empty, string.Empty);
    }

    private static bool TryValidateEmail(string email, out string normalized)
    {
        normalized = email?.Trim() ?? string.Empty;

        if (string.IsNullOrWhiteSpace(normalized))
        {
            return false;
        }

        try
        {
            _ = new System.Net.Mail.MailAddress(normalized);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryValidatePassword(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            return false;
        }

        return password.Trim().Length >= 6;
    }

    private static IResult CreateErrorResult(HttpRequest request, int statusCode, string message)
    {
        if (WantsJson(request))
        {
            return Results.Json(new { error = message }, statusCode: statusCode);
        }

        var escaped = HtmlEncoder.Default.Encode(message);
        return Results.Text($"<!doctype html><html><body><h1>Error</h1><p>{escaped}</p></body></html>", MediaTypeNames.Text.Html, statusCode: statusCode);
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

    private static string GenerateRefreshTokenHandle()
    {
        return Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
    }

    private static string BuildRegisterFormHtml()
    {
        return "<!doctype html><html><body><h1>Register</h1><form method=\"post\"><label>Email <input name=\"email\" type=\"email\" required></label><br/><label>Password <input name=\"password\" type=\"password\" required></label><br/><button type=\"submit\">Register</button></form></body></html>";
    }

    private static string BuildLoginFormHtml()
    {
        return "<!doctype html><html><body><h1>Login</h1><form method=\"post\"><label>Email <input name=\"email\" type=\"email\" required></label><br/><label>Password <input name=\"password\" type=\"password\" required></label><br/><button type=\"submit\">Login</button></form></body></html>";
    }

    private sealed record EmailPasswordRequest(string Email, string Password);
}
