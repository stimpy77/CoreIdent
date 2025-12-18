using System.Net.Mime;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
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

namespace CoreIdent.Core.Endpoints;

/// <summary>
/// Endpoint mapping for passwordless SMS authentication.
/// </summary>
public static class PasswordlessSmsEndpointsExtensions
{
    /// <summary>
    /// Maps passwordless SMS endpoints using route options resolved from DI.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <returns>The endpoint route builder.</returns>
    public static IEndpointRouteBuilder MapCoreIdentPasswordlessSmsEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var routeOptions = endpoints.ServiceProvider.GetRequiredService<IOptions<CoreIdentRouteOptions>>().Value;
        var startPath = routeOptions.CombineWithBase(routeOptions.PasswordlessSmsStartPath);
        var verifyPath = routeOptions.CombineWithBase(routeOptions.PasswordlessSmsVerifyPath);

        return endpoints.MapCoreIdentPasswordlessSmsEndpoints(startPath, verifyPath);
    }

    /// <summary>
    /// Maps passwordless SMS endpoints at the specified paths.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="startPath">Start endpoint path.</param>
    /// <param name="verifyPath">Verify endpoint path.</param>
    /// <returns>The endpoint route builder.</returns>
    public static IEndpointRouteBuilder MapCoreIdentPasswordlessSmsEndpoints(
        this IEndpointRouteBuilder endpoints,
        string startPath,
        string verifyPath)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(startPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(verifyPath);

        endpoints.MapPost(startPath, HandleStartAsync);
        endpoints.MapPost(verifyPath, HandleVerifyAsync);

        return endpoints;
    }

    private static async Task<IResult> HandleStartAsync(
        HttpContext httpContext,
        IPasswordlessTokenStore tokenStore,
        ISmsProvider smsProvider,
        TimeProvider timeProvider,
        ILoggerFactory loggerFactory,
        CancellationToken ct)
    {
        var logger = loggerFactory.CreateLogger("CoreIdent.Passwordless.Sms.Start");
        using var _ = CoreIdentCorrelation.BeginScope(logger, httpContext);

        var request = httpContext.Request;
        var (phoneNumber, messagePrefix) = await ReadStartRequestAsync(request, ct);

        phoneNumber = NormalizePhone(phoneNumber);
        if (string.IsNullOrWhiteSpace(phoneNumber) || !IsValidE164(phoneNumber))
        {
            return Results.Ok(new { message = "If the phone number exists, an OTP will be sent." });
        }

        try
        {
            var tokenModel = new PasswordlessToken
            {
                Recipient = phoneNumber,
                TokenType = PasswordlessTokenTypes.SmsOtp,
                CreatedAt = timeProvider.GetUtcNow().UtcDateTime
            };

            var otp = await tokenStore.CreateTokenAsync(tokenModel, ct);

            var message = string.IsNullOrWhiteSpace(messagePrefix)
                ? $"Your CoreIdent code is: {otp}"
                : $"{messagePrefix} {otp}";

            await smsProvider.SendAsync(phoneNumber, message, ct);
        }
        catch (PasswordlessRateLimitExceededException)
        {
            logger.LogWarning("Passwordless SMS rate limit exceeded for {Phone}", CoreIdentRedaction.MaskPhone(phoneNumber));
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to send passwordless SMS to {Phone}", CoreIdentRedaction.MaskPhone(phoneNumber));
        }

        return Results.Ok(new { message = "If the phone number exists, an OTP will be sent." });
    }

    private static async Task<IResult> HandleVerifyAsync(
        HttpContext httpContext,
        IPasswordlessTokenStore tokenStore,
        IUserStore userStore,
        ITokenService tokenService,
        IRefreshTokenStore refreshTokenStore,
        ICustomClaimsProvider customClaimsProvider,
        IOptions<CoreIdentOptions> coreOptions,
        TimeProvider timeProvider,
        ILoggerFactory loggerFactory,
        CancellationToken ct)
    {
        var logger = loggerFactory.CreateLogger("CoreIdent.Passwordless.Sms.Verify");
        using var _ = CoreIdentCorrelation.BeginScope(logger, httpContext);

        var request = httpContext.Request;
        var (phoneNumber, otp) = await ReadVerifyRequestAsync(request, ct);

        phoneNumber = NormalizePhone(phoneNumber);
        otp = (otp ?? string.Empty).Trim();

        if (string.IsNullOrWhiteSpace(phoneNumber) || !IsValidE164(phoneNumber) || string.IsNullOrWhiteSpace(otp))
        {
            return CreateErrorResult(request, StatusCodes.Status400BadRequest, "Invalid or expired token.");
        }

        var validated = await tokenStore.ValidateAndConsumeAsync(otp, PasswordlessTokenTypes.SmsOtp, phoneNumber, ct);
        if (validated is null)
        {
            return CreateErrorResult(request, StatusCodes.Status400BadRequest, "Invalid or expired token.");
        }

        // Use phone number as username for now (keeps user store surface minimal).
        var user = await userStore.FindByUsernameAsync(phoneNumber, ct);
        if (user is null)
        {
            user = new CoreIdentUser
            {
                UserName = phoneNumber,
                NormalizedUserName = phoneNumber.ToUpperInvariant(),
                CreatedAt = timeProvider.GetUtcNow().UtcDateTime
            };

            await userStore.CreateAsync(user, ct);
        }

        var options = coreOptions.Value;

        var now = timeProvider.GetUtcNow();
        var accessTokenExpiresAt = now.Add(options.AccessTokenLifetime);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(ClaimTypes.NameIdentifier, user.Id),
            new("phone_number", user.UserName),
            new("client_id", "passwordless_sms")
        };

        var userClaims = await userStore.GetClaimsAsync(user.Id, ct);
        claims.AddRange(userClaims);

        var claimsContext = new ClaimsContext
        {
            SubjectId = user.Id,
            ClientId = "passwordless_sms",
            Scopes = [],
            GrantType = "passwordless_sms"
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
            ClientId = "passwordless_sms",
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

        logger.LogInformation("Passwordless SMS verified for {UserId}", user.Id);

        if (WantsJson(request))
        {
            return Results.Ok(tokenResponse);
        }

        return Results.Text("<!doctype html><html><body><h1>Signed in</h1><p>Authentication successful.</p></body></html>", MediaTypeNames.Text.Html);
    }

    private static async Task<(string PhoneNumber, string? MessagePrefix)> ReadStartRequestAsync(HttpRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!string.IsNullOrWhiteSpace(request.ContentType) && request.ContentType.Contains("application/json", StringComparison.OrdinalIgnoreCase))
        {
            var body = await request.ReadFromJsonAsync<SmsStartRequest>(cancellationToken: ct);
            return (body?.PhoneNumber ?? string.Empty, body?.MessagePrefix);
        }

        if (request.HasFormContentType)
        {
            var form = await request.ReadFormAsync(ct);
            return (form["phone_number"].ToString(), form["message_prefix"].ToString());
        }

        return (string.Empty, null);
    }

    private static async Task<(string PhoneNumber, string Otp)> ReadVerifyRequestAsync(HttpRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!string.IsNullOrWhiteSpace(request.ContentType) && request.ContentType.Contains("application/json", StringComparison.OrdinalIgnoreCase))
        {
            var body = await request.ReadFromJsonAsync<SmsVerifyRequest>(cancellationToken: ct);
            return (body?.PhoneNumber ?? string.Empty, body?.Otp ?? string.Empty);
        }

        if (request.HasFormContentType)
        {
            var form = await request.ReadFormAsync(ct);
            return (form["phone_number"].ToString(), form["otp"].ToString());
        }

        return (string.Empty, string.Empty);
    }

    private static string NormalizePhone(string phone)
    {
        var value = (phone ?? string.Empty).Trim();

        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        value = value
            .Replace(" ", string.Empty, StringComparison.Ordinal)
            .Replace("-", string.Empty, StringComparison.Ordinal)
            .Replace("(", string.Empty, StringComparison.Ordinal)
            .Replace(")", string.Empty, StringComparison.Ordinal);

        if (value.StartsWith("00", StringComparison.Ordinal))
        {
            value = "+" + value[2..];
        }

        return value;
    }

    private static bool IsValidE164(string phone)
    {
        return Regex.IsMatch(phone, "^\\+[1-9]\\d{7,14}$", RegexOptions.CultureInvariant);
    }

    private static bool WantsJson(HttpRequest request)
    {
        var accept = request.Headers.Accept.ToString();
        return !string.IsNullOrWhiteSpace(accept) && accept.Contains("application/json", StringComparison.OrdinalIgnoreCase);
    }

    private static IResult CreateErrorResult(HttpRequest request, int statusCode, string message)
    {
        var accept = request.Headers.Accept.ToString();
        var wantsJson = !string.IsNullOrWhiteSpace(accept) && accept.Contains("application/json", StringComparison.OrdinalIgnoreCase);

        if (wantsJson)
        {
            var (errorCode, title) = statusCode switch
            {
                StatusCodes.Status401Unauthorized => ("unauthorized", "Unauthorized"),
                StatusCodes.Status403Forbidden => ("forbidden", "Forbidden"),
                _ => ("invalid_request", "Invalid request")
            };

            return CoreIdentProblemDetails.Create(request, statusCode, errorCode, title, message);
        }

        var escaped = HtmlEncoder.Default.Encode(message);
        return Results.Text($"<!doctype html><html><body><h1>Error</h1><p>{escaped}</p></body></html>", MediaTypeNames.Text.Html, statusCode: statusCode);
    }

    private static string GenerateRefreshTokenHandle()
    {
        return Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
    }

    private sealed record SmsStartRequest(
        [property: JsonPropertyName("phone_number")] string PhoneNumber,
        [property: JsonPropertyName("message_prefix")] string? MessagePrefix);

    private sealed record SmsVerifyRequest(
        [property: JsonPropertyName("phone_number")] string PhoneNumber,
        [property: JsonPropertyName("otp")] string Otp);
}
