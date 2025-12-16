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
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;

namespace CoreIdent.Core.Endpoints;

public static class PasswordlessEmailEndpointsExtensions
{
    public static IEndpointRouteBuilder MapCoreIdentPasswordlessEmailEndpoints(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapCoreIdentPasswordlessEmailEndpoints(
            "/auth/passwordless/email/start",
            "/auth/passwordless/email/verify");
    }

    public static IEndpointRouteBuilder MapCoreIdentPasswordlessEmailEndpoints(
        this IEndpointRouteBuilder endpoints,
        string startPath,
        string verifyPath)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(startPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(verifyPath);

        endpoints.MapPost(startPath, HandleStartAsync);
        endpoints.MapGet(verifyPath, HandleVerifyAsync);

        return endpoints;
    }

    private static async Task<IResult> HandleStartAsync(
        HttpContext httpContext,
        IPasswordlessTokenStore tokenStore,
        IEmailSender emailSender,
        PasswordlessEmailTemplateRenderer templateRenderer,
        IOptions<PasswordlessEmailOptions> options,
        IOptions<CoreIdentRouteOptions> routeOptions,
        IHostEnvironment environment,
        ILoggerFactory loggerFactory,
        CancellationToken ct)
    {
        var logger = loggerFactory.CreateLogger("CoreIdent.Passwordless.Email.Start");

        var request = httpContext.Request;
        var email = await ReadEmailAsync(request, ct);

        if (!TryValidateEmail(email, out var normalizedEmail))
        {
            return Results.Ok(new { message = "If the email exists, a sign-in link will be sent." });
        }

        try
        {
            var tokenModel = new PasswordlessToken
            {
                Recipient = normalizedEmail,
                TokenType = PasswordlessTokenTypes.EmailMagicLink,
                CreatedAt = DateTime.UtcNow
            };

            var rawToken = await tokenStore.CreateTokenAsync(tokenModel, ct);

            var verifyUrl = BuildVerifyUrl(httpContext, options.Value, routeOptions.Value, rawToken);

            var html = await templateRenderer.RenderAsync(normalizedEmail, verifyUrl, ct);
            var subject = options.Value.EmailSubject.Replace("{AppName}", environment.ApplicationName, StringComparison.Ordinal);

            await emailSender.SendAsync(new EmailMessage(normalizedEmail, subject, html), ct);
        }
        catch (PasswordlessRateLimitExceededException)
        {
            logger.LogWarning("Passwordless email rate limit exceeded for {Email}", normalizedEmail);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to send passwordless email to {Email}", normalizedEmail);
        }

        return Results.Ok(new { message = "If the email exists, a sign-in link will be sent." });
    }

    private static async Task<IResult> HandleVerifyAsync(
        HttpContext httpContext,
        IPasswordlessTokenStore tokenStore,
        IUserStore userStore,
        ITokenService tokenService,
        IRefreshTokenStore refreshTokenStore,
        ICustomClaimsProvider customClaimsProvider,
        IOptions<CoreIdentOptions> coreOptions,
        IOptions<PasswordlessEmailOptions> emailOptions,
        TimeProvider timeProvider,
        ILoggerFactory loggerFactory,
        CancellationToken ct)
    {
        var logger = loggerFactory.CreateLogger("CoreIdent.Passwordless.Email.Verify");

        var request = httpContext.Request;
        var token = request.Query["token"].ToString();

        var validated = await tokenStore.ValidateAndConsumeAsync(token, PasswordlessTokenTypes.EmailMagicLink, recipient: null, ct);
        if (validated is null)
        {
            return CreateErrorResult(request, StatusCodes.Status400BadRequest, "Invalid or expired token.");
        }

        var email = validated.Recipient;
        if (!TryValidateEmail(email, out var normalizedEmail))
        {
            return CreateErrorResult(request, StatusCodes.Status400BadRequest, "Invalid token.");
        }

        var user = await userStore.FindByUsernameAsync(normalizedEmail, ct);
        if (user is null)
        {
            user = new CoreIdentUser
            {
                UserName = normalizedEmail,
                NormalizedUserName = normalizedEmail.ToUpperInvariant(),
                CreatedAt = DateTime.UtcNow
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
            new(ClaimTypes.Email, user.UserName),
            new("client_id", "passwordless_email")
        };

        var userClaims = await userStore.GetClaimsAsync(user.Id, ct);
        claims.AddRange(userClaims);

        var claimsContext = new ClaimsContext
        {
            SubjectId = user.Id,
            ClientId = "passwordless_email",
            Scopes = [],
            GrantType = "passwordless_email"
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
            ClientId = "passwordless_email",
            FamilyId = Guid.NewGuid().ToString("N"),
            Scopes = [],
            CreatedAt = now.UtcDateTime,
            ExpiresAt = now.Add(options.RefreshTokenLifetime).UtcDateTime
        };

        await refreshTokenStore.StoreAsync(refreshToken, ct);

        var successRedirect = emailOptions.Value.SuccessRedirectUrl;
        if (!string.IsNullOrWhiteSpace(successRedirect))
        {
            var separator = successRedirect.Contains('?', StringComparison.Ordinal) ? '&' : '?';
            var url = $"{successRedirect}{separator}access_token={Uri.EscapeDataString(accessToken)}&refresh_token={Uri.EscapeDataString(refreshTokenHandle)}&token_type=Bearer&expires_in={(int)options.AccessTokenLifetime.TotalSeconds}";
            return Results.Redirect(url);
        }

        logger.LogInformation("Passwordless email verified for {UserId}", user.Id);

        return Results.Text("<!doctype html><html><body><h1>Signed in</h1><p>Authentication successful.</p></body></html>", MediaTypeNames.Text.Html);
    }

    private static string BuildVerifyUrl(HttpContext httpContext, PasswordlessEmailOptions options, CoreIdentRouteOptions routes, string token)
    {
        var verify = options.VerifyEndpointUrl;
        if (string.IsNullOrWhiteSpace(verify))
        {
            verify = "passwordless/email/verify";
        }

        if (!verify.StartsWith("http", StringComparison.OrdinalIgnoreCase))
        {
            if (!verify.StartsWith("/", StringComparison.Ordinal))
            {
                verify = routes.CombineWithBase(verify);
            }

            verify = $"{httpContext.Request.Scheme}://{httpContext.Request.Host}{verify}";
        }

        var separator = verify.Contains('?', StringComparison.Ordinal) ? '&' : '?';
        return $"{verify}{separator}token={Uri.EscapeDataString(token)}";
    }

    private static async Task<string> ReadEmailAsync(HttpRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!string.IsNullOrWhiteSpace(request.ContentType) && request.ContentType.Contains("application/json", StringComparison.OrdinalIgnoreCase))
        {
            var body = await request.ReadFromJsonAsync<EmailRequest>(cancellationToken: ct);
            return body?.Email ?? string.Empty;
        }

        if (request.HasFormContentType)
        {
            var form = await request.ReadFormAsync(ct);
            return form["email"].ToString();
        }

        return string.Empty;
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

    private static IResult CreateErrorResult(HttpRequest request, int statusCode, string message)
    {
        var accept = request.Headers.Accept.ToString();
        var wantsJson = !string.IsNullOrWhiteSpace(accept) && accept.Contains("application/json", StringComparison.OrdinalIgnoreCase);

        if (wantsJson)
        {
            return Results.Json(new { error = message }, statusCode: statusCode);
        }

        var escaped = HtmlEncoder.Default.Encode(message);
        return Results.Text($"<!doctype html><html><body><h1>Error</h1><p>{escaped}</p></body></html>", MediaTypeNames.Text.Html, statusCode: statusCode);
    }

    private static string GenerateRefreshTokenHandle()
    {
        return Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
    }

    private sealed record EmailRequest(string Email);
}
