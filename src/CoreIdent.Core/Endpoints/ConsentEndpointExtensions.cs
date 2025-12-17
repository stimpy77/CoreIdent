using System.Net;
using System.Security.Claims;
using System.Text;
using CoreIdent.Core.Configuration;
using CoreIdent.Core.Extensions;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CoreIdent.Core.Endpoints;

public static class ConsentEndpointExtensions
{
    public static IEndpointRouteBuilder MapCoreIdentConsentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var routeOptions = endpoints.ServiceProvider.GetRequiredService<IOptions<CoreIdentRouteOptions>>().Value;
        var consentPath = routeOptions.CombineWithBase(routeOptions.ConsentPath);

        return endpoints.MapCoreIdentConsentEndpoints(consentPath);
    }

    public static IEndpointRouteBuilder MapCoreIdentConsentEndpoints(this IEndpointRouteBuilder endpoints, string consentPath)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(consentPath);

        endpoints.MapGet(consentPath, HandleGetConsent);
        endpoints.MapPost(consentPath, HandlePostConsent);
        return endpoints;
    }

    private static async Task<IResult> HandleGetConsent(
        HttpContext httpContext,
        IClientStore clientStore,
        ILoggerFactory loggerFactory,
        CancellationToken ct)
    {
        var logger = loggerFactory.CreateLogger("CoreIdent.ConsentEndpoint");
        using var logScope = CoreIdentCorrelation.BeginScope(logger, httpContext);

        if (httpContext.User?.Identity?.IsAuthenticated != true)
        {
            return Results.Challenge();
        }

        var query = httpContext.Request.Query;
        var clientId = query["client_id"].ToString();
        var redirectUri = query["redirect_uri"].ToString();
        var responseType = query["response_type"].ToString();
        var scope = query["scope"].ToString();
        var state = query["state"].ToString();
        var nonce = query["nonce"].ToString();
        var codeChallenge = query["code_challenge"].ToString();
        var codeChallengeMethod = query["code_challenge_method"].ToString();

        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(redirectUri))
        {
            return Results.BadRequest(new { error = "invalid_request", error_description = "client_id and redirect_uri are required." });
        }

        var client = await clientStore.FindByClientIdAsync(clientId, ct);
        if (client is null || !client.Enabled)
        {
            logger.LogWarning("Consent request for unknown or disabled client: {ClientId}", clientId);
            return Results.BadRequest(new { error = "invalid_client", error_description = "Unknown client." });
        }

        var scopes = ParseScopes(scope);

        var html = BuildConsentHtml(client.ClientName, clientId, redirectUri, responseType, scope, state, nonce, codeChallenge, codeChallengeMethod, scopes);

        return Results.Text(html, "text/html", Encoding.UTF8, statusCode: (int)HttpStatusCode.OK);
    }

    private static async Task<IResult> HandlePostConsent(
        HttpContext httpContext,
        IUserGrantStore userGrantStore,
        IOptions<CoreIdentRouteOptions> routeOptions,
        TimeProvider timeProvider,
        ILoggerFactory loggerFactory,
        CancellationToken ct)
    {
        var logger = loggerFactory.CreateLogger("CoreIdent.ConsentEndpoint");
        using var logScope = CoreIdentCorrelation.BeginScope(logger, httpContext);

        if (httpContext.User?.Identity?.IsAuthenticated != true)
        {
            return Results.Challenge();
        }

        if (!httpContext.Request.HasFormContentType)
        {
            return Results.BadRequest(new { error = "invalid_request", error_description = "Form content type is required." });
        }

        var form = await httpContext.Request.ReadFormAsync(ct);

        var decision = form["decision"].ToString();
        var clientId = form["client_id"].ToString();
        var redirectUri = form["redirect_uri"].ToString();
        var responseType = form["response_type"].ToString();
        var scope = form["scope"].ToString();
        var state = form["state"].ToString();
        var nonce = form["nonce"].ToString();
        var codeChallenge = form["code_challenge"].ToString();
        var codeChallengeMethod = form["code_challenge_method"].ToString();

        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(redirectUri))
        {
            return Results.BadRequest(new { error = "invalid_request", error_description = "client_id and redirect_uri are required." });
        }

        if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out _))
        {
            return Results.BadRequest(new { error = "invalid_request", error_description = "redirect_uri must be absolute." });
        }

        var subjectId = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? httpContext.User.FindFirstValue("sub");
        if (string.IsNullOrWhiteSpace(subjectId))
        {
            return Results.Forbid();
        }

        if (string.Equals(decision, "deny", StringComparison.OrdinalIgnoreCase))
        {
            var denyRedirect = AppendQueryParams(redirectUri, new Dictionary<string, string>
            {
                ["error"] = "access_denied",
                ["error_description"] = "The user denied the request.",
                ["state"] = state
            });

            return Results.Redirect(denyRedirect);
        }

        var scopes = ParseScopes(scope);

        await userGrantStore.SaveAsync(new CoreIdentUserGrant
        {
            SubjectId = subjectId,
            ClientId = clientId,
            Scopes = scopes,
            CreatedAt = timeProvider.GetUtcNow().UtcDateTime
        }, ct);

        var authorizePath = routeOptions.Value.CombineWithBase(routeOptions.Value.AuthorizePath);

        var authorizeRedirect = AppendQueryParams(authorizePath, new Dictionary<string, string>
        {
            ["client_id"] = clientId,
            ["redirect_uri"] = redirectUri,
            ["response_type"] = responseType,
            ["scope"] = scope,
            ["state"] = state,
            ["nonce"] = nonce,
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = codeChallengeMethod
        });

        return Results.Redirect(authorizeRedirect);
    }

    private static List<string> ParseScopes(string? scope)
    {
        if (string.IsNullOrWhiteSpace(scope))
        {
            return [];
        }

        return scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
    }

    private static string BuildConsentHtml(
        string clientName,
        string clientId,
        string redirectUri,
        string responseType,
        string scope,
        string state,
        string nonce,
        string codeChallenge,
        string codeChallengeMethod,
        IReadOnlyList<string> scopes)
    {
        var sb = new StringBuilder();

        sb.Append("<!doctype html><html><head><meta charset=\"utf-8\"><title>Consent</title></head><body>");
        sb.Append("<h1>Consent</h1>");
        sb.Append($"<p>Client: <strong>{WebUtility.HtmlEncode(clientName)}</strong></p>");

        if (scopes.Count > 0)
        {
            sb.Append("<p>Requested scopes:</p><ul>");
            foreach (var s in scopes)
            {
                sb.Append($"<li>{WebUtility.HtmlEncode(s)}</li>");
            }
            sb.Append("</ul>");
        }

        sb.Append("<form method=\"post\">");

        AppendHidden(sb, "client_id", clientId);
        AppendHidden(sb, "redirect_uri", redirectUri);
        AppendHidden(sb, "response_type", responseType);
        AppendHidden(sb, "scope", scope);
        AppendHidden(sb, "state", state);
        AppendHidden(sb, "nonce", nonce);
        AppendHidden(sb, "code_challenge", codeChallenge);
        AppendHidden(sb, "code_challenge_method", codeChallengeMethod);

        sb.Append("<button type=\"submit\" name=\"decision\" value=\"allow\">Allow</button>");
        sb.Append("<button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button>");
        sb.Append("</form>");

        sb.Append("</body></html>");

        return sb.ToString();
    }

    private static void AppendHidden(StringBuilder sb, string name, string value)
    {
        sb.Append($"<input type=\"hidden\" name=\"{WebUtility.HtmlEncode(name)}\" value=\"{WebUtility.HtmlEncode(value)}\" />");
    }

    private static string AppendQueryParams(string baseUri, IDictionary<string, string> parameters)
    {
        var query = new Dictionary<string, string>(StringComparer.Ordinal);

        string path;
        string existingQuery;

        if (Uri.TryCreate(baseUri, UriKind.Absolute, out var absolute))
        {
            path = absolute.GetLeftPart(UriPartial.Path);
            existingQuery = absolute.Query;
        }
        else
        {
            var parts = baseUri.Split('?', 2);
            path = parts[0];
            existingQuery = parts.Length == 2 ? "?" + parts[1] : string.Empty;
        }

        if (!string.IsNullOrWhiteSpace(existingQuery))
        {
            var trimmed = existingQuery.TrimStart('?');
            foreach (var pair in trimmed.Split('&', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var kvp = pair.Split('=', 2);
                if (kvp.Length == 2)
                {
                    query[Uri.UnescapeDataString(kvp[0])] = Uri.UnescapeDataString(kvp[1]);
                }
            }
        }

        foreach (var (k, v) in parameters)
        {
            if (!string.IsNullOrWhiteSpace(v))
            {
                query[k] = v;
            }
        }

        var q = string.Join("&", query.Select(kvp => $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value)}"));
        return string.IsNullOrWhiteSpace(q) ? path : $"{path}?{q}";
    }
}
