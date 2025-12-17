using System.Security.Claims;
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

public static class AuthorizationEndpointExtensions
{
    private const string ResponseTypeCode = "code";
    private const string PkceMethodS256 = "S256";

    public static IEndpointRouteBuilder MapCoreIdentAuthorizeEndpoint(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var routeOptions = endpoints.ServiceProvider.GetRequiredService<IOptions<CoreIdentRouteOptions>>().Value;
        var authorizePath = routeOptions.CombineWithBase(routeOptions.AuthorizePath);

        return endpoints.MapCoreIdentAuthorizeEndpoint(authorizePath);
    }

    public static IEndpointRouteBuilder MapCoreIdentAuthorizeEndpoint(this IEndpointRouteBuilder endpoints, string authorizePath)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(authorizePath);

        endpoints.MapGet(authorizePath, HandleAuthorizeRequest);
        return endpoints;
    }

    private static async Task<IResult> HandleAuthorizeRequest(
        HttpContext httpContext,
        IClientStore clientStore,
        IScopeStore scopeStore,
        IAuthorizationCodeStore authorizationCodeStore,
        IUserGrantStore userGrantStore,
        IOptions<CoreIdentAuthorizationCodeOptions> authorizationCodeOptions,
        IOptions<CoreIdentRouteOptions> routeOptions,
        ILoggerFactory loggerFactory,
        TimeProvider timeProvider,
        CancellationToken ct)
    {
        var logger = loggerFactory.CreateLogger("CoreIdent.AuthorizeEndpoint");
        using var _ = CoreIdentCorrelation.BeginScope(logger, httpContext);

        var request = httpContext.Request;
        var query = request.Query;

        var clientId = query["client_id"].ToString();
        var redirectUri = query["redirect_uri"].ToString();
        var responseType = query["response_type"].ToString();
        var scope = query["scope"].ToString();
        var state = query["state"].ToString();
        var nonce = query["nonce"].ToString();
        var codeChallenge = query["code_challenge"].ToString();
        var codeChallengeMethod = query["code_challenge_method"].ToString();

        if (string.IsNullOrWhiteSpace(clientId))
        {
            return Results.BadRequest(new { error = "invalid_request", error_description = "client_id is required." });
        }

        if (string.IsNullOrWhiteSpace(redirectUri))
        {
            return Results.BadRequest(new { error = "invalid_request", error_description = "redirect_uri is required." });
        }

        if (!string.Equals(responseType, ResponseTypeCode, StringComparison.Ordinal))
        {
            return RedirectErrorOrBadRequest(redirectUri, state, "unsupported_response_type", "response_type must be 'code'.");
        }

        if (string.IsNullOrWhiteSpace(state))
        {
            return RedirectErrorOrBadRequest(redirectUri, state: null, "invalid_request", "state is required.");
        }

        if (string.IsNullOrWhiteSpace(codeChallenge) || string.IsNullOrWhiteSpace(codeChallengeMethod))
        {
            return RedirectErrorOrBadRequest(redirectUri, state, "invalid_request", "PKCE is required (code_challenge and code_challenge_method)." );
        }

        if (!string.Equals(codeChallengeMethod, PkceMethodS256, StringComparison.Ordinal))
        {
            return RedirectErrorOrBadRequest(redirectUri, state, "invalid_request", "code_challenge_method must be S256." );
        }

        var client = await clientStore.FindByClientIdAsync(clientId, ct);
        if (client is null || !client.Enabled)
        {
            logger.LogWarning("Authorize request for unknown or disabled client: {ClientId}", clientId);
            return Results.BadRequest(new { error = "invalid_client", error_description = "Unknown client." });
        }

        if (!client.AllowedGrantTypes.Contains(GrantTypes.AuthorizationCode))
        {
            return RedirectErrorOrBadRequest(redirectUri, state, "unauthorized_client", "Client is not authorized for authorization_code flow.");
        }

        if (!client.RedirectUris.Contains(redirectUri, StringComparer.Ordinal))
        {
            return Results.BadRequest(new { error = "invalid_request", error_description = "redirect_uri is not registered for this client." });
        }

        var requestedScopes = ParseScopes(scope);
        var grantedScopes = requestedScopes.Count == 0
            ? client.AllowedScopes.ToList()
            : requestedScopes.Where(s => client.AllowedScopes.Contains(s)).ToList();

        if (requestedScopes.Count > 0 && grantedScopes.Count == 0)
        {
            return RedirectErrorOrBadRequest(redirectUri, state, "invalid_scope", "None of the requested scopes are allowed for this client.");
        }

        // Validate scopes exist in store (when present)
        if (grantedScopes.Count > 0)
        {
            var knownScopes = (await scopeStore.FindByScopesAsync(grantedScopes, ct)).Select(s => s.Name).ToHashSet(StringComparer.Ordinal);
            var unknown = grantedScopes.Where(s => !knownScopes.Contains(s)).ToList();
            if (unknown.Count > 0)
            {
                return RedirectErrorOrBadRequest(redirectUri, state, "invalid_scope", "One or more requested scopes are not recognized.");
            }
        }

        if (httpContext.User?.Identity?.IsAuthenticated != true)
        {
            return Results.Challenge();
        }

        var subjectId = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? httpContext.User.FindFirstValue("sub");
        if (string.IsNullOrWhiteSpace(subjectId))
        {
            return Results.Forbid();
        }

        if (client.RequireConsent)
        {
            var hasConsent = await userGrantStore.HasUserGrantedConsentAsync(subjectId, client.ClientId, grantedScopes, ct);
            if (!hasConsent)
            {
                var consentPath = routeOptions.Value.CombineWithBase(routeOptions.Value.ConsentPath);
                var consentRedirect = AppendQueryParams(consentPath, new Dictionary<string, string>
                {
                    ["client_id"] = client.ClientId,
                    ["redirect_uri"] = redirectUri,
                    ["response_type"] = responseType,
                    ["scope"] = scope,
                    ["state"] = state,
                    ["nonce"] = nonce,
                    ["code_challenge"] = codeChallenge,
                    ["code_challenge_method"] = codeChallengeMethod
                });

                return Results.Redirect(consentRedirect);
            }
        }

        var now = timeProvider.GetUtcNow().UtcDateTime;
        var codeLifetime = authorizationCodeOptions.Value.CodeLifetime;

        var code = new CoreIdentAuthorizationCode
        {
            Handle = string.Empty,
            ClientId = client.ClientId,
            SubjectId = subjectId,
            RedirectUri = redirectUri,
            Scopes = grantedScopes,
            CreatedAt = now,
            ExpiresAt = now.Add(codeLifetime),
            Nonce = string.IsNullOrWhiteSpace(nonce) ? null : nonce,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod
        };

        await authorizationCodeStore.CreateAsync(code, ct);

        var redirect = AppendQueryParams(redirectUri, new Dictionary<string, string>
        {
            ["code"] = code.Handle,
            ["state"] = state
        });

        return Results.Redirect(redirect);
    }

    private static IResult RedirectErrorOrBadRequest(string redirectUri, string? state, string error, string description)
    {
        if (Uri.TryCreate(redirectUri, UriKind.Absolute, out _))
        {
            var location = AppendQueryParams(redirectUri, new Dictionary<string, string>
            {
                ["error"] = error,
                ["error_description"] = description,
                ["state"] = state ?? string.Empty
            });

            return Results.Redirect(location);
        }

        return Results.BadRequest(new { error, error_description = description });
    }

    private static List<string> ParseScopes(string? scope)
    {
        if (string.IsNullOrWhiteSpace(scope))
        {
            return [];
        }

        return scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
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
            query[k] = v;
        }

        var q = string.Join("&", query.Select(kvp => $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value)}"));
        return string.IsNullOrWhiteSpace(q) ? path : $"{path}?{q}";
    }
}
