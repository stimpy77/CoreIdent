using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Models.Requests;
using CoreIdent.Core.Stores;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

namespace CoreIdent.Core.Extensions
{
    /// <summary>
    /// Extension methods for mapping OAuth2 and consent endpoints.
    /// </summary>
    public static class OAuthEndpointsExtensions
    {
        public static void MapOAuthEndpoints(this IEndpointRouteBuilder endpoints, CoreIdentRouteOptions routeOptions)
        {
            // --- /authorize endpoint (Authorization Code Flow + PKCE) ---
            endpoints.MapGet(routeOptions.AuthorizePath, async (
                HttpRequest request,
                HttpResponse response,
                HttpContext httpContext,
                IClientStore clientStore,
                IScopeStore scopeStore,
                ILoggerFactory loggerFactory,
                CancellationToken cancellationToken
                ) =>
            {
                var logger = loggerFactory.CreateLogger("CoreIdent.Authorize");
                logger.LogInformation("Authorize endpoint hit: {Query}", request.QueryString);

                // Log request headers to check for Cookie
                var cookieHeader = request.Headers["Cookie"].ToString();
                logger.LogInformation("[AUTHORIZE DEBUG] Request Cookie Header: {CookieHeader}",
                     string.IsNullOrWhiteSpace(cookieHeader) ? "<Not Present>" : cookieHeader);

                // 1. Parse and Validate Request Parameters
                string? clientId = request.Query["client_id"];
                string? redirectUri = request.Query["redirect_uri"];
                string? responseType = request.Query["response_type"];
                string? scope = request.Query["scope"];
                string? state = request.Query["state"];
                string? codeChallenge = request.Query["code_challenge"];
                string? codeChallengeMethod = request.Query["code_challenge_method"];
                string? nonce = request.Query["nonce"];

                if (string.IsNullOrWhiteSpace(clientId) ||
                    string.IsNullOrWhiteSpace(redirectUri) ||
                    string.IsNullOrWhiteSpace(responseType) ||
                    string.IsNullOrWhiteSpace(scope))
                {
                    logger.LogWarning("Authorize request missing required parameters.");
                    return Results.BadRequest(new { error = "invalid_request", error_description = "Missing required parameters (client_id, redirect_uri, response_type, scope)." });
                }

                if (responseType != "code")
                {
                    logger.LogWarning("Authorize request has unsupported response_type: {ResponseType}", responseType);
                    return Results.BadRequest(new { error = "unsupported_response_type", error_description = "Only 'code' response_type is supported." });
                }

                if (!string.IsNullOrWhiteSpace(codeChallenge) && string.IsNullOrWhiteSpace(codeChallengeMethod))
                {
                    logger.LogWarning("Authorize request has code_challenge but missing code_challenge_method.");
                    return Results.BadRequest(new { error = "invalid_request", error_description = "code_challenge_method is required when code_challenge is provided." });
                }
                if (!string.IsNullOrWhiteSpace(codeChallengeMethod) && codeChallengeMethod != "S256")
                {
                    logger.LogWarning("Authorize request uses unsupported code_challenge_method: {Method}", codeChallengeMethod);
                    return Results.BadRequest(new { error = "invalid_request", error_description = "Only 'S256' code_challenge_method is supported." });
                }

                CoreIdentClient? client;
                try
                {
                    client = await clientStore.FindClientByIdAsync(clientId, cancellationToken);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error retrieving client {ClientId} during authorization.", clientId);
                    return Results.Problem("An unexpected error occurred during client validation.", statusCode: StatusCodes.Status500InternalServerError);
                }

                if (client == null || !client.Enabled)
                {
                    logger.LogWarning("Authorize request for unknown or disabled client: {ClientId}", clientId);
                    return Results.BadRequest(new { error = "unauthorized_client", error_description = "Client is unknown or disabled." });
                }

                if (!client.RedirectUris.Contains(redirectUri))
                {
                    logger.LogWarning("Authorize request for client {ClientId} with invalid redirect_uri: {RedirectUri}", clientId, redirectUri);
                    return Results.BadRequest(new { error = "invalid_request", error_description = "Invalid redirect_uri." });
                }

                var requestedScopes = scope?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? Enumerable.Empty<string>();
                IEnumerable<CoreIdentScope> validScopes;
                try
                {
                    validScopes = await scopeStore.FindScopesByNameAsync(requestedScopes, cancellationToken);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error retrieving scopes during authorization for client {ClientId}. Scopes: {Scopes}", clientId, scope);
                    return Results.Problem("An unexpected error occurred during scope validation.", statusCode: StatusCodes.Status500InternalServerError);
                }

                var isAuthenticated = httpContext.User?.Identity?.IsAuthenticated ?? false;
                logger.LogInformation("User authenticated: {IsAuthenticated}, Claims: {Claims}",
                    isAuthenticated,
                    string.Join(", ", httpContext.User?.Claims.Select(c => $"{c.Type}={c.Value}") ?? Array.Empty<string>()));

                if (!isAuthenticated)
                {
                    logger.LogInformation("User not authenticated for authorize request. Redirecting to login.");
                    var returnUrl = Uri.EscapeDataString(Microsoft.AspNetCore.Http.Extensions.UriHelper.GetEncodedUrl(request));
                    var loginUrl = routeOptions.Combine(routeOptions.LoginPath) + "?ReturnUrl=" + returnUrl;
                    return Results.Redirect(loginUrl);
                }

                if (isAuthenticated)
                {
                    bool requireConsent = client.RequireConsent;
                    var subject = httpContext.User?.FindFirstValue(System.Security.Claims.ClaimTypes.NameIdentifier)
                        ?? httpContext.User?.FindFirstValue(System.Security.Claims.ClaimTypes.Name)
                        ?? httpContext.User?.Identity?.Name;

                    if (string.IsNullOrEmpty(subject))
                    {
                        logger.LogWarning("Authenticated user has no subject identifier (NameIdentifier or Name)");
                        return Results.Unauthorized();
                    }

                    var userGrantStore = httpContext.RequestServices.GetRequiredService<IUserGrantStore>();
                    var existingGrant = await userGrantStore.FindAsync(subject, clientId, cancellationToken);

                    logger.LogInformation("[AUTHORIZE DEBUG] Consent lookup subject: {Subject}", subject);
                    if (existingGrant != null)
                    {
                        logger.LogInformation("[AUTHORIZE DEBUG] Existing grant found: {Grant}", System.Text.Json.JsonSerializer.Serialize(existingGrant));
                    }
                    else
                    {
                        logger.LogInformation("[AUTHORIZE DEBUG] No existing grant found for subject {Subject} and client {ClientId}", subject, clientId);
                    }

                    logger.LogInformation("Checking consent for subject {Subject}, client {ClientId}, requires consent: {RequiresConsent}, existing grant: {HasGrant}",
                        subject, clientId, requireConsent, existingGrant != null);

                    if (requireConsent)
                    {
                        bool hasConsent = false;
                        if (existingGrant != null)
                        {
                            hasConsent = requestedScopes.All(s => existingGrant.GrantedScopes.Contains(s));
                            logger.LogInformation("Existing grant found, has consent for all requested scopes: {HasConsent}", hasConsent);
                        }
                        if (!hasConsent)
                        {
                            hasConsent = await userGrantStore.HasUserGrantedConsentAsync(subject, clientId, requestedScopes, cancellationToken);
                            logger.LogInformation("HasUserGrantedConsentAsync result: {HasConsent}", hasConsent);
                        }
                        if (!hasConsent)
                        {
                            logger.LogInformation("Redirecting to consent page for subject {Subject}, client {ClientId}", subject, clientId);
                            var consentUrl = routeOptions.Combine(routeOptions.ConsentPath) + request.QueryString;
                            return Results.Redirect(consentUrl);
                        }
                        logger.LogInformation("Consent already granted for all requested scopes");
                    }
                }
                else
                {
                    var returnUrl = Uri.EscapeDataString(Microsoft.AspNetCore.Http.Extensions.UriHelper.GetEncodedUrl(request));
                    var loginUrl = routeOptions.Combine(routeOptions.LoginPath) + "?ReturnUrl=" + returnUrl;
                    return Results.Redirect(loginUrl);
                }

                IAuthorizationCodeStore? authorizationCodeStore;
                try
                {
                    authorizationCodeStore = httpContext.RequestServices.GetRequiredService<IAuthorizationCodeStore>();
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Failed to resolve IAuthorizationCodeStore.");
                    return Results.Problem("Authorization storage service not available.", statusCode: StatusCodes.Status500InternalServerError);
                }

                AuthorizationCode? storedCode = null;
                string? generatedCode = null;
                int attempts = 0;
                const int maxAttempts = 10;

                while (storedCode == null && attempts < maxAttempts)
                {
                    attempts++;
                    generatedCode = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32))
                                        .Replace("+", "-").Replace("/", "_").TrimEnd('=');

                    var existing = await authorizationCodeStore.GetAuthorizationCodeAsync(generatedCode, cancellationToken);
                    if (existing != null)
                    {
                        logger.LogWarning("Generated authorization code collision detected *before* store attempt {Attempt}, retrying.", attempts);
                        continue;
                    }

                    var codeLifetime = TimeSpan.FromMinutes(5);
                    var subjectId = httpContext.User?.FindFirstValue(System.Security.Claims.ClaimTypes.NameIdentifier);
                    if (string.IsNullOrWhiteSpace(subjectId))
                    {
                        logger.LogError("Authenticated user is missing Subject ID (sub) claim.");
                        return Results.Problem("User identifier missing.", statusCode: StatusCodes.Status500InternalServerError);
                    }

                    var codeToStore = new AuthorizationCode
                    {
                        CodeHandle = generatedCode,
                        ClientId = clientId,
                        SubjectId = subjectId,
                        RequestedScopes = requestedScopes.ToList(),
                        RedirectUri = redirectUri,
                        Nonce = nonce,
                        CodeChallenge = codeChallenge,
                        CodeChallengeMethod = codeChallengeMethod,
                        CreationTime = DateTime.UtcNow,
                        ExpirationTime = DateTime.UtcNow.Add(codeLifetime)
                    };

                    StoreResult storeResult = StoreResult.Failure;
                    try
                    {
                        storeResult = await authorizationCodeStore.StoreAuthorizationCodeAsync(codeToStore, cancellationToken);

                        if (storeResult == StoreResult.Success)
                        {
                            storedCode = codeToStore;
                            logger.LogInformation("Stored authorization code {CodeHandle} for client {ClientId} and user {UserId} on attempt {Attempt}",
                                generatedCode, clientId, subjectId, attempts);
                        }
                        else if (storeResult == StoreResult.Conflict)
                        {
                            logger.LogWarning("Conflict storing authorization code {CodeHandle} on attempt {Attempt} (detected by store), retrying.", generatedCode, attempts);
                        }
                        else
                        {
                            logger.LogError("Authorization code storage failed with result {StoreResult} for code {CodeHandle} on attempt {Attempt}", storeResult, generatedCode, attempts);
                            return Results.Problem("Failed to store authorization request.", statusCode: StatusCodes.Status500InternalServerError);
                        }
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "Unexpected exception calling StoreAuthorizationCodeAsync for code {CodeHandle} on attempt {Attempt}", generatedCode, attempts);
                        return Results.Problem("Failed to store authorization request due to unexpected error.", statusCode: StatusCodes.Status500InternalServerError);
                    }
                }

                if (storedCode == null)
                {
                    logger.LogError("Failed to generate and store a unique authorization code after {Attempts} attempts.", maxAttempts);
                    return Results.Problem("Failed to generate a unique authorization code.", statusCode: StatusCodes.Status500InternalServerError);
                }

                var authorizationCode = storedCode.CodeHandle;

                var redirectUrlBuilder = new System.Text.StringBuilder(redirectUri);
                redirectUrlBuilder.Append(redirectUri.Contains('?') ? '&' : '?');
                redirectUrlBuilder.Append("code=");
                redirectUrlBuilder.Append(Uri.EscapeDataString(authorizationCode));
                if (!string.IsNullOrWhiteSpace(state))
                {
                    redirectUrlBuilder.Append("&state=");
                    redirectUrlBuilder.Append(Uri.EscapeDataString(state));
                }

                logger.LogInformation("Redirecting back to client: {RedirectUrl}", redirectUrlBuilder.ToString());
                return Results.Redirect(redirectUrlBuilder.ToString());
            })
            .WithName("Authorize")
            .WithTags("CoreIdent")
            .Produces(StatusCodes.Status302Found)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status500InternalServerError)
            .WithSummary("OAuth2 Authorization Endpoint.")
            .WithDescription("Handles OAuth2 Authorization Code Flow with PKCE and user consent.");

            // --- /consent GET endpoint ---
            endpoints.MapGet(routeOptions.ConsentPath, (
                HttpRequest request,
                HttpContext httpContext,
                IAntiforgery antiforgery) =>
            {
                var tokens = antiforgery.GetAndStoreTokens(httpContext);
                var returnUrl = routeOptions.Combine(routeOptions.AuthorizePath) + request.QueryString;
                var clientId = request.Query["client_id"];
                var redirectUri = request.Query["redirect_uri"];
                var scope = request.Query["scope"];
                var state = request.Query["state"];
                var html = $@"<html><body>
<form method=""post"" action=""{request.Path}"">
<input name=""__RequestVerificationToken"" type=""hidden"" value=""{tokens.RequestToken}"" />
<input name=""ReturnUrl"" type=""hidden"" value=""{returnUrl}"" />
<input name=""ClientId"" type=""hidden"" value=""{clientId}"" />
<input name=""RedirectUri"" type=""hidden"" value=""{redirectUri}"" />
<input name=""Scope"" type=""hidden"" value=""{scope}"" />
<input name=""State"" type=""hidden"" value=""{state}"" />
<button type=""submit"" name=""Allow"" value=""true"">Allow</button>
<button type=""submit"" name=""Allow"" value=""false"">Deny</button>
</form>
</body></html>";
                return Results.Content(html, "text/html");
            })
            .WithName("ConsentGet")
            .WithTags("CoreIdent")
            .Produces(StatusCodes.Status200OK, typeof(void), "text/html")
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status500InternalServerError)
            .WithSummary("Consent form display endpoint.")
            .WithDescription("Displays the consent form for the user to approve or deny requested scopes.");

            // --- /consent POST endpoint ---
            endpoints.MapPost(routeOptions.ConsentPath, async (
                [FromForm] ConsentRequest request,
                HttpContext httpContext,
                IAntiforgery antiforgery,
                IUserGrantStore userGrantStore,
                ILoggerFactory loggerFactory,
                CancellationToken cancellationToken) =>
            {
                var logger = loggerFactory.CreateLogger("CoreIdent.Consent");
                var subject = httpContext.User?.FindFirstValue(System.Security.Claims.ClaimTypes.NameIdentifier)
                    ?? httpContext.User?.FindFirstValue(System.Security.Claims.ClaimTypes.Name)
                    ?? httpContext.User?.Identity?.Name;

                if (string.IsNullOrWhiteSpace(subject))
                {
                    logger.LogWarning("No subject identifier found in authenticated user for consent");
                    return Results.Unauthorized();
                }

                logger.LogInformation("POST Consent: Subject: {Subject}, Allow: {Allow}, ReturnUrl: {ReturnUrl}",
                    subject, request.Allow, request.ReturnUrl);

                try
                {
                    await antiforgery.ValidateRequestAsync(httpContext);
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "Antiforgery validation failed in consent endpoint");
                    return Results.BadRequest(new { error = "invalid_request", error_description = "Invalid request token." });
                }

                if (!request.Allow)
                {
                    var queryString = request.ReturnUrl.Contains('?') ? request.ReturnUrl.Substring(request.ReturnUrl.IndexOf('?')) : string.Empty;
                    var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(queryString);

                    if (!query.TryGetValue("redirect_uri", out var redirectUriValues) || string.IsNullOrEmpty(redirectUriValues))
                    {
                        logger.LogWarning("Missing redirect_uri in consent returnUrl: {ReturnUrl}", request.ReturnUrl);
                        return Results.BadRequest(new { error = "invalid_request", error_description = "Invalid return URL." });
                    }
                    var redirectUri = redirectUriValues.ToString();

                    string? state = null;
                    if (query.TryGetValue("state", out var stateValues) && !string.IsNullOrEmpty(stateValues))
                    {
                        state = stateValues.ToString();
                    }

                    var denyUrl = redirectUri + (redirectUri.Contains('?') ? '&' : '?') + "error=access_denied";
                    if (!string.IsNullOrEmpty(state))
                        denyUrl += "&state=" + Uri.EscapeDataString(state);

                    logger.LogInformation("Consent denied, redirecting to: {DenyUrl}", denyUrl);
                    return Results.Redirect(denyUrl);
                }

                var qsString = request.ReturnUrl.Contains('?') ? request.ReturnUrl.Substring(request.ReturnUrl.IndexOf('?')) : string.Empty;
                var qs = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(qsString);

                if (!qs.TryGetValue("client_id", out var clientIdValues) || string.IsNullOrEmpty(clientIdValues))
                {
                    logger.LogWarning("Missing client_id in consent returnUrl: {ReturnUrl}", request.ReturnUrl);
                    return Results.BadRequest(new { error = "invalid_request", error_description = "Invalid client ID." });
                }
                var clientId = clientIdValues.ToString();

                if (!qs.TryGetValue("scope", out var scopeValues) || string.IsNullOrEmpty(scopeValues))
                {
                    logger.LogWarning("Missing scope in consent returnUrl: {ReturnUrl}", request.ReturnUrl);
                    return Results.BadRequest(new { error = "invalid_request", error_description = "Invalid scope." });
                }
                var scope = scopeValues.ToString();
                var grantedScopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();

                var grant = new UserGrant
                {
                    SubjectId = subject,
                    UserId = subject,
                    ClientId = clientId,
                    GrantedScopes = grantedScopes,
                    Scopes = grantedScopes.ToList(),
                    CreatedAt = DateTime.UtcNow,
                    GrantedAt = DateTime.UtcNow
                };

                try
                {
                    logger.LogInformation("Saving consent grant for subject {Subject}, client {ClientId}, scopes: {Scopes}",
                        subject, clientId, string.Join(" ", grantedScopes));
                    await userGrantStore.SaveAsync(grant, cancellationToken);
                    logger.LogInformation("Grant saved successfully");
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error saving consent grant");
                    return Results.Problem("An error occurred while processing your consent.", statusCode: StatusCodes.Status500InternalServerError);
                }

                logger.LogInformation("Consent granted, redirecting to: {ReturnUrl}", request.ReturnUrl);
                return Results.Redirect(request.ReturnUrl);
            })
            .WithName("ConsentPost")
            .WithTags("CoreIdent")
            .Produces(StatusCodes.Status302Found)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status500InternalServerError)
            .WithSummary("Consent submission endpoint.")
            .WithDescription("Handles user submission of consent decisions.");
        }
    }
}
