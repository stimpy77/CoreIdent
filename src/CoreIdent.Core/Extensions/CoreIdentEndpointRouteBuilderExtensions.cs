using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Models.Requests;
using CoreIdent.Core.Models.Responses;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using Microsoft.AspNetCore.Antiforgery; // Added namespace
using Microsoft.AspNetCore.Builder; // IEndpointRouteBuilder
using Microsoft.AspNetCore.Http;    // Results, StatusCodes
using Microsoft.AspNetCore.Mvc;     // FromBody attribute (though often inferred)
using Microsoft.AspNetCore.Routing; // RouteGroupBuilder
using Microsoft.Extensions.DependencyInjection; // GetRequiredService
using Microsoft.Extensions.Logging; // ILoggerFactory
using Microsoft.Extensions.Options; // IOptions
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations; // ValidationResult
using System.Linq; // For validation results
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http.Extensions; // For GetEncodedUrl
using System.Security.Cryptography; // For PKCE random generation
using System.Text; // For Encoding
using Microsoft.Extensions.Primitives; // For StringValues
using System.Net.Http.Headers; // For Basic Authentication
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities; // Added for QueryHelpers

namespace CoreIdent.Core.Extensions;

/// <summary>
/// Extension methods for mapping CoreIdent endpoints using Minimal APIs.
/// </summary>
public static class CoreIdentEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps the CoreIdent core authentication and OAuth/OIDC endpoints.
    /// </summary>
    /// <param name="endpoints">The <see cref="IEndpointRouteBuilder"/> to add the routes to.</param>
    /// <param name="configureRoutes">Optional action to configure the default routes.</param>
    /// <returns>A <see cref="RouteGroupBuilder"/> containing the mapped CoreIdent endpoints.</returns>
    public static RouteGroupBuilder MapCoreIdentEndpoints(this IEndpointRouteBuilder endpoints, Action<CoreIdentRouteOptions>? configureRoutes = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var routeOptions = new CoreIdentRouteOptions();
        configureRoutes?.Invoke(routeOptions);

        // Map user profile endpoints (/me)
        endpoints.MapUserProfileEndpoints(routeOptions);

        // Validate BasePath
        if (string.IsNullOrWhiteSpace(routeOptions.BasePath) || !routeOptions.BasePath.StartsWith("/"))
        {
            throw new InvalidOperationException($"{nameof(CoreIdentRouteOptions.BasePath)} must be configured and start with a '/'. Current value: '{routeOptions.BasePath}'");
        }

        var routeGroup = endpoints.MapGroup(routeOptions.BasePath);

        // Map standard authentication endpoints (login, register)
        routeGroup.MapAuthEndpoints(routeOptions);

        // Map OAuth/OIDC endpoints (authorize, consent)
        routeGroup.MapOAuthEndpoints(routeOptions);

        // Map token management endpoints (introspect, revoke)
        routeGroup.MapTokenManagementEndpoints(routeOptions);

        // Endpoint: POST /token
        // Handles various grant types for token issuance.
        routeGroup.MapPost(routeOptions.TokenPath, async (
            HttpRequest request,
            HttpContext httpContext,
            IClientStore clientStore,
            IAuthorizationCodeStore authCodeStore, // New store needed
            IUserStore userStore, // Needed to get user for token generation
            ITokenService tokenService,
            IPasswordHasher passwordHasher, // For client secret validation
            IOptions<CoreIdentOptions> options,
            ILoggerFactory loggerFactory,
            CancellationToken cancellationToken) =>
        {
            var logger = loggerFactory.CreateLogger("CoreIdent.Token");

            // Read form data
            if (!request.HasFormContentType)
            {
                return Results.BadRequest(new { error = "invalid_request", error_description = "Request must be form-urlencoded." });
            }

            var form = await request.ReadFormAsync(cancellationToken);

            string? grantType = form["grant_type"];
            if (string.IsNullOrWhiteSpace(grantType))
            {
                return Results.BadRequest(new { error = "invalid_request", error_description = "grant_type is required." });
            }

            // --- Client Authentication ---
            // Clients can authenticate using Basic Auth header or client_id/client_secret in the body
            CoreIdentClient? client = null;
            string? clientIdFromRequest = form["client_id"];
            string? clientSecretFromRequest = form["client_secret"];

            // Try Basic Authentication header first
            if (AuthenticationHeaderValue.TryParse(request.Headers["Authorization"], out var authHeader) &&
                authHeader.Scheme.Equals("Basic", StringComparison.OrdinalIgnoreCase) &&
                authHeader.Parameter != null)
            {
                try
                {
                    var credentialBytes = Convert.FromBase64String(authHeader.Parameter);
                    var credentials = Encoding.UTF8.GetString(credentialBytes).Split(':', 2);
                    if (credentials.Length == 2)
                    {
                        clientIdFromRequest = credentials[0];
                        clientSecretFromRequest = credentials[1];
                    }
                }
                catch (FormatException)
                {
                    logger.LogWarning("Invalid Basic authentication header format.");
                    return Results.BadRequest(new { error = "invalid_client", error_description = "Invalid Basic authentication header." });
                }
            }

            if (string.IsNullOrWhiteSpace(clientIdFromRequest))
            {
                return Results.BadRequest(new { error = "invalid_client", error_description = "Client authentication failed (client_id missing)." });
            }

            try
            {
                client = await clientStore.FindClientByIdAsync(clientIdFromRequest, cancellationToken);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error retrieving client {ClientId} during token request.", clientIdFromRequest);
                return Results.Problem("An unexpected error occurred during client lookup.", statusCode: StatusCodes.Status500InternalServerError);
            }

            if (client == null || !client.Enabled)
            {
                logger.LogWarning("Token request for unknown or disabled client: {ClientId}", clientIdFromRequest);
                return Results.BadRequest(new { error = "invalid_client", error_description = "Client is unknown or disabled." });
            }

            // Validate client secret if required (confidential client)
            // TODO: Determine if client is confidential based on its configuration (e.g., client.ClientSecrets collection)
            bool isConfidentialClient = client.ClientSecrets.Any(); // Basic check
            if (isConfidentialClient)
            {
                if (string.IsNullOrWhiteSpace(clientSecretFromRequest))
                {
                     logger.LogWarning("Missing client_secret for confidential client {ClientId}", clientIdFromRequest);
                     return Results.BadRequest(new { error = "invalid_client", error_description = "Client secret is required for this client." });
                }

                // Validate the provided secret against stored secrets
                bool validSecret = false;
                foreach (var storedSecret in client.ClientSecrets)
                {
                    // Assuming storedSecret.Value contains the hashed secret
                    // and storedSecret.Type indicates the hashing mechanism if needed.
                    var verificationResult = passwordHasher.VerifyHashedPassword(null, storedSecret.Value, clientSecretFromRequest); // Using password hasher for secrets too
                    if (verificationResult != PasswordVerificationResult.Failed)
                    {
                        validSecret = true;
                        // Optionally handle hash updates if verificationResult == PasswordVerificationResult.SuccessRehashNeeded
                        break;
                    }
                }

                if (!validSecret)
                {
                    logger.LogWarning("Invalid client_secret provided for client {ClientId}", clientIdFromRequest);
                    return Results.BadRequest(new { error = "invalid_client", error_description = "Invalid client secret." });
                }
            }
            // Else: Public client - no secret validation needed.


            // --- Grant Type Handling ---
            if (grantType == "authorization_code")
            {
                // Extract parameters for authorization_code grant
                string? code = form["code"];
                string? redirectUri = form["redirect_uri"];
                string? codeVerifier = form["code_verifier"]; // For PKCE

                if (string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(redirectUri))
                {
                    return Results.BadRequest(new { error = "invalid_request", error_description = "Missing required parameters for authorization_code grant (code, redirect_uri)." });
                }

                // Retrieve the stored authorization code
                AuthorizationCode? storedCode;
                try
                {
                    storedCode = await authCodeStore.GetAuthorizationCodeAsync(code, cancellationToken);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error retrieving authorization code handle {CodeHandle}", code);
                    return Results.Problem("An unexpected error occurred retrieving authorization details.", statusCode: StatusCodes.Status500InternalServerError);
                }

                // Validate the code
                if (storedCode == null)
                {
                    logger.LogWarning("Authorization code not found: {CodeHandle}", code);
                    return Results.BadRequest(new { error = "invalid_grant", error_description = "Authorization code is invalid or expired." });
                }

                if (storedCode.ClientId != client.ClientId)
                {
                    logger.LogError("Client mismatch for authorization code {CodeHandle}. Expected {ExpectedClient}, Got {ActualClient}", code, storedCode.ClientId, client.ClientId);
                    // Potential attack? Consume code anyway?
                    await authCodeStore.RemoveAuthorizationCodeAsync(code, cancellationToken); // Consume invalid code
                    return Results.BadRequest(new { error = "invalid_grant", error_description = "Client mismatch." });
                }

                if (storedCode.RedirectUri != redirectUri)
                {
                    logger.LogWarning("Redirect URI mismatch for authorization code {CodeHandle}. Expected {ExpectedUri}, Got {ActualUri}", code, storedCode.RedirectUri, redirectUri);
                    await authCodeStore.RemoveAuthorizationCodeAsync(code, cancellationToken); // Consume invalid code
                    return Results.BadRequest(new { error = "invalid_grant", error_description = "Redirect URI mismatch." });
                }

                if (storedCode.ExpirationTime < DateTime.UtcNow)
                {
                    logger.LogWarning("Expired authorization code presented: {CodeHandle}", code);
                    await authCodeStore.RemoveAuthorizationCodeAsync(code, cancellationToken); // Consume expired code
                    return Results.BadRequest(new { error = "invalid_grant", error_description = "Authorization code expired." });
                }

                // PKCE Validation
                if (!string.IsNullOrWhiteSpace(storedCode.CodeChallenge))
                {
                    if (string.IsNullOrWhiteSpace(codeVerifier))
                    {
                        logger.LogWarning("Missing code_verifier for PKCE flow. Code: {CodeHandle}", code);
                        await authCodeStore.RemoveAuthorizationCodeAsync(code, cancellationToken);
                        return Results.BadRequest(new { error = "invalid_grant", error_description = "Missing PKCE code_verifier." });
                    }

                    // Validate based on method (only S256 supported here)
                    if (storedCode.CodeChallengeMethod == "S256")
                    {
                        using var sha256 = SHA256.Create();
                        var challengeBytes = sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
                        var calculatedChallenge = Convert.ToBase64String(challengeBytes)
                                                   .Replace("+", "-")
                                                   .Replace("/", "_")
                                                   .TrimEnd('=');

                        if (!string.Equals(calculatedChallenge, storedCode.CodeChallenge, StringComparison.Ordinal))
                        {
                            logger.LogWarning("Invalid code_verifier for PKCE flow. Code: {CodeHandle}", code);
                            await authCodeStore.RemoveAuthorizationCodeAsync(code, cancellationToken);
                            return Results.BadRequest(new { error = "invalid_grant", error_description = "Invalid PKCE code_verifier." });
                        }
                    }
                    else // 'plain' or unsupported
                    {
                         logger.LogError("Unsupported PKCE method ({Method}) found for code {CodeHandle}", storedCode.CodeChallengeMethod ?? "null", code);
                         await authCodeStore.RemoveAuthorizationCodeAsync(code, cancellationToken);
                         return Results.BadRequest(new { error = "invalid_grant", error_description = "Unsupported PKCE method." });
                    }
                }
                else if (client.RequirePkce) // Check if client *requires* PKCE but code was issued without it (shouldn't happen)
                {
                     logger.LogError("Client {ClientId} requires PKCE, but authorization code {CodeHandle} was issued without a challenge.", client.ClientId, code);
                     await authCodeStore.RemoveAuthorizationCodeAsync(code, cancellationToken);
                     return Results.BadRequest(new { error = "invalid_grant", error_description = "PKCE required by client but not used in authorization." });
                }

                // --- Validation successful --- Consume the code
                try
                {
                    await authCodeStore.RemoveAuthorizationCodeAsync(code, cancellationToken);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Failed to remove consumed authorization code {CodeHandle}", code);
                    // Critical failure - stop processing
                    return Results.Problem("Failed to consume authorization code.", statusCode: StatusCodes.Status500InternalServerError);
                }

                // Get the user associated with the code
                 CoreIdentUser? user;
                try
                {
                    user = await userStore.FindUserByIdAsync(storedCode.SubjectId, cancellationToken);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error finding user {UserId} during token exchange for code {CodeHandle}", storedCode.SubjectId, code);
                    return Results.Problem("An unexpected error occurred retrieving user details.", statusCode: StatusCodes.Status500InternalServerError);
                }

                if (user == null)
                {
                    logger.LogError("User {UserId} not found for valid authorization code {CodeHandle}", storedCode.SubjectId, code);
                    // Code consumed, user gone? Security event?
                    return Results.BadRequest(new { error = "invalid_grant", error_description = "User associated with authorization code not found." });
                }

                // --- Issue Tokens ---
                try
                {
                    var accessToken = await tokenService.GenerateAccessTokenAsync(user, storedCode.RequestedScopes);
                    var idToken = await tokenService.GenerateIdTokenAsync(user, client.ClientId, storedCode.Nonce, storedCode.RequestedScopes);
                    string? refreshToken = null;
 
                    if (storedCode.RequestedScopes.Contains("offline_access") && client.AllowOfflineAccess)
                    {
                        refreshToken = await tokenService.GenerateAndStoreRefreshTokenAsync(user, client.ClientId);
                    }
 
                    // Construct the standard TokenResponse DTO
                    var tokenResponse = new TokenResponse
                    {
                        AccessToken = accessToken,
                        TokenType = "Bearer",
                        ExpiresIn = (int)options.Value.AccessTokenLifetime.TotalSeconds,
                        RefreshToken = refreshToken, // Will be null if not requested/allowed
                        IdToken = idToken, // Will be null if nonce/openid scope wasn't requested
                        Scope = string.Join(" ", storedCode.RequestedScopes) // Echo back granted scopes
                    };
 
                     // Log the actual token values being returned
                    logger.LogDebug("Token endpoint returning: AccessToken='{AccessToken}', RefreshToken='{RefreshToken}', IdToken='{IdToken}', TokenType='{TokenType}', Scope='{Scope}'",
                                     tokenResponse.AccessToken ?? "<null>", 
                                     tokenResponse.RefreshToken ?? "<null>", 
                                     tokenResponse.IdToken ?? "<null>", 
                                     tokenResponse.TokenType ?? "<null>",
                                     tokenResponse.Scope ?? "<null>");

                     logger.LogInformation("Tokens issued successfully via authorization_code grant for client {ClientId} and user {UserId}", client.ClientId, user.Id);
                    return Results.Ok(tokenResponse);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error issuing tokens during authorization_code grant for client {ClientId} user {UserId}", client.ClientId, user.Id);
                    return Results.Problem("An unexpected error occurred during token generation.", statusCode: StatusCodes.Status500InternalServerError);
                }

            }
            else if (grantType == "refresh_token")
            {
                // --- Logic moved from standalone /token/refresh endpoint ---
                var refreshTokenRequest = new RefreshTokenRequest { RefreshToken = form["refresh_token"] }; // Extract refresh token from form
                var refreshTokenStore = httpContext.RequestServices.GetRequiredService<IRefreshTokenStore>();

                // Basic validation
                if (refreshTokenRequest == null || string.IsNullOrWhiteSpace(refreshTokenRequest.RefreshToken))
                {
                    logger.LogWarning("Missing refresh_token parameter for refresh_token grant type.");
                    return Results.BadRequest(new { error = "invalid_request", error_description = "refresh_token is required for grant_type=refresh_token." });
                }

                // Validate the incoming refresh token handle using the store
                CoreIdentRefreshToken? existingToken;
                try
                {
                    existingToken = await refreshTokenStore.GetRefreshTokenAsync(refreshTokenRequest.RefreshToken, cancellationToken);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error retrieving refresh token during refresh operation.");
                    return Results.Problem("An unexpected error occurred during token validation.", statusCode: StatusCodes.Status500InternalServerError);
                }

                // Validation checks
                if (existingToken == null)
                {
                    logger.LogWarning("Refresh token handle not found: {RefreshTokenHandle}", refreshTokenRequest.RefreshToken);
                    return Results.BadRequest(new { error = "invalid_grant", error_description = "Refresh token is invalid or expired." }); // Use invalid_grant as per spec
                }
                if (existingToken.ConsumedTime.HasValue)
                {
                    logger.LogWarning("Attempted reuse of consumed refresh token: {RefreshTokenHandle}", refreshTokenRequest.RefreshToken);
                    // Implement token theft detection response (reuse existing logic)
                    try
                    {
                        var theftDetectionMode = options.Value.TokenSecurity.TokenTheftDetectionMode;
                        if (theftDetectionMode != TokenTheftDetectionMode.Silent)
                        {
                            logger.LogWarning("Potential token theft detected for user {SubjectId}, client {ClientId}, token family {FamilyId}. Taking action: {Action}",
                                existingToken.SubjectId, existingToken.ClientId, existingToken.FamilyId, theftDetectionMode);
                            if (theftDetectionMode == TokenTheftDetectionMode.RevokeFamily)
                            {
                                await refreshTokenStore.RevokeTokenFamilyAsync(existingToken.FamilyId, cancellationToken);
                                logger.LogWarning("Revoked all tokens in family {FamilyId} due to potential token theft", existingToken.FamilyId);
                            }
                            else if (theftDetectionMode == TokenTheftDetectionMode.RevokeAllUserTokens)
                            {
                                var userTokens = await refreshTokenStore.FindTokensBySubjectIdAsync(existingToken.SubjectId, cancellationToken);
                                int count = 0;
                                foreach (var token in userTokens.Where(t => !t.ConsumedTime.HasValue))
                                {
                                    await refreshTokenStore.RemoveRefreshTokenAsync(token.Handle, cancellationToken); // Consume/remove
                                    count++;
                                }
                                logger.LogWarning("Revoked {Count} active tokens for user {SubjectId} due to potential token theft", count, existingToken.SubjectId);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "Error during token theft response for token {RefreshTokenHandle}", refreshTokenRequest.RefreshToken);
                    }
                    return Results.BadRequest(new { error = "invalid_grant", error_description = "Refresh token has already been used." }); // Use invalid_grant
                }
                if (existingToken.ExpirationTime < DateTime.UtcNow)
                {
                     logger.LogWarning("Expired refresh token presented: {RefreshTokenHandle}", refreshTokenRequest.RefreshToken);
                     await refreshTokenStore.RemoveRefreshTokenAsync(existingToken.Handle, cancellationToken); // Consume expired token
                     return Results.BadRequest(new { error = "invalid_grant", error_description = "Refresh token has expired." }); // Use invalid_grant
                }

                // Client check: Ensure the authenticated client matches the client associated with the refresh token
                if (existingToken.ClientId != client.ClientId)
                {
                    logger.LogError("Client mismatch for refresh token {RefreshTokenHandle}. Expected {ExpectedClient}, Got {ActualClient}", existingToken.Handle, existingToken.ClientId, client.ClientId);
                    // Consume the token as it's likely compromised or misused
                    await refreshTokenStore.RemoveRefreshTokenAsync(existingToken.Handle, cancellationToken);
                    return Results.BadRequest(new { error = "invalid_grant", error_description = "Client mismatch for refresh token." });
                }

                // Mark the old token as consumed *before* issuing new ones
                try
                {
                    await refreshTokenStore.RemoveRefreshTokenAsync(existingToken.Handle, cancellationToken);
                }
                catch(Exception ex)
                {
                    logger.LogError(ex, "Error consuming old refresh token {RefreshTokenHandle} during refresh.", existingToken.Handle);
                    return Results.Problem("An unexpected error occurred during token refresh.", statusCode: StatusCodes.Status500InternalServerError);
                }

                // Found valid token, now find user
                CoreIdentUser? user;
                try
                {
                    user = await userStore.FindUserByIdAsync(existingToken.SubjectId, cancellationToken);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error finding user {UserId} during token refresh", existingToken.SubjectId);
                    return Results.Problem("An unexpected error occurred during user lookup.", statusCode: StatusCodes.Status500InternalServerError);
                }

                if (user == null)
                {
                    logger.LogError("User {UserId} associated with refresh token {RefreshTokenHandle} not found.", existingToken.SubjectId, existingToken.Handle);
                    return Results.BadRequest(new { error = "invalid_grant", error_description = "User associated with refresh token not found." });
                }

                // Generate NEW tokens
                string newAccessToken;
                string newRefreshTokenHandle;
                try
                {
                    newAccessToken = await tokenService.GenerateAccessTokenAsync(user); // Reuse original scopes implicitly
                    if (options.Value.TokenSecurity.EnableTokenFamilyTracking)
                    {
                        newRefreshTokenHandle = await tokenService.GenerateAndStoreRefreshTokenAsync(user, existingToken.ClientId, existingToken);
                    }
                    else
                    {
                        newRefreshTokenHandle = await tokenService.GenerateAndStoreRefreshTokenAsync(user, existingToken.ClientId);
                    }
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error generating new tokens for user {UserId} during refresh", user.Id);
                    return Results.Problem("An unexpected error occurred during token generation.", statusCode: StatusCodes.Status500InternalServerError);
                }

                var response = new TokenResponse
                {
                    AccessToken = newAccessToken,
                    ExpiresIn = (int)options.Value.AccessTokenLifetime.TotalSeconds,
                    RefreshToken = newRefreshTokenHandle,
                    TokenType = "Bearer"
                };

                logger.LogInformation("Tokens refreshed successfully for user {UserId} via grant_type=refresh_token", user.Id);
                return Results.Ok(response);
            }
            else if (grantType == "client_credentials")
            {
                // --- Client Credentials Grant --- Handle M2M authentication ---
                logger.LogInformation("Processing client_credentials grant type for client {ClientId}", client.ClientId);

                // 1. Validate Client Grant Type
                if (!client.AllowedGrantTypes.Contains("client_credentials"))
                {
                    logger.LogWarning("Client {ClientId} is not allowed to use grant_type=client_credentials.", client.ClientId);
                    return Results.BadRequest(new { error = "unauthorized_client", error_description = "Client is not authorized to use this grant type." });
                }

                // 2. Validate Scopes (Optional for this grant, but good practice)
                string? scopeParam = form["scope"];
                var requestedScopes = scopeParam?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? Enumerable.Empty<string>();
                List<string> grantedScopes = new();

                if (requestedScopes.Any())
                {
                    var scopeStore = httpContext.RequestServices.GetRequiredService<IScopeStore>();
                    IEnumerable<CoreIdentScope> validScopes;
                    try
                    {
                        validScopes = await scopeStore.FindScopesByNameAsync(requestedScopes, cancellationToken);
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "Error retrieving scopes during client_credentials grant for client {ClientId}. Scopes: {Scopes}", client.ClientId, scopeParam);
                        return Results.Problem("An unexpected error occurred during scope validation.", statusCode: StatusCodes.Status500InternalServerError);
                    }

                    // Filter requested scopes to only those allowed for the client
                    foreach (var requestedScope in requestedScopes)
                    {
                        var scopeDetail = validScopes.FirstOrDefault(s => s.Name == requestedScope);
                        if (scopeDetail == null || !scopeDetail.Enabled)
                        {
                             logger.LogWarning("Client {ClientId} requested invalid or disabled scope: {Scope}", client.ClientId, requestedScope);
                             // Per spec, ignore invalid scopes or return error? Return error for now.
                             return Results.BadRequest(new { error = "invalid_scope", error_description = $"Scope '{requestedScope}' is invalid or disabled." });
                        }
                        if (!client.AllowedScopes.Contains(requestedScope))
                        {
                            logger.LogWarning("Client {ClientId} requested scope {Scope} which is not allowed for this client.", client.ClientId, requestedScope);
                            return Results.BadRequest(new { error = "invalid_scope", error_description = $"Scope '{requestedScope}' is not allowed for this client." });
                        }
                        grantedScopes.Add(requestedScope);
                    }
                    logger.LogInformation("Client {ClientId} granted scopes: [{GrantedScopes}]", client.ClientId, string.Join(", ", grantedScopes));
                }
                else
                {
                    // If no scope requested, grant client's default allowed scopes or none?
                    // For now, grant none if none requested.
                     logger.LogInformation("Client {ClientId} requested no scopes.", client.ClientId);
                }

                // 3. Issue Access Token (No Refresh Token for client_credentials)
                try
                {
                    var accessToken = await tokenService.GenerateAccessTokenAsync(client, grantedScopes);

                    var tokenResponse = new TokenResponse
                    {
                        AccessToken = accessToken,
                        TokenType = "Bearer",
                        ExpiresIn = (int)options.Value.AccessTokenLifetime.TotalSeconds,
                        Scope = grantedScopes.Any() ? string.Join(" ", grantedScopes) : null // Echo back granted scopes
                        // No Refresh Token or ID Token for client_credentials
                    };

                    logger.LogInformation("Access token issued successfully via client_credentials grant for client {ClientId}", client.ClientId);
                    return Results.Ok(tokenResponse);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error issuing tokens during client_credentials grant for client {ClientId}", client.ClientId);
                    return Results.Problem("An unexpected error occurred during token generation.", statusCode: StatusCodes.Status500InternalServerError);
                }
            }
            else
            {
                logger.LogWarning("Unsupported grant_type requested: {GrantType}", grantType);
                return Results.BadRequest(new { error = "unsupported_grant_type", error_description = $"Grant type '{grantType}' is not supported." });
            }

        })
        .WithName("TokenExchange")
        .WithTags("CoreIdent")
        // TODO: Define Produces accurately
        .Produces<TokenResponse>(StatusCodes.Status200OK)
        .Produces<ProblemDetails>(StatusCodes.Status400BadRequest)
        .Produces<ProblemDetails>(StatusCodes.Status500InternalServerError)
        .WithSummary("Exchanges various grants for access tokens.")
        .WithDescription("Handles token issuance based on grant types like authorization_code, client_credentials, etc.");

        // Map well-known endpoints relative to the root
        // Endpoint: GET /.well-known/openid-configuration
        endpoints.MapGet(routeOptions.DiscoveryPath, (IOptions<CoreIdentOptions> options, ILogger<CoreIdentRouteOptions> logger, LinkGenerator links, HttpContext httpContext) =>
        {
            try
            {
                logger.LogInformation("Discovery endpoint hit: {Path}", routeOptions.DiscoveryPath);
                var opts = options.Value;
                var issuer = opts.Issuer ?? httpContext.Request.Scheme + "://" + httpContext.Request.Host.Value;
                var baseUrl = issuer.TrimEnd('/');
                var jwksUri = baseUrl + "/.well-known/jwks.json";
                var authorizationEndpoint = baseUrl + "/auth/authorize";
                var tokenEndpoint = baseUrl + "/auth/token";
                var userinfoEndpoint = baseUrl + "/auth/userinfo";
                var discovery = new {
                    issuer = issuer,
                    jwks_uri = jwksUri,
                    authorization_endpoint = authorizationEndpoint,
                    token_endpoint = tokenEndpoint,
                    userinfo_endpoint = userinfoEndpoint,
                    response_types_supported = new[] { "code", "token" },
                    subject_types_supported = new[] { "public" },
                    id_token_signing_alg_values_supported = new[] { "HS256" },
                    scopes_supported = new[] { "openid", "profile", "email" },
                    token_endpoint_auth_methods_supported = new[] { "client_secret_post", "client_secret_basic" },
                    grant_types_supported = new[] { "authorization_code", "client_credentials", "refresh_token", "password" }
                };
                return Results.Json(discovery);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Discovery endpoint error");
                return Results.Problem($"{ex.Message}\n{ex.StackTrace}", statusCode: StatusCodes.Status500InternalServerError);
            }
        })
        .WithName("OidcDiscovery")
        .WithTags("CoreIdent")
        .Produces(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status404NotFound)
        .WithSummary("Provides OpenID Connect discovery information.");

        // Endpoint: GET /.well-known/jwks.json
        endpoints.MapGet(routeOptions.JwksPath, (
            IOptions<CoreIdentOptions> options,
            [Microsoft.AspNetCore.Mvc.FromServices] JwtTokenService tokenService,
            ILogger<CoreIdentRouteOptions> logger) =>
        {
            try
            {
                logger.LogInformation("JWKS endpoint hit: {Path}", routeOptions.JwksPath);
                // Only HS256 supported for now
                var securityKey = tokenService.GetSecurityKey() as Microsoft.IdentityModel.Tokens.SymmetricSecurityKey;
                if (securityKey == null)
                {
                    return Results.Problem("No symmetric key configured.", statusCode: StatusCodes.Status500InternalServerError);
                }
                var jwk = new {
                    kty = "oct",
                    k = System.Convert.ToBase64String(securityKey.Key),
                    alg = "HS256",
                    use = "sig",
                    kid = "coreident-hs256"
                };
                var jwks = new { keys = new[] { jwk } };
                return Results.Json(jwks);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "JWKS endpoint error");
                return Results.Problem($"{ex.Message}\n{ex.StackTrace}", statusCode: StatusCodes.Status500InternalServerError);
            }
        })
        .WithName("OidcJwks")
        .WithTags("CoreIdent")
        .Produces(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status404NotFound)
        .WithSummary("Provides the JSON Web Key Set (JWKS) for token validation.");

        // Note: Refresh token endpoint is now handled within the main /token endpoint
        // via grant_type=refresh_token. The old RefreshTokenPath is kept for potential
        // legacy use or different configuration but is not mapped by default here.

        return routeGroup;
    }
}