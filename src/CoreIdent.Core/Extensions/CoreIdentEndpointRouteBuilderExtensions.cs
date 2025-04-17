using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Models.Requests;
using CoreIdent.Core.Models.Responses;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
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

namespace CoreIdent.Core.Extensions;

/// <summary>
/// Extension methods for mapping CoreIdent endpoints using Minimal APIs.
/// </summary>
public static class CoreIdentEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps the CoreIdent core authentication endpoints (/register, /login, /token/refresh).
    /// </summary>
    /// <param name="endpoints">The <see cref="IEndpointRouteBuilder"/> to add the routes to.</param>
    /// <param name="basePath">Optional base path for the endpoints (e.g., "/api/auth"). Defaults to "/".</param>
    /// <returns>A <see cref="RouteGroupBuilder"/> for further customization.</returns>
    public static RouteGroupBuilder MapCoreIdentEndpoints(this IEndpointRouteBuilder endpoints, string basePath = "/")
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        basePath = string.IsNullOrWhiteSpace(basePath) ? "/" : basePath.TrimEnd('/') + "/"; // Ensure trailing slash

        var routeGroup = endpoints.MapGroup(basePath);

        // Endpoint: /register
        routeGroup.MapPost("register", async (
            [FromBody] RegisterRequest request,
            HttpContext httpContext,
            IUserStore userStore,
            IPasswordHasher passwordHasher,
            ILoggerFactory loggerFactory,
            CancellationToken cancellationToken) =>
        {
            var logger = loggerFactory.CreateLogger("CoreIdent.Register");

            // Manual validation (Minimal APIs handle basic validation, but this shows explicit control)
            var validationResults = new List<ValidationResult>();
            if (!Validator.TryValidateObject(request, new ValidationContext(request), validationResults, validateAllProperties: true))
            {
                return Results.ValidationProblem(validationResults.ToDictionary(vr => vr.MemberNames.FirstOrDefault() ?? string.Empty, vr => vr.ErrorMessage?.Split(',') ?? Array.Empty<string>()));
            }

            // --- Check if user already exists ---
            var normalizedUsername = request.Email!.ToUpperInvariant();
            logger.LogDebug("Register endpoint: Checking if user exists: {NormalizedUsername}", normalizedUsername);
            try
            {
                var existingUser = await userStore.FindUserByUsernameAsync(normalizedUsername, cancellationToken);
                if (existingUser != null)
                {
                     logger.LogWarning("Register endpoint: Found existing user: {Username}. Returning Conflict.", request.Email);
                     return Results.Conflict(new { Message = $"Username '{request.Email}' already exists." });
                }
                logger.LogDebug("Register endpoint: User {NormalizedUsername} does not exist.", normalizedUsername);
            }
            catch (Exception ex)
            {
                 logger.LogError(ex, "Error checking for existing user {Username} during registration", request.Email);
                 return Results.Problem("An unexpected error occurred during registration.", statusCode: StatusCodes.Status500InternalServerError);
            }

            // --- User does not exist, proceed with creation ---
            logger.LogDebug("Register endpoint: Proceeding to create new user: {Username}", request.Email);
            var newUser = new CoreIdentUser
            {
                UserName = request.Email, // Assuming email is username for now
                NormalizedUserName = normalizedUsername, // Use already normalized name
                PasswordHash = passwordHasher.HashPassword(null, request.Password!) // Pass null for user context during creation
            };

            // Redundant Check: Ensure NormalizedUserName is set before attempting to save (already checked above indirectly)
            // if (string.IsNullOrWhiteSpace(newUser.NormalizedUserName)) ...

            try
            {
                var result = await userStore.CreateUserAsync(newUser, cancellationToken);
                 logger.LogDebug("Register endpoint: CreateUserAsync result: {Result} for user {Username}", result, request.Email);
                return result switch
                {
                    StoreResult.Success => Results.Created($"/{newUser.Id}", new { UserId = newUser.Id, Message = "User registered successfully." }), // Use Created (201) for resource creation
                    StoreResult.Conflict => Results.Conflict(new { Message = $"Username '{request.Email}' already exists." }),
                    _ => Results.Problem("An unexpected error occurred during registration.", statusCode: StatusCodes.Status500InternalServerError),
                };
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error during user registration for {Username}", request.Email);
                return Results.Problem("An unexpected error occurred during registration.", statusCode: StatusCodes.Status500InternalServerError);
            }
        })
        .WithName("RegisterUser")
        .WithTags("CoreIdent")
        .Produces(StatusCodes.Status201Created)
        .Produces<ValidationProblemDetails>(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status409Conflict)
        .Produces(StatusCodes.Status500InternalServerError)
        .WithSummary("Registers a new user.")
        .WithDescription("Creates a new user account with the provided email and password.");


        // Endpoint: /login
        routeGroup.MapPost("login", async (
            [FromBody] LoginRequest request,
            HttpContext httpContext,
            IUserStore userStore,
            IPasswordHasher passwordHasher,
            ITokenService tokenService,
            IRefreshTokenStore refreshTokenStore,
            IOptions<CoreIdentOptions> options,
            ILoggerFactory loggerFactory,
            CancellationToken cancellationToken) =>
        {
            var logger = loggerFactory.CreateLogger("CoreIdent.Login");

            var validationResults = new List<ValidationResult>();
            if (!Validator.TryValidateObject(request, new ValidationContext(request), validationResults, validateAllProperties: true))
            {
                return Results.ValidationProblem(validationResults.ToDictionary(vr => vr.MemberNames.FirstOrDefault() ?? string.Empty, vr => vr.ErrorMessage?.Split(',') ?? Array.Empty<string>()));
            }

            // Find user by normalized username
            var normalizedUsername = request.Email!.ToUpperInvariant();
            CoreIdentUser? user;
            try
            {
                user = await userStore.FindUserByUsernameAsync(normalizedUsername, cancellationToken);
            }
            catch (Exception ex)
            {
                 logger.LogError(ex, "Error finding user by username {Username} during login", request.Email);
                 return Results.Problem("An unexpected error occurred during login.", statusCode: StatusCodes.Status500InternalServerError);
            }

            if (user == null || user.PasswordHash == null)
            {
                logger.LogWarning("Login attempt failed: User {Username} not found or has no password.", request.Email);
                return Results.Unauthorized();
            }

            // --- Use IUserStore to validate credentials ---
            PasswordVerificationResult passwordVerificationResult;
            try
            {
                // This allows the store (like DelegatedUserStore) to handle validation
                passwordVerificationResult = await userStore.ValidateCredentialsAsync(normalizedUsername, request.Password!, cancellationToken);
            }
            catch (Exception ex)
            {
                 logger.LogError(ex, "Error validating credentials for user {Username}", request.Email);
                 // Consider if specific store exceptions should lead to different results
                 return Results.Problem("An unexpected error occurred during credential validation.", statusCode: StatusCodes.Status500InternalServerError);
            }

            // --- Check validation result ---
            if (passwordVerificationResult == PasswordVerificationResult.Failed)
            {
                logger.LogWarning("Password verification failed for user {Username}", request.Email); // Keep log generic
                // TODO: Increment AccessFailedCount and check for lockout via IUserStore methods
                return Results.Unauthorized(); // Incorrect password or validation failed
            }

            // Password verification successful (or needs rehashing - handle if store supports it)
            if (passwordVerificationResult == PasswordVerificationResult.SuccessRehashNeeded)
            {
                logger.LogInformation("Password requires rehashing for user {Username}. Attempting to update hash.", request.Email);
                try
                {
                    // Hash the current password using the latest algorithm/settings
                    var newHash = passwordHasher.HashPassword(user, request.Password!);
                    await userStore.SetPasswordHashAsync(user, newHash, cancellationToken);
                    // Optionally update the user object in memory if needed for token generation
                    user.PasswordHash = newHash;
                    logger.LogInformation("Password hash updated successfully for user {Username}.", request.Email);
                }
                catch (Exception ex)
                {
                    // Log error but proceed with login - hash update failure shouldn't block login
                    logger.LogError(ex, "Failed to update rehashed password for user {Username}", request.Email);
                }
            }

            // --- Reset AccessFailedCount on successful login --- (if applicable)
            // TODO: await userStore.ResetAccessFailedCountAsync(user, cancellationToken);

            // Generate tokens
            var accessToken = await tokenService.GenerateAccessTokenAsync(user, new[] { "openid", "profile", "email" }); // Example scopes
            string? refreshTokenHandle = null;
            // Remove the incorrect check for user.AllowRefreshToken
            // Always attempt to generate refresh token for password grant if client allows
            const string clientIdForPasswordFlow = "__password_flow__"; // Client ID associated with password grant
            try
            {
                logger.LogDebug("Attempting to generate and store refresh token for user {UserId} and client {ClientId}", user.Id, clientIdForPasswordFlow);
                refreshTokenHandle = await tokenService.GenerateAndStoreRefreshTokenAsync(user, clientIdForPasswordFlow);
                logger.LogInformation("Generated refresh token handle for user {UserId}: {RefreshTokenHandle}", user.Id, refreshTokenHandle ?? "<null>"); // Log handle after generation
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to generate or store refresh token for user {UserId}", user.Id);
                // Decide if login should fail here? For now, continue without refresh token.
                refreshTokenHandle = null;
            }

            logger.LogInformation("User {UserName} successfully logged in.", request.Email);

            // Prepare response
            var tokenResponse = new TokenResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshTokenHandle, // Assign handle
                ExpiresIn = 3600, // TODO: Get actual lifetime from config or token itself
                TokenType = "Bearer"
            };

            // Log the response object *before* returning
            logger.LogDebug("Returning TokenResponse: AccessTokenPresent={AccessTokenPresent}, RefreshTokenPresent={RefreshTokenPresent}", 
                            !string.IsNullOrEmpty(tokenResponse.AccessToken), 
                            !string.IsNullOrEmpty(tokenResponse.RefreshToken));

            return Results.Ok(tokenResponse);
        })
        .WithName("LoginUser")
        .WithTags("CoreIdent")
        .Produces<TokenResponse>(StatusCodes.Status200OK)
        .Produces<ValidationProblemDetails>(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status401Unauthorized)
        .Produces(StatusCodes.Status500InternalServerError)
        .WithSummary("Logs in a user.")
        .WithDescription("Authenticates a user with email and password, returning JWT tokens.");

        // Endpoint: /token/refresh (Refactored for IRefreshTokenStore and Rotation)
        routeGroup.MapPost("token/refresh", async (
            [FromBody] RefreshTokenRequest request,
            IUserStore userStore,
            ITokenService tokenService,
            IRefreshTokenStore refreshTokenStore,
            IOptions<CoreIdentOptions> options,
            ILoggerFactory loggerFactory,
            CancellationToken cancellationToken) =>
        {
            var logger = loggerFactory.CreateLogger("CoreIdent.RefreshToken");

            // Basic validation
            if (request == null || string.IsNullOrWhiteSpace(request.RefreshToken))
            {
                return Results.BadRequest(new { Message = "Refresh token is required." });
            }

            // Validate the incoming refresh token handle using the store
            CoreIdentRefreshToken? existingToken;
            try
            {
                existingToken = await refreshTokenStore.GetRefreshTokenAsync(request.RefreshToken, cancellationToken);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error retrieving refresh token during refresh operation.");
                return Results.Problem("An unexpected error occurred during token validation.", statusCode: StatusCodes.Status500InternalServerError);
            }

            // Validation checks
            if (existingToken == null)
            {
                logger.LogWarning("Refresh token handle not found: {RefreshTokenHandle}", request.RefreshToken);
                return Results.Unauthorized(); // Token not found
            }
            if (existingToken.ConsumedTime.HasValue)
            {
                logger.LogWarning("Attempted reuse of consumed refresh token: {RefreshTokenHandle}", request.RefreshToken);
                // Implement token theft detection response
                try 
                {
                    var theftDetectionMode = options.Value.TokenSecurity.TokenTheftDetectionMode;
                    
                    if (theftDetectionMode != TokenTheftDetectionMode.Silent)
                    {
                        logger.LogWarning("Potential token theft detected for user {SubjectId}, client {ClientId}, token family {FamilyId}. Taking action: {Action}", 
                            existingToken.SubjectId, existingToken.ClientId, existingToken.FamilyId, theftDetectionMode);
                        
                        if (theftDetectionMode == TokenTheftDetectionMode.RevokeFamily)
                        {
                            // Revoke all tokens in this family
                            await refreshTokenStore.RevokeTokenFamilyAsync(existingToken.FamilyId, cancellationToken);
                            logger.LogWarning("Revoked all tokens in family {FamilyId} due to potential token theft", existingToken.FamilyId);
                        }
                        else if (theftDetectionMode == TokenTheftDetectionMode.RevokeAllUserTokens)
                        {
                            // Find tokens by user ID and revoke them all
                            var userTokens = await refreshTokenStore.FindTokensBySubjectIdAsync(existingToken.SubjectId, cancellationToken);
                            int count = 0;
                            
                            foreach (var token in userTokens.Where(t => !t.ConsumedTime.HasValue))
                            {
                                token.ConsumedTime = DateTime.UtcNow;
                                await refreshTokenStore.RemoveRefreshTokenAsync(token.Handle, cancellationToken);
                                count++;
                            }
                            
                            logger.LogWarning("Revoked {Count} active tokens for user {SubjectId} due to potential token theft", count, existingToken.SubjectId);
                        }
                    }
                }
                catch (Exception ex)
                {
                    // Log but don't block response - security action is best effort
                    logger.LogError(ex, "Error during token theft response for token {RefreshTokenHandle}", request.RefreshToken);
                }
                
                return Results.Unauthorized(); // Token already used
            }
            if (existingToken.ExpirationTime < DateTime.UtcNow)
            {
                 logger.LogWarning("Expired refresh token presented: {RefreshTokenHandle}", request.RefreshToken);
                 return Results.Unauthorized(); // Token expired
            }

            // Mark the old token as consumed *before* issuing new ones
            try
            {
                await refreshTokenStore.RemoveRefreshTokenAsync(existingToken.Handle, cancellationToken);
            }
            catch(Exception ex)
            {
                logger.LogError(ex, "Error consuming old refresh token {RefreshTokenHandle} during refresh.", existingToken.Handle);
                // Fail the operation if we can't consume the old token to prevent potential replay
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
                // If user lookup fails, the old token is already consumed. Return error.
                return Results.Problem("An unexpected error occurred during user lookup.", statusCode: StatusCodes.Status500InternalServerError);
            }

            if (user == null)
            {
                logger.LogError("User {UserId} associated with refresh token {RefreshTokenHandle} not found.", existingToken.SubjectId, existingToken.Handle);
                // Old token consumed, user not found - return Unauthorized
                return Results.Unauthorized();
            }

            // Generate NEW tokens
            string newAccessToken;
            string newRefreshTokenHandle;
            try
            {
                // Refresh token grant typically reuses original scopes implicitly
                // TODO: Potentially retrieve original scopes associated with the refresh token if needed?
                newAccessToken = await tokenService.GenerateAccessTokenAsync(user);
                
                // Generate descendant token to maintain the family lineage for token theft detection
                if (options.Value.TokenSecurity.EnableTokenFamilyTracking)
                {
                    newRefreshTokenHandle = await tokenService.GenerateAndStoreRefreshTokenAsync(user, existingToken.ClientId, existingToken);
                }
                else
                {
                    // Create a new token family if tracking is disabled
                    newRefreshTokenHandle = await tokenService.GenerateAndStoreRefreshTokenAsync(user, existingToken.ClientId);
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error generating new tokens for user {UserId} during refresh", user.Id);
                return Results.Problem("An unexpected error occurred during token generation.", statusCode: StatusCodes.Status500InternalServerError);
            }

            // Log the generated handle
            logger.LogDebug("Generated new refresh token handle during refresh for user {UserId}: {RefreshTokenHandle}", user.Id, newRefreshTokenHandle ?? "<null>");

            var response = new TokenResponse
            {
                AccessToken = newAccessToken,
                ExpiresIn = (int)options.Value.AccessTokenLifetime.TotalSeconds,
                RefreshToken = newRefreshTokenHandle,
                TokenType = "Bearer" // Add missing TokenType
                // No IdToken or Scope for refresh token grant
            };

            logger.LogInformation("Tokens refreshed successfully for user {UserId}", user.Id);
            
            // Log the response object *before* returning
            logger.LogDebug("Returning TokenResponse from refresh: AccessTokenPresent={AccessTokenPresent}, RefreshTokenPresent={RefreshTokenPresent}", 
                            !string.IsNullOrEmpty(response.AccessToken), 
                            !string.IsNullOrEmpty(response.RefreshToken));

            return Results.Ok(response);
        })
        .WithName("RefreshToken")
        .WithTags("CoreIdent")
        .Produces<TokenResponse>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status400BadRequest) // Invalid request (e.g., missing token)
        .Produces(StatusCodes.Status401Unauthorized) // Invalid/Expired/Consumed token or User not found
        .Produces(StatusCodes.Status500InternalServerError)
        .WithSummary("Exchanges a refresh token for new tokens.")
        .WithDescription("Provides a new access and refresh token if the provided refresh token is valid and unused.");


        // --- Phase 3: OAuth/OIDC Endpoints ---

        // Endpoint: GET /authorize
        // Handles the start of the Authorization Code flow.
        routeGroup.MapGet("authorize", async (
            HttpRequest request, // Access query parameters directly
            HttpResponse response, // Needed for redirects
            HttpContext httpContext,
            IClientStore clientStore,
            IScopeStore scopeStore,
            ILoggerFactory loggerFactory,
            CancellationToken cancellationToken
            ) =>
        {
            var logger = loggerFactory.CreateLogger("CoreIdent.Authorize");
            logger.LogInformation("Authorize endpoint hit: {Query}", request.QueryString);

            // 1. Parse and Validate Request Parameters
            // Required parameters for 'code' flow:
            string? clientId = request.Query["client_id"];
            string? redirectUri = request.Query["redirect_uri"];
            string? responseType = request.Query["response_type"]; // MUST be 'code'
            string? scope = request.Query["scope"]; // Space-separated list
            string? state = request.Query["state"]; // Recommended
            // PKCE parameters (required for 'code' flow with public clients)
            string? codeChallenge = request.Query["code_challenge"];
            string? codeChallengeMethod = request.Query["code_challenge_method"]; // 'S256' or 'plain'
            // OIDC parameter
            string? nonce = request.Query["nonce"]; // Recommended for OIDC

            // Basic validation
            if (string.IsNullOrWhiteSpace(clientId) ||
                string.IsNullOrWhiteSpace(redirectUri) ||
                string.IsNullOrWhiteSpace(responseType) ||
                string.IsNullOrWhiteSpace(scope))
            {
                // TODO: Redirect back to client with error=invalid_request
                logger.LogWarning("Authorize request missing required parameters.");
                return Results.BadRequest(new { error = "invalid_request", error_description = "Missing required parameters (client_id, redirect_uri, response_type, scope)." });
            }

            if (responseType != "code")
            {
                 // TODO: Redirect back to client with error=unsupported_response_type
                logger.LogWarning("Authorize request has unsupported response_type: {ResponseType}", responseType);
                return Results.BadRequest(new { error = "unsupported_response_type", error_description = "Only 'code' response_type is supported." });
            }

            // PKCE validation (MUST be present if client is public, RECOMMENDED for confidential)
            // Client check (Requires IClientStore lookup) will determine if PKCE is strictly required.
            // For now, let's assume required if provided.
            if (!string.IsNullOrWhiteSpace(codeChallenge) && string.IsNullOrWhiteSpace(codeChallengeMethod))
            {
                // TODO: Redirect back to client with error=invalid_request
                logger.LogWarning("Authorize request has code_challenge but missing code_challenge_method.");
                return Results.BadRequest(new { error = "invalid_request", error_description = "code_challenge_method is required when code_challenge is provided." });
            }
            if (!string.IsNullOrWhiteSpace(codeChallengeMethod) && codeChallengeMethod != "S256") // Only support S256 initially
            {
                // TODO: Redirect back to client with error=invalid_request
                logger.LogWarning("Authorize request uses unsupported code_challenge_method: {Method}", codeChallengeMethod);
                return Results.BadRequest(new { error = "invalid_request", error_description = "Only 'S256' code_challenge_method is supported." });
            }

             // 2. Validate Client and Redirect URI
            CoreIdentClient? client;
            try
            {
                client = await clientStore.FindClientByIdAsync(clientId, cancellationToken);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error retrieving client {ClientId} during authorization.", clientId);
                // TODO: Redirect back to client? Problem? For now, return 500.
                return Results.Problem("An unexpected error occurred during client validation.", statusCode: StatusCodes.Status500InternalServerError);
            }

            if (client == null || !client.Enabled)
            {
                logger.LogWarning("Authorize request for unknown or disabled client: {ClientId}", clientId);
                // Do NOT redirect back to an unvalidated redirect_uri on client error.
                return Results.BadRequest(new { error = "unauthorized_client", error_description = "Client is unknown or disabled." });
            }

            // Validate Redirect URI against registered URIs
            if (!client.RedirectUris.Contains(redirectUri))
            {
                 logger.LogWarning("Authorize request for client {ClientId} with invalid redirect_uri: {RedirectUri}", clientId, redirectUri);
                 // Do NOT redirect back.
                 return Results.BadRequest(new { error = "invalid_request", error_description = "Invalid redirect_uri." });
            }

            // TODO: Add check: if (client.RequirePkce && string.IsNullOrWhiteSpace(codeChallenge)) error...

            // 3. Validate Scopes
            var requestedScopes = scope?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? Enumerable.Empty<string>();
            IEnumerable<CoreIdentScope> validScopes;
             try
            {
                validScopes = await scopeStore.FindScopesByNameAsync(requestedScopes, cancellationToken);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error retrieving scopes during authorization for client {ClientId}. Scopes: {Scopes}", clientId, scope);
                // Redirect back with error?
                return Results.Problem("An unexpected error occurred during scope validation.", statusCode: StatusCodes.Status500InternalServerError);
            }
            // TODO: Check if all requested scopes were found and are enabled. Handle invalid scopes.
            // TODO: Check if requested scopes are allowed for the client (client.AllowedScopes). Redirect back with error=invalid_scope?

             // 4. Check User Authentication & Consent
             // This part requires integration with ASP.NET Core authentication middleware (e.g., cookies)
             // and a consent mechanism (Phase 4).
             // For now, we'll skip this and assume the user is authenticated and consented.
             var isAuthenticated = httpContext.User?.Identity?.IsAuthenticated ?? false;
             if (!isAuthenticated)
             {
                // TODO: Redirect to Login Page, passing the authorization request parameters so it can return here.
                logger.LogInformation("User not authenticated for authorize request. Redirecting to login.");
                // Example redirect (adapt to your login page path):
                // return Results.Redirect($"/Account/Login?ReturnUrl={Uri.EscapeDataString(request.GetEncodedUrl())}");
                return Results.Challenge(); // Returns 401, lets auth middleware handle redirect
             }

            // TODO: Check for existing consent/grants. If needed, redirect to Consent Page.

            // --- If authenticated and consented (or consent not required) ---

            // 5. Generate and Store Authorization Code
            var authorizationCode = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
                                    .Replace("+", "-").Replace("/", "_").TrimEnd('='); // URL-safe
            var codeLifetime = TimeSpan.FromMinutes(5); // Example lifetime
            var subjectId = httpContext.User?.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrWhiteSpace(subjectId))
            {
                logger.LogError("Authenticated user is missing Subject ID (sub) claim.");
                // This shouldn't happen for a properly authenticated user via OIDC/JWT principles
                return Results.Problem("User identifier missing.", statusCode: StatusCodes.Status500InternalServerError);
            }

            // Ensure IAuthorizationCodeStore is resolved
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

            var storedCode = new AuthorizationCode
            {
                CodeHandle = authorizationCode,
                ClientId = clientId,
                SubjectId = subjectId,
                RequestedScopes = requestedScopes.ToList(), // Store the validated scopes
                RedirectUri = redirectUri,
                Nonce = nonce,
                CodeChallenge = codeChallenge,
                CodeChallengeMethod = codeChallengeMethod,
                CreationTime = DateTime.UtcNow,
                ExpirationTime = DateTime.UtcNow.Add(codeLifetime)
            };

            try
            {
                await authorizationCodeStore.StoreAuthorizationCodeAsync(storedCode, cancellationToken);
                logger.LogInformation("Stored authorization code {CodeHandle} for client {ClientId} and user {UserId}", 
                    authorizationCode, clientId, subjectId);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to store authorization code {CodeHandle}", authorizationCode);
                return Results.Problem("Failed to store authorization request.", statusCode: StatusCodes.Status500InternalServerError);
            }

            // 6. Redirect Back to Client
            var redirectUrlBuilder = new StringBuilder(redirectUri);
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
        // TODO: Define Produces responses accurately (Redirect, BadRequest, Problem)
        .Produces(StatusCodes.Status302Found) // Redirect
        .Produces<ProblemDetails>(StatusCodes.Status400BadRequest)
        .Produces<ProblemDetails>(StatusCodes.Status500InternalServerError)
        .WithSummary("Starts the OAuth 2.0 Authorization Code flow.")
        .WithDescription("Validates the client request and redirects the user agent back to the client with an authorization code.");


        // Endpoint: POST /token
        // Handles various grant types for token issuance.
        routeGroup.MapPost("token", async (
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
            // --- Add other grant types (client_credentials, password, refresh_token) here later ---
            // else if (grantType == "client_credentials") { ... }
            // else if (grantType == "refresh_token") { ... Reuse existing /token/refresh logic or integrate here ... }
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
        .Produces<ProblemDetails>(StatusCodes.Status400BadRequest) // invalid_request, invalid_grant, invalid_client, unsupported_grant_type
        .Produces<ProblemDetails>(StatusCodes.Status500InternalServerError)
        .WithSummary("Exchanges various grants for access tokens.")
        .WithDescription("Handles token issuance based on grant types like authorization_code, client_credentials, etc.");



        return routeGroup;
    }
}


// --- Placeholder for Authorization Code Store (Needs implementation, e.g., EF Core) ---
// Should be registered in DI
public class InMemoryAuthorizationCodeStore : IAuthorizationCodeStore
{
    private readonly ConcurrentDictionary<string, AuthorizationCode> _codes = new();
    private readonly ILogger<InMemoryAuthorizationCodeStore> _logger;

    public InMemoryAuthorizationCodeStore(ILogger<InMemoryAuthorizationCodeStore> logger)
    {
        _logger = logger;
    }

    public Task StoreAuthorizationCodeAsync(AuthorizationCode code, CancellationToken cancellationToken)
    {
        _codes[code.CodeHandle] = code;
        _logger.LogDebug("Stored authorization code: {CodeHandle}, Expires: {Expiry}", code.CodeHandle, code.ExpirationTime);
        // Start a background task to remove expired code (simple cleanup)
        _ = Task.Delay(code.ExpirationTime - DateTime.UtcNow + TimeSpan.FromSeconds(5), cancellationToken)
            .ContinueWith(_ =>
            {
                if (_codes.TryRemove(code.CodeHandle, out var removedCode) && removedCode.ExpirationTime <= DateTime.UtcNow)
                {
                    _logger.LogDebug("Removed expired authorization code: {CodeHandle}", code.CodeHandle);
                }
            }, CancellationToken.None); // Use CancellationToken.None for the cleanup task

        return Task.CompletedTask;
    }

    public Task<AuthorizationCode?> GetAuthorizationCodeAsync(string codeHandle, CancellationToken cancellationToken)
    {
        _codes.TryGetValue(codeHandle, out var code);
        if (code != null && code.ExpirationTime < DateTime.UtcNow)
        {
             _logger.LogDebug("Attempted to retrieve expired code: {CodeHandle}", codeHandle);
             _codes.TryRemove(codeHandle, out _); // Remove expired on retrieval attempt
            return Task.FromResult<AuthorizationCode?>(null);
        }
        _logger.LogDebug("Retrieved authorization code: {CodeHandle} (Found: {Found})", codeHandle, code != null);
        return Task.FromResult(code);
    }

    public Task RemoveAuthorizationCodeAsync(string codeHandle, CancellationToken cancellationToken)
    {
        if (_codes.TryRemove(codeHandle, out _))
        {
             _logger.LogDebug("Removed authorization code: {CodeHandle}", codeHandle);
        }
        else
        {
             _logger.LogDebug("Attempted to remove non-existent code: {CodeHandle}", codeHandle);
        }
        return Task.CompletedTask;
    }
}
