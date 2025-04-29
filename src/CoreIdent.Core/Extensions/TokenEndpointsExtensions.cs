using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Models.Requests;
using CoreIdent.Core.Models.Responses;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;

namespace CoreIdent.Core.Extensions
{
    /// <summary>
    /// Extension methods for mapping token and OIDC discovery endpoints.
    /// </summary>
    public static class TokenEndpointsExtensions
    {
        /// <summary>
        /// Maps /token endpoint.
        /// </summary>
        public static void MapTokenEndpoints(this IEndpointRouteBuilder endpoints, CoreIdentRouteOptions routeOptions)
        {
            // POST /token - Main token endpoint for all grant types
            var logger = endpoints.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("TokenEndpoints");
            logger.LogInformation("Registering token endpoint at path: {Path}", routeOptions.Combine(routeOptions.TokenPath));

            endpoints.MapPost(routeOptions.TokenPath, async (
                HttpRequest request,
                HttpContext httpContext,
                IClientStore clientStore,
                IAuthorizationCodeStore authCodeStore,
                IUserStore userStore,
                ITokenService tokenService,
                IRefreshTokenStore refreshTokenStore,
                IPasswordHasher passwordHasher,
                IOptions<CoreIdentOptions> options,
                ILoggerFactory loggerFactory,
                CancellationToken cancellationToken) =>
            {
                // Use ErrorResponse DTO for consistency
                Func<string, string, IResult> CreateErrorResult = (error, description) =>
                    Results.BadRequest(new ErrorResponse { Error = error, ErrorDescription = description });

                TokenRequest? requestBody = null;
                string? clientId = null;
                string? clientSecret = null;
                var handlerLogger = loggerFactory.CreateLogger("TokenEndpoint"); // Use consistent logger name

                // Check if client credentials are in Authorization header (Basic auth)
                var authHeader = request.Headers.Authorization.ToString();
                if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        var encodedCredentials = authHeader.Substring("Basic ".Length).Trim();
                        var decodedCredentials = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(encodedCredentials));
                        var credentials = decodedCredentials.Split(':');
                        if (credentials.Length == 2)
                        {
                            clientId = credentials[0];
                            clientSecret = credentials[1];
                        }
                    }
                    catch (Exception ex)
                    {
                        var authLogger = loggerFactory.CreateLogger("TokenEndpoint.Auth");
                        authLogger.LogWarning(ex, "Failed to parse Basic authorization header");
                    }
                }

                // Check content type to determine how to read the request
                var contentType = request.ContentType?.ToLower() ?? string.Empty;

                try
                {
                    if (contentType.Contains("application/json"))
                    {
                        // Read as JSON if content type is application/json
                        requestBody = await request.ReadFromJsonAsync<TokenRequest>();
                    }
                    else if (contentType.Contains("application/x-www-form-urlencoded"))
                    {
                        // Read as form data if content type is form-urlencoded (typical for OAuth flows)
                        var form = await request.ReadFormAsync(cancellationToken);
                        requestBody = new TokenRequest
                        {
                            GrantType = form["grant_type"].ToString(),
                            Code = form["code"].ToString(),
                            ClientId = form["client_id"].ToString(),
                            ClientSecret = form["client_secret"].ToString(),
                            RedirectUri = form["redirect_uri"].ToString(),
                            RefreshToken = form["refresh_token"].ToString(),
                            Scope = form["scope"].ToString(),
                            Username = form["username"].ToString(),
                            Password = form["password"].ToString()
                        };

                        // Store code_verifier in HttpContext items if needed - it's not part of TokenRequest
                        if (!string.IsNullOrEmpty(form["code_verifier"].ToString()))
                        {
                            httpContext.Items["code_verifier"] = form["code_verifier"].ToString();
                        }
                    }
                    else
                    {
                        handlerLogger.LogWarning("Unsupported content type: {ContentType}", contentType);
                    }
                }
                catch (Exception ex)
                {
                    handlerLogger.LogError(ex, "Error parsing token request");
                    return CreateErrorResult("invalid_request", "Could not parse the request");
                }

                if (requestBody == null)
                {
                    return CreateErrorResult("invalid_request", "The request body is invalid or missing");
                }

                var grantType = requestBody.GrantType;
                if (string.IsNullOrEmpty(grantType))
                {
                    return CreateErrorResult("invalid_request", "The grant_type parameter is required");
                }

                // If client credentials were found in Authorization header, they take precedence
                // over any client_id/client_secret in the request body
                if (!string.IsNullOrEmpty(clientId))
                {
                    requestBody.ClientId = clientId;
                }
                if (!string.IsNullOrEmpty(clientSecret))
                {
                    requestBody.ClientSecret = clientSecret;
                }

                // --- Client Authentication (Moved here for all grants except password which is implicit) ---
                CoreIdentClient? client = null;
                if (grantType != "password") // Password grant uses implicit client
                {
                    if (string.IsNullOrEmpty(requestBody.ClientId))
                    {
                        return CreateErrorResult("invalid_client", "Client authentication failed (client_id missing).");
                    }
                    try
                    {
                        client = await clientStore.FindClientByIdAsync(requestBody.ClientId, cancellationToken);
                    }
                    catch (Exception ex)
                    {
                        handlerLogger.LogError(ex, "Error retrieving client {ClientId} during token request.", requestBody.ClientId);
                        return Results.Problem("An unexpected error occurred during client lookup.", statusCode: StatusCodes.Status500InternalServerError);
                    }

                    if (client == null || !client.Enabled)
                    {
                        handlerLogger.LogWarning("Token request for unknown or disabled client: {ClientId}", requestBody.ClientId);
                        return CreateErrorResult("invalid_client", "Client is unknown or disabled.");
                    }

                    // Validate client secret if required (confidential client)
                    bool isConfidentialClient = client.ClientSecrets?.Any() ?? false;
                    if (isConfidentialClient)
                    {
                        if (string.IsNullOrWhiteSpace(requestBody.ClientSecret))
                        {
                            handlerLogger.LogWarning("Missing client_secret for confidential client {ClientId}", requestBody.ClientId);
                            return CreateErrorResult("invalid_client", "Client secret is required for this client.");
                        }

                        bool validSecret = false;
                        if (client.ClientSecrets != null)
                        {
                            foreach (var storedSecret in client.ClientSecrets)
                            {
                                var verificationResult = passwordHasher.VerifyHashedPassword(null, storedSecret.Value, requestBody.ClientSecret);
                                if (verificationResult != PasswordVerificationResult.Failed)
                                {
                                    validSecret = true;
                                    // TODO: Handle rehash if needed
                                    break;
                                }
                            }
                        }

                        if (!validSecret)
                        {
                            handlerLogger.LogWarning("Invalid client_secret provided for client {ClientId}", requestBody.ClientId);
                            return CreateErrorResult("invalid_client", "Invalid client secret.");
                        }
                    }
                }

                switch (grantType)
                {
                    case "authorization_code":
                        if (client == null) // Should have been loaded above
                            return CreateErrorResult("invalid_client", "Client validation failed.");

                        if (string.IsNullOrEmpty(requestBody.Code) || string.IsNullOrEmpty(requestBody.RedirectUri))
                        {
                            return CreateErrorResult("invalid_request", "Missing required parameters for authorization_code grant (code, redirect_uri).");
                        }

                        var authCode = await authCodeStore.GetAuthorizationCodeAsync(requestBody.Code, cancellationToken);

                        // Validate the code
                        if (authCode == null)
                        {
                            handlerLogger.LogWarning("Authorization code not found: {CodeHandle}", requestBody.Code);
                            return CreateErrorResult("invalid_grant", "Authorization code is invalid or expired.");
                        }

                        // Validate ClientId
                        if (authCode.ClientId != client.ClientId)
                        {
                            handlerLogger.LogError("Client mismatch for authorization code {CodeHandle}. Expected {ExpectedClient}, Got {ActualClient}", requestBody.Code, authCode.ClientId, client.ClientId);
                            await authCodeStore.RemoveAuthorizationCodeAsync(requestBody.Code, cancellationToken); // Consume invalid code
                            return CreateErrorResult("invalid_grant", "Client mismatch.");
                        }

                        // Validate RedirectUri
                        if (authCode.RedirectUri != requestBody.RedirectUri)
                        {
                            handlerLogger.LogWarning("Redirect URI mismatch for authorization code {CodeHandle}. Expected {ExpectedUri}, Got {ActualUri}", requestBody.Code, authCode.RedirectUri, requestBody.RedirectUri);
                            await authCodeStore.RemoveAuthorizationCodeAsync(requestBody.Code, cancellationToken); // Consume invalid code
                            return CreateErrorResult("invalid_grant", "Redirect URI mismatch.");
                        }

                        // Check expiration (redundant if Get returns null for expired, but safe)
                        if (authCode.ExpirationTime < DateTime.UtcNow)
                        {
                            handlerLogger.LogWarning("Expired authorization code presented: {CodeHandle}", requestBody.Code);
                            // Already removed implicitly by Get or explicitly below
                            return CreateErrorResult("invalid_grant", "Authorization code expired.");
                        }

                        // PKCE Validation
                        if (!string.IsNullOrEmpty(authCode.CodeChallenge))
                        {
                            string? codeVerifier = null;
                            if (httpContext.Items.TryGetValue("code_verifier", out var codeVerifierObj))
                            {
                                codeVerifier = codeVerifierObj as string;
                            }

                            if (string.IsNullOrEmpty(codeVerifier))
                            {
                                handlerLogger.LogWarning("Missing code_verifier for PKCE flow. Code: {CodeHandle}", requestBody.Code);
                                await authCodeStore.RemoveAuthorizationCodeAsync(requestBody.Code, cancellationToken);
                                return CreateErrorResult("invalid_grant", "Missing PKCE code_verifier.");
                            }

                            bool isValidCodeVerifier = false;
                            if (authCode.CodeChallengeMethod == "S256")
                            {
                                using var sha256 = SHA256.Create();
                                var challengeBytes = sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
                                var calculatedChallenge = Base64UrlEncode(challengeBytes);
                                isValidCodeVerifier = string.Equals(calculatedChallenge, authCode.CodeChallenge, StringComparison.Ordinal);
                            }
                            // else if (authCode.CodeChallengeMethod == "plain") { /* Plain support removed for simplicity */ }

                            if (!isValidCodeVerifier)
                            {
                                handlerLogger.LogWarning("Invalid code_verifier for PKCE flow. Code: {CodeHandle}", requestBody.Code);
                                await authCodeStore.RemoveAuthorizationCodeAsync(requestBody.Code, cancellationToken);
                                return CreateErrorResult("invalid_grant", "Invalid PKCE code_verifier.");
                            }
                        }
                        else if (client.RequirePkce) // Client requires PKCE, but code has no challenge
                        {
                            handlerLogger.LogError("Client {ClientId} requires PKCE, but authorization code {CodeHandle} was issued without a challenge.", client.ClientId, requestBody.Code);
                            await authCodeStore.RemoveAuthorizationCodeAsync(requestBody.Code, cancellationToken);
                            return CreateErrorResult("invalid_grant", "PKCE required by client but not used in authorization.");
                        }

                        // --- Validation successful --- Consume the code ---
                        try
                        {
                            await authCodeStore.RemoveAuthorizationCodeAsync(requestBody.Code, cancellationToken);
                        }
                        catch (Exception ex)
                        {
                            handlerLogger.LogError(ex, "Failed to remove consumed authorization code {CodeHandle}", requestBody.Code);
                            return Results.Problem("Failed to consume authorization code.", statusCode: StatusCodes.Status500InternalServerError);
                        }

                        // --- Get User ---
                        var user = await userStore.FindUserByIdAsync(authCode.SubjectId, cancellationToken);
                        if (user == null)
                        {
                            handlerLogger.LogError("User {UserId} not found for valid authorization code {CodeHandle}", authCode.SubjectId, requestBody.Code);
                            return CreateErrorResult("invalid_grant", "User associated with authorization code not found.");
                        }

                        // --- Issue Tokens ---
                        try
                        {
                            var accessToken = await tokenService.GenerateAccessTokenAsync(user, authCode.RequestedScopes);
                            var idToken = await tokenService.GenerateIdTokenAsync(user, client.ClientId, authCode.Nonce, authCode.RequestedScopes);
                            string? generatedRefreshToken = null;

                            if (authCode.RequestedScopes.Contains("offline_access") && client.AllowOfflineAccess)
                            {
                                generatedRefreshToken = await tokenService.GenerateAndStoreRefreshTokenAsync(user, client.ClientId);
                            }

                            var tokenResponse = new TokenResponse
                            {
                                AccessToken = accessToken,
                                TokenType = "Bearer",
                                ExpiresIn = (int)options.Value.AccessTokenLifetime.TotalSeconds,
                                RefreshToken = generatedRefreshToken,
                                IdToken = idToken,
                                Scope = string.Join(" ", authCode.RequestedScopes)
                            };

                            handlerLogger.LogInformation("Tokens issued successfully via authorization_code grant for client {ClientId} and user {UserId}", client.ClientId, user.Id);
                        return Results.Ok(tokenResponse);
                        }
                        catch (Exception ex)
                        {
                             handlerLogger.LogError(ex, "Error issuing tokens during authorization_code grant for client {ClientId} user {UserId}", client.ClientId, user.Id);
                             return Results.Problem("An unexpected error occurred during token generation.", statusCode: StatusCodes.Status500InternalServerError);
                        }

                    case "client_credentials":
                         if (client == null) // Should have been loaded above
                             return CreateErrorResult("invalid_client", "Client validation failed.");

                        // Validate Grant Type allowed for client
                        if (!(client.AllowedGrantTypes?.Contains("client_credentials") ?? false))
                        {
                            handlerLogger.LogWarning("Client {ClientId} is not allowed to use grant_type=client_credentials.", client.ClientId);
                            return CreateErrorResult("unauthorized_client", "Client is not authorized to use this grant type.");
                        }

                        // Validate Scopes
                        var requestedScopes = requestBody.Scope?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? Enumerable.Empty<string>();
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
                                handlerLogger.LogError(ex, "Error retrieving scopes during client_credentials grant for client {ClientId}. Scopes: {Scopes}", client.ClientId, requestBody.Scope);
                                return Results.Problem("An unexpected error occurred during scope validation.", statusCode: StatusCodes.Status500InternalServerError);
                            }

                            foreach (var requestedScopeName in requestedScopes)
                            {
                                var scopeDetail = validScopes.FirstOrDefault(s => s.Name == requestedScopeName);
                                if (scopeDetail == null || !scopeDetail.Enabled)
                                {
                                    handlerLogger.LogWarning("Client {ClientId} requested invalid or disabled scope: {Scope}", client.ClientId, requestedScopeName);
                                    return CreateErrorResult("invalid_scope", $"Scope '{requestedScopeName}' is invalid or disabled.");
                                }
                                if (!(client.AllowedScopes?.Contains(requestedScopeName) ?? false))
                                {
                                    handlerLogger.LogWarning("Client {ClientId} requested scope {Scope} which is not allowed for this client.", client.ClientId, requestedScopeName);
                                    return CreateErrorResult("invalid_scope", $"Scope '{requestedScopeName}' is not allowed for this client.");
                                }
                                grantedScopes.Add(requestedScopeName);
                            }
                            handlerLogger.LogInformation("Client {ClientId} granted scopes: [{GrantedScopes}]", client.ClientId, string.Join(", ", grantedScopes));
                        }
                        else
                        {
                            handlerLogger.LogInformation("Client {ClientId} requested no scopes.", client.ClientId);
                        }

                        // Issue Access Token
                        try
                        {
                            var clientAccessToken = await tokenService.GenerateAccessTokenAsync(client, grantedScopes);
                            var clientTokenResponse = new TokenResponse
                            {
                                AccessToken = clientAccessToken,
                                TokenType = "Bearer",
                                ExpiresIn = (int)options.Value.AccessTokenLifetime.TotalSeconds, // Set expiry
                                Scope = grantedScopes.Any() ? string.Join(" ", grantedScopes) : null // Set scope
                            };

                            handlerLogger.LogInformation("Access token issued successfully via client_credentials grant for client {ClientId}", client.ClientId);
                            return Results.Ok(clientTokenResponse);
                        }
                        catch (Exception ex)
                        {
                            handlerLogger.LogError(ex, "Error issuing tokens during client_credentials grant for client {ClientId}", client.ClientId);
                            return Results.Problem("An unexpected error occurred during token generation.", statusCode: StatusCodes.Status500InternalServerError);
                        }

                    case "refresh_token":
                         if (client == null) // Should have been loaded above (client_id is required for refresh)
                            return CreateErrorResult("invalid_client", "Client validation failed (client_id required).");

                        if (string.IsNullOrEmpty(requestBody.RefreshToken))
                        {
                            return CreateErrorResult("invalid_request", "The refresh_token parameter is required for the refresh_token grant.");
                        }

                        CoreIdentRefreshToken? refreshToken;
                        try
                        {
                            refreshToken = await refreshTokenStore.GetRefreshTokenAsync(requestBody.RefreshToken, cancellationToken);
                        }
                         catch (Exception ex)
                        {
                            handlerLogger.LogError(ex, "Error retrieving refresh token during refresh operation.");
                            return Results.Problem("An unexpected error occurred during token validation.", statusCode: StatusCodes.Status500InternalServerError);
                        }


                        if (refreshToken == null)
                        {
                            handlerLogger.LogWarning("Refresh token handle not found: {RefreshTokenHandle}", requestBody.RefreshToken);
                            return CreateErrorResult("invalid_grant", "The refresh token is invalid or has been revoked.");
                        }

                        // Check ClientId match FIRST
                         if (refreshToken.ClientId != client.ClientId)
                        {
                            handlerLogger.LogWarning("Client ID mismatch for refresh token {RefreshTokenHandle}. Expected {ExpectedClientId}, got {ActualClientId}.", refreshToken.Handle, refreshToken.ClientId, client.ClientId);
                            // Consider consuming the token here? Or just deny? Deny for now.
                            return CreateErrorResult("invalid_grant", "The refresh token was not issued to this client.");
                        }

                        if (refreshToken.ConsumedTime.HasValue)
                        {
                            handlerLogger.LogWarning("Attempted reuse of consumed refresh token: {RefreshTokenHandle}", requestBody.RefreshToken);
                            // Implement token theft detection response
                            try
                            {
                                var theftDetectionMode = options.Value.TokenSecurity.TokenTheftDetectionMode;
                                if (theftDetectionMode != TokenTheftDetectionMode.Silent)
                                {
                                    handlerLogger.LogWarning("Potential token theft detected for user {SubjectId}, client {ClientId}, token family {FamilyId}. Taking action: {Action}",
                                        refreshToken.SubjectId, refreshToken.ClientId, refreshToken.FamilyId, theftDetectionMode);
                                    if (theftDetectionMode == TokenTheftDetectionMode.RevokeFamily)
                                    {
                                    await refreshTokenStore.RevokeTokenFamilyAsync(refreshToken.FamilyId, cancellationToken);
                                        handlerLogger.LogWarning("Revoked all tokens in family {FamilyId} due to potential token theft", refreshToken.FamilyId);
                                    }
                                    // TODO: Implement RevokeAllUserTokens if needed
                                }
                            }
                            catch (Exception ex)
                            {
                                handlerLogger.LogError(ex, "Error during token theft response for token {RefreshTokenHandle}", requestBody.RefreshToken);
                                // Still return invalid_grant, but log the internal error
                            }
                            return CreateErrorResult("invalid_grant", "The refresh token has already been used.");
                        }

                        if (refreshToken.ExpirationTime < DateTime.UtcNow)
                        {
                            handlerLogger.LogWarning("Expired refresh token presented: {RefreshTokenHandle}", requestBody.RefreshToken);
                            await refreshTokenStore.RemoveRefreshTokenAsync(refreshToken.Handle, cancellationToken); // Consume expired token
                            return CreateErrorResult("invalid_grant", "The refresh token has expired.");
                        }

                        // Get User
                        var refreshUser = await userStore.FindUserByIdAsync(refreshToken.SubjectId, cancellationToken);
                        if (refreshUser == null)
                        {
                            handlerLogger.LogError("User {UserId} associated with refresh token {RefreshTokenHandle} not found.", refreshToken.SubjectId, refreshToken.Handle);
                            return CreateErrorResult("invalid_grant", "The user associated with this token does not exist.");
                        }

                        // Mark old token consumed and generate new tokens
                        string newAccessToken;
                        string newRefreshTokenHandle;
                        try
                        {
                             // Mark the old token as consumed *before* issuing new ones
                            await refreshTokenStore.RemoveRefreshTokenAsync(refreshToken!.Handle, cancellationToken); // This effectively consumes it

                            // Generate NEW tokens
                            newAccessToken = await tokenService.GenerateAccessTokenAsync(refreshUser); // TODO: Consider passing scopes if needed

                            if (options.Value.TokenSecurity.EnableTokenFamilyTracking && refreshToken != null)
                            {
                                // Pass the previous token for rotation/family tracking
                                newRefreshTokenHandle = await tokenService.GenerateAndStoreRefreshTokenAsync(refreshUser, client.ClientId, refreshToken);
                            }
                            else
                            {
                                // Generate a new token without linking to a previous one
                                newRefreshTokenHandle = await tokenService.GenerateAndStoreRefreshTokenAsync(refreshUser, client.ClientId);
                            }
                        }
                        catch(Exception ex)
                        {
                            handlerLogger.LogError(ex, "Error consuming old refresh token or generating new tokens for user {UserId} during refresh.", refreshUser.Id);
                            // This replaces the old remove/store block's potential failure point
                            return Results.Problem("An unexpected error occurred during token refresh processing.", statusCode: StatusCodes.Status500InternalServerError);
                        }


                        var refreshResponse = new TokenResponse
                        {
                            AccessToken = newAccessToken,
                            RefreshToken = newRefreshTokenHandle,
                            TokenType = "Bearer",
                            ExpiresIn = (int)options.Value.AccessTokenLifetime.TotalSeconds // Set expiry
                        };

                        handlerLogger.LogInformation("Tokens refreshed successfully for user {UserId} via grant_type=refresh_token", refreshUser.Id);
                        return Results.Ok(refreshResponse);

                    default:
                        return CreateErrorResult("unsupported_grant_type", $"Grant type '{grantType}' is not supported.");
                }
            })
            .WithName("TokenExchange")
            .WithTags("CoreIdent")
            .Produces<TokenResponse>(StatusCodes.Status200OK)
            .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError);

            // POST /token/refresh - Dedicated refresh token endpoint (for backward compatibility)
            logger.LogInformation("Registering token refresh endpoint at path: {Path}", routeOptions.Combine(routeOptions.RefreshTokenPath));

            endpoints.MapPost(routeOptions.RefreshTokenPath, async (
                HttpRequest request,
                HttpContext httpContext,
                ITokenService tokenService,
                IRefreshTokenStore refreshTokenStore,
                IUserStore userStore,
                IOptions<CoreIdentOptions> options,
                ILoggerFactory loggerFactory,
                CancellationToken cancellationToken) =>
            {
                var handlerLogger = loggerFactory.CreateLogger("RefreshTokenEndpoint");
                handlerLogger.LogInformation("RefreshToken endpoint accessed");

                // Use ErrorResponse DTO for consistency
                Func<string, string, IResult> CreateErrorResult = (error, description) =>
                    Results.BadRequest(new ErrorResponse { Error = error, ErrorDescription = description });

                try
                {
                    var form = await request.ReadFormAsync(cancellationToken);
                    var refreshTokenValue = form["refresh_token"].ToString();
                    var clientId = form["client_id"].ToString(); // Client ID might be needed depending on validation logic

                    if (string.IsNullOrEmpty(refreshTokenValue))
                    {
                        return CreateErrorResult("invalid_request", "The refresh_token parameter is required.");
                    }

                    CoreIdentRefreshToken? refreshToken;
                    try
                    {
                         refreshToken = await refreshTokenStore.GetRefreshTokenAsync(refreshTokenValue, cancellationToken);
                    }
                     catch (Exception ex)
                    {
                        handlerLogger.LogError(ex, "Error retrieving refresh token during refresh operation.");
                        return Results.Problem("An unexpected error occurred during token validation.", statusCode: StatusCodes.Status500InternalServerError);
                    }


                    if (refreshToken == null)
                    {
                        return CreateErrorResult("invalid_grant", "The refresh token is invalid or has been revoked.");
                    }

                    // Validate Client ID if provided and matches token's client
                    if (!string.IsNullOrEmpty(clientId) && refreshToken.ClientId != clientId)
                    {
                        handlerLogger.LogWarning("Client ID mismatch for refresh token. Expected {ExpectedClientId}, got {ActualClientId}.", refreshToken.ClientId, clientId);
                        return CreateErrorResult("invalid_grant", "The refresh token was not issued to this client.");
                    }


                    if (refreshToken.ConsumedTime.HasValue)
                    {
                         // ... existing token theft detection logic ...
                        return CreateErrorResult("invalid_grant", "The refresh token has already been used.");
                    }

                    if (refreshToken.ExpirationTime < DateTime.UtcNow)
                    {
                        await refreshTokenStore.RemoveRefreshTokenAsync(refreshToken.Handle, cancellationToken); // Consume expired token
                        return CreateErrorResult("invalid_grant", "The refresh token has expired.");
                    }

                    var refreshUser = await userStore.FindUserByIdAsync(refreshToken.SubjectId, cancellationToken);
                    if (refreshUser == null)
                    {
                        return CreateErrorResult("invalid_grant", "The user associated with this token does not exist.");
                    }

                    // Mark old token consumed and generate new tokens
                    string newAccessToken;
                    string newRefreshTokenHandle;
                    try
                    {
                        await refreshTokenStore.RemoveRefreshTokenAsync(refreshToken!.Handle, cancellationToken); // Consume old

                        newAccessToken = await tokenService.GenerateAccessTokenAsync(refreshUser);

                        if (options.Value.TokenSecurity.EnableTokenFamilyTracking && refreshToken != null)
                        {
                             // Pass the previous token for rotation/family tracking
                             newRefreshTokenHandle = await tokenService.GenerateAndStoreRefreshTokenAsync(refreshUser, refreshToken.ClientId, refreshToken);
                        }
                        else
                        {
                            // Generate a new token without linking to a previous one
                            newRefreshTokenHandle = await tokenService.GenerateAndStoreRefreshTokenAsync(refreshUser, refreshToken!.ClientId);
                        }
                    }
                     catch(Exception ex)
                    {
                        handlerLogger.LogError(ex, "Error consuming old refresh token or generating new tokens for user {UserId} during refresh.", refreshUser.Id);
                        return Results.Problem("An unexpected error occurred during token refresh processing.", statusCode: StatusCodes.Status500InternalServerError);
                    }


                    return Results.Ok(new TokenResponse
                    {
                        AccessToken = newAccessToken,
                        RefreshToken = newRefreshTokenHandle,
                        TokenType = "Bearer",
                        ExpiresIn = (int)options.Value.AccessTokenLifetime.TotalSeconds // Set expiry
                    });
                }
                catch (Exception ex)
                {
                    handlerLogger.LogError(ex, "Error processing refresh token request");
                    // Use Problem for unexpected server errors, BadRequest for client errors
                    return Results.Problem("An error occurred processing the request.", statusCode: StatusCodes.Status500InternalServerError);
                }
            })
            .WithName("RefreshTokenExchange")
            .WithTags("CoreIdent")
            .Produces<TokenResponse>(StatusCodes.Status200OK)
            .Produces<ErrorResponse>(StatusCodes.Status400BadRequest);
        }

        // Helper method for PKCE S256 challenge method verification
        private static string Base64UrlEncode(byte[] arg)
        {
            var s = Convert.ToBase64String(arg);
            s = s.Split('=')[0]; // Remove trailing '='s
            s = s.Replace('+', '-'); // Replace '+' with '-'
            s = s.Replace('/', '_'); // Replace '/' with '_'
            return s;
        }
    }
}
