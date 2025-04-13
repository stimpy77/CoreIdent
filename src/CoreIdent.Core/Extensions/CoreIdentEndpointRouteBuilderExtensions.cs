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

            var newUser = new CoreIdentUser
            {
                UserName = request.Email, // Assuming email is username for now
                PasswordHash = passwordHasher.HashPassword(null, request.Password!) // Pass null for user context during creation
            };

            try
            {
                var result = await userStore.CreateUserAsync(newUser, cancellationToken);

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
            var normalizedUsername = request.Email!.ToUpperInvariant(); // Request validation ensures Email is not null
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
                return Results.Unauthorized(); // User not found or has no password hash
            }

            // Verify password
            var passwordVerificationResult = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password!);

            if (passwordVerificationResult == PasswordVerificationResult.Failed)
            {
                logger.LogWarning("Password verification failed for user {Username}", request.Email);
                return Results.Unauthorized(); // Incorrect password
            }

            // Password verification successful (or needs rehashing - handle later if needed)
            if (passwordVerificationResult == PasswordVerificationResult.SuccessRehashNeeded)
            {
                // Optionally rehash and update the password hash in the store
                // var newHash = passwordHasher.HashPassword(user, request.Password!);
                // user.PasswordHash = newHash;
                // await userStore.UpdateUserAsync(user, cancellationToken); // Add UpdateUserAsync if not present
                logger.LogInformation("Password requires rehashing for user {Username}", request.Email);
            }

            // Generate tokens
            string accessToken;
            string refreshTokenHandle;
            try
            {
                accessToken = await tokenService.GenerateAccessTokenAsync(user);
                refreshTokenHandle = await tokenService.GenerateRefreshTokenAsync(user);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error generating tokens for user {Username}", request.Email);
                return Results.Problem("An unexpected error occurred during token generation.", statusCode: StatusCodes.Status500InternalServerError);
            }

            // Create and store the refresh token entity
            try
            {
                var refreshTokenEntity = new CoreIdentRefreshToken
                {
                    Handle = refreshTokenHandle,
                    SubjectId = user.Id,
                    // TODO: ClientId Handling - Hardcoded for now as this endpoint lacks client context.
                    // Associate with a real client when implementing client-specific flows.
                    ClientId = "__password_flow__",
                    CreationTime = DateTime.UtcNow,
                    ExpirationTime = DateTime.UtcNow.Add(options.Value.RefreshTokenLifetime),
                    ConsumedTime = null // Initially not consumed
                };
                await refreshTokenStore.StoreRefreshTokenAsync(refreshTokenEntity, cancellationToken);
            }
            catch(Exception ex)
            {
                logger.LogError(ex, "Error storing refresh token for user {Username}", request.Email);
                // Decide if login should fail if refresh token storage fails.
                // For now, we'll proceed but log the error.
                // Consider returning Results.Problem(...) in a production scenario.
            }

            var response = new TokenResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshTokenHandle,
                AccessTokenLifetime = options.Value.AccessTokenLifetime,
                RefreshTokenLifetime = options.Value.RefreshTokenLifetime
            };

            logger.LogInformation("User {Username} successfully logged in.", request.Email);
            return Results.Ok(response);

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
                 // TODO: Implement potential security measures here, like revoking all tokens for the user/client.
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
                newAccessToken = await tokenService.GenerateAccessTokenAsync(user);
                newRefreshTokenHandle = await tokenService.GenerateRefreshTokenAsync(user);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error generating new tokens for user {UserId} during refresh", user.Id);
                // Consider if we should try to rollback the consumption of the old token? Complex.
                // For now, return error.
                return Results.Problem("An unexpected error occurred during token generation.", statusCode: StatusCodes.Status500InternalServerError);
            }

            // Store the NEW refresh token
            try
            {
                var newRefreshTokenEntity = new CoreIdentRefreshToken
                {
                    Handle = newRefreshTokenHandle,
                    SubjectId = user.Id,
                    ClientId = existingToken.ClientId, // Re-use the ClientId from the original token
                    CreationTime = DateTime.UtcNow,
                    ExpirationTime = DateTime.UtcNow.Add(options.Value.RefreshTokenLifetime),
                    ConsumedTime = null
                };
                await refreshTokenStore.StoreRefreshTokenAsync(newRefreshTokenEntity, cancellationToken);
            }
            catch(Exception ex)
            {
                 logger.LogError(ex, "Failed to store new refresh token for user {UserId} after successful refresh. Old token {OldRefreshTokenHandle} consumed.", user.Id, existingToken.Handle);
                 // Critical error: Old token consumed, new token not stored. User needs to log in again.
                 return Results.Problem("An unexpected error occurred completing the token refresh.", statusCode: StatusCodes.Status500InternalServerError);
            }

            var response = new TokenResponse
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshTokenHandle,
                AccessTokenLifetime = options.Value.AccessTokenLifetime,
                RefreshTokenLifetime = options.Value.RefreshTokenLifetime
            };

            logger.LogInformation("Tokens refreshed successfully for user {UserId}", user.Id);
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

        return routeGroup;
    }
}
