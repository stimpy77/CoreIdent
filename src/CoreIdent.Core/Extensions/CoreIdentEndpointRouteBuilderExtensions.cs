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
    // WARNING: TEMPORARY Phase 1 In-Memory Refresh Token Store.
    // This is NOT suitable for production. Phase 2 will use IRefreshTokenStore.
    private static readonly ConcurrentDictionary<string, string> _refreshTokens = new();

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
            string refreshToken;
            try
            {
                accessToken = await tokenService.GenerateAccessTokenAsync(user);
                refreshToken = await tokenService.GenerateRefreshTokenAsync(user); // Basic refresh token for Phase 1
                 // In Phase 2, we'll store the refresh token hash using IRefreshTokenStore
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error generating tokens for user {Username}", request.Email);
                return Results.Problem("An unexpected error occurred during token generation.", statusCode: StatusCodes.Status500InternalServerError);
            }

            // Phase 1: Store the initial refresh token in the static dictionary
            _refreshTokens.TryAdd(refreshToken, user.Id);

            var response = new TokenResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken, // Return refresh token
                AccessTokenLifetime = options.Value.AccessTokenLifetime, // Set required property
                RefreshTokenLifetime = options.Value.RefreshTokenLifetime // Set required property
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

        // Endpoint: /token/refresh (Phase 1 - Basic Implementation)
        routeGroup.MapPost("token/refresh", async (
            [FromBody] RefreshTokenRequest request,
            IUserStore userStore,
            ITokenService tokenService,
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

            // Phase 1: Validate and consume token from static dictionary
            if (!_refreshTokens.TryRemove(request.RefreshToken, out var userId) || string.IsNullOrEmpty(userId))
            {
                logger.LogWarning("Invalid or expired refresh token presented.");
                return Results.Unauthorized(); // Token not found or already used
            }

            // Found token, now find user
            CoreIdentUser? user;
            try
            {
                user = await userStore.FindUserByIdAsync(userId, cancellationToken);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error finding user {UserId} during token refresh", userId);
                // Restore the token if user lookup fails unexpectedly?
                // For simplicity in Phase 1, we won't restore. The token is considered consumed.
                return Results.Problem("An unexpected error occurred during user lookup.", statusCode: StatusCodes.Status500InternalServerError);
            }

            if (user == null)
            {
                logger.LogError("User {UserId} associated with refresh token not found.", userId);
                // Don't restore the token, it's potentially compromised or stale.
                return Results.Unauthorized(); // User associated with token no longer exists
            }

            // Generate new tokens
            string newAccessToken;
            string newRefreshToken;
            try
            {
                newAccessToken = await tokenService.GenerateAccessTokenAsync(user);
                newRefreshToken = await tokenService.GenerateRefreshTokenAsync(user);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error generating new tokens for user {UserId} during refresh", userId);
                return Results.Problem("An unexpected error occurred during token generation.", statusCode: StatusCodes.Status500InternalServerError);
            }

            // Phase 1: Store the new refresh token in the static dictionary
            _refreshTokens.TryAdd(newRefreshToken, user.Id); // Store new token

            var response = new TokenResponse
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken,
                AccessTokenLifetime = options.Value.AccessTokenLifetime, // Set required property
                RefreshTokenLifetime = options.Value.RefreshTokenLifetime // Set required property
            };

            logger.LogInformation("Tokens refreshed successfully for user {UserId}", userId);
            return Results.Ok(response);
        })
        .WithName("RefreshToken")
        .WithTags("CoreIdent")
        .Produces<TokenResponse>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status400BadRequest) // Invalid request (e.g., missing token)
        .Produces(StatusCodes.Status401Unauthorized) // Invalid/Expired token
        .Produces(StatusCodes.Status500InternalServerError)
        .WithSummary("Exchanges a refresh token for new tokens.")
        .WithDescription("Provides a new access and refresh token if the provided refresh token is valid.");

        return routeGroup;
    }
}
