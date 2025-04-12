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
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations; // ValidationResult
using System.Linq; // For validation results
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
                PasswordHash = passwordHasher.HashPassword(null, request.Password!) // Request validation ensures Password is not null
            };

            try
            {
                var result = await userStore.CreateUserAsync(newUser, cancellationToken);

                return result switch
                {
                    StoreResult.Success => Results.Ok(new { UserId = newUser.Id, Message = "User registered successfully." }), // Consider CreatedAtRoute if exposing a GET /users/{id} later
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
        .Produces(StatusCodes.Status200OK)
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
            var passwordVerificationResult = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password!); // Request validation ensures Password is not null

            if (passwordVerificationResult == PasswordVerificationResult.Failed)
            {
                return Results.Unauthorized(); // Invalid password
            }

            // Handle SuccessRehashNeeded - Optional: Update hash in store (consider for Phase 2)
            if (passwordVerificationResult == PasswordVerificationResult.SuccessRehashNeeded)
            {
                // Log or schedule rehash? For now, proceed with login.
                logger.LogInformation("Password rehash needed for user {UserId}", user.Id);
                // In Phase 2, might update user.PasswordHash = passwordHasher.HashPassword(user, request.Password!);
                // and call userStore.UpdateUserAsync(user, cancellationToken);
            }

            // Generate tokens
            try
            {
                var accessToken = await tokenService.GenerateAccessTokenAsync(user);
                var refreshToken = await tokenService.GenerateRefreshTokenAsync(user); // Simple refresh token for Phase 1

                var response = new TokenResponse
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    AccessTokenLifetime = options.Value.AccessTokenLifetime,
                    RefreshTokenLifetime = options.Value.RefreshTokenLifetime
                };

                return Results.Ok(response);
            }
             catch (Exception ex)
            {
                 logger.LogError(ex, "Error generating tokens for user {UserId} during login", user.Id);
                 return Results.Problem("An unexpected error occurred during token generation.", statusCode: StatusCodes.Status500InternalServerError);
            }
        })
        .WithName("LoginUser")
        .WithTags("CoreIdent")
        .Produces<TokenResponse>(StatusCodes.Status200OK)
        .Produces<ValidationProblemDetails>(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status401Unauthorized)
        .Produces(StatusCodes.Status500InternalServerError)
        .WithSummary("Authenticates a user and returns tokens.")
        .WithDescription("Logs in a user with email and password, providing access and refresh tokens upon success.");

        // Endpoint: /token/refresh (Phase 1 - Stub)
        routeGroup.MapPost("token/refresh", (
             [FromBody] RefreshTokenRequest request) =>
             {
                 // Phase 1: Not implemented. Return 501.
                 // Phase 2 will involve validating the refresh token, finding the associated user,
                 // potentially revoking the old token, and issuing new access/refresh tokens.
                 return Results.StatusCode(StatusCodes.Status501NotImplemented);
             })
        .WithName("RefreshToken")
        .WithTags("CoreIdent")
        .Produces(StatusCodes.Status501NotImplemented)
        .Produces<ValidationProblemDetails>(StatusCodes.Status400BadRequest) // Still validate input
        .WithSummary("Refreshes an access token using a refresh token (Not Implemented in Phase 1).")
        .WithDescription("Exchanges a valid refresh token for a new access token and refresh token. This functionality is planned for Phase 2.");


        return routeGroup;
    }
}
