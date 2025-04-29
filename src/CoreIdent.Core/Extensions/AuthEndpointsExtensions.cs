using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Models.Requests;
using CoreIdent.Core.Models.Responses;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;

namespace CoreIdent.Core.Extensions
{
    /// <summary>
    /// Extension methods for mapping authentication endpoints (register, login).
    /// </summary>
    public static class AuthEndpointsExtensions
    {
        public static void MapAuthEndpoints(this IEndpointRouteBuilder endpoints, CoreIdentRouteOptions routeOptions)
        {
            // Endpoint: /register
            endpoints.MapPost(routeOptions.RegisterPath, async (
                [FromBody] RegisterRequest request,
                HttpContext httpContext,
                IUserStore userStore,
                IPasswordHasher passwordHasher,
                ILoggerFactory loggerFactory,
                CancellationToken cancellationToken) =>
            {
                var logger = loggerFactory.CreateLogger("CoreIdent.Register");

                // Manual validation
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
                    UserName = request.Email,
                    NormalizedUserName = normalizedUsername,
                    PasswordHash = passwordHasher.HashPassword(null, request.Password!)
                };

                try
                {
                    var result = await userStore.CreateUserAsync(newUser, cancellationToken);
                    logger.LogDebug("Register endpoint: CreateUserAsync result: {Result} for user {Username}", result, request.Email);
                    return result switch
                    {
                        StoreResult.Success => Results.Created($"/{newUser.Id}", new { UserId = newUser.Id, Message = "User registered successfully." }),
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
            endpoints.MapPost(routeOptions.LoginPath, async (
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
                    passwordVerificationResult = await userStore.ValidateCredentialsAsync(normalizedUsername, request.Password!, cancellationToken);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error validating credentials for user {Username}", request.Email);
                    return Results.Problem("An unexpected error occurred during credential validation.", statusCode: StatusCodes.Status500InternalServerError);
                }

                if (passwordVerificationResult == PasswordVerificationResult.Failed)
                {
                    logger.LogWarning("Password verification failed for user {Username}", request.Email);
                    return Results.Unauthorized();
                }

                if (passwordVerificationResult == PasswordVerificationResult.SuccessRehashNeeded)
                {
                    logger.LogInformation("Password requires rehashing for user {Username}. Attempting to update hash.", request.Email);
                    try
                    {
                        var newHash = passwordHasher.HashPassword(user, request.Password!);
                        await userStore.SetPasswordHashAsync(user, newHash, cancellationToken);
                        user.PasswordHash = newHash;
                        logger.LogInformation("Password hash updated successfully for user {Username}.", request.Email);
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "Failed to update rehashed password for user {Username}", request.Email);
                    }
                }

                // Generate tokens
                var accessToken = await tokenService.GenerateAccessTokenAsync(user, new[] { "openid", "profile", "email" });
                string? refreshTokenHandle = null;

                // Check if the implicit client for password flow allows offline access
                const string clientIdForPasswordFlow = "__password_flow__";
                var clientStore = httpContext.RequestServices.GetRequiredService<IClientStore>();
                var passwordClient = await clientStore.FindClientByIdAsync(clientIdForPasswordFlow, cancellationToken);

                if (passwordClient?.AllowOfflineAccess == true)
                {
                    try
                    {
                        logger.LogDebug("LOGIN_ENDPOINT: Trying refresh token generation...");
                        refreshTokenHandle = await tokenService.GenerateAndStoreRefreshTokenAsync(user, clientIdForPasswordFlow);
                        logger.LogInformation("LOGIN_ENDPOINT: GenerateAndStoreRefreshTokenAsync returned: {RefreshTokenHandle}", refreshTokenHandle ?? "<null>");
                        logger.LogInformation("LOGIN_ENDPOINT: Reached end of try block after refresh token generation.");
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "LOGIN_ENDPOINT: FAILED in try block for refresh token generation/storage.");
                        refreshTokenHandle = null;
                    }
                }
                else
                {
                    logger.LogWarning("Refresh token not generated for user {UserId}: Client {ClientId} does not allow offline access or was not found.", user.Id, clientIdForPasswordFlow);
                }

                logger.LogInformation("LOGIN_ENDPOINT: Preparing final TokenResponse.");
                var tokenResponse = new TokenResponse
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshTokenHandle,
                    ExpiresIn = 3600,
                    TokenType = "Bearer"
                };

                try
                {
                    var responseJson = JsonSerializer.Serialize(tokenResponse);
                    logger.LogInformation("LOGIN_ENDPOINT: Serialized TokenResponse being returned: {JsonResponse}", responseJson);
                }
                catch (Exception jsonEx)
                {
                    logger.LogError(jsonEx, "LOGIN_ENDPOINT: Failed to serialize TokenResponse before returning.");
                }

                logger.LogDebug("LOGIN_ENDPOINT: Returning OK response.");
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
        }
    }
}
