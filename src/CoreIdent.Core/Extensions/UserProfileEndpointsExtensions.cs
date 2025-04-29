using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using System.Linq;

namespace CoreIdent.Core.Extensions
{
    /// <summary>
    /// Extension methods for mapping user profile management endpoints.
    /// </summary>
    public static class UserProfileEndpointsExtensions
    {
        /// <summary>
        /// Maps endpoints for getting and updating the current user's profile.
        /// </summary>
        public static void MapUserProfileEndpoints(this IEndpointRouteBuilder endpoints, CoreIdentRouteOptions routeOptions)
        {
            ArgumentNullException.ThrowIfNull(endpoints);
            ArgumentNullException.ThrowIfNull(routeOptions);

            var path = routeOptions.UserProfilePath;
            IEndpointRouteBuilder targetBuilder;

            // Determine the target builder based on the path prefix
            if (path.StartsWith("/"))
            {
                // If path starts with '/', use the root builder (passed as `endpoints`)
                // and ensure the path doesn't have duplicate slashes if combined later (though it shouldn't be)
                targetBuilder = endpoints; 
                path = "/" + path.TrimStart('/'); // Ensure single leading slash
            }
            else
            {
                // If path does not start with '/', assume it's relative to the group
                // The `endpoints` parameter here is expected to be the group builder itself
                targetBuilder = endpoints; 
                path = path.TrimStart('/'); // Path is relative, no leading slash needed for MapGet
            }

            // GET /me - Get current user's profile
            targetBuilder.MapGet(path, async (
                HttpContext httpContext,
                IUserStore userStore,
                ILoggerFactory loggerFactory,
                CancellationToken cancellationToken) =>
            {
                var logger = loggerFactory.CreateLogger("CoreIdent.UserProfile");
                var userId = httpContext.User?.FindFirstValue(ClaimTypes.NameIdentifier);
                if (string.IsNullOrWhiteSpace(userId))
                {
                    logger.LogWarning("/me endpoint: User not authenticated");
                    return Results.Unauthorized();
                }
                CoreIdentUser? user;
                try
                {
                    user = await userStore.FindUserByIdAsync(userId, cancellationToken);
                }
                catch (System.Exception ex)
                {
                    logger.LogError(ex, "/me endpoint: Error retrieving user {UserId}", userId);
                    return Results.Problem("An error occurred while retrieving the user profile.", statusCode: StatusCodes.Status500InternalServerError);
                }
                if (user == null)
                {
                    logger.LogWarning("/me endpoint: User {UserId} not found", userId);
                    return Results.NotFound();
                }
                // Return a DTO or the user directly (customize as needed)
                return Results.Ok(new
                {
                    user.Id,
                    user.UserName,
                    Claims = user.Claims.Select(c => new { c.ClaimType, c.ClaimValue })
                });
            })
            .WithName("GetUserProfile")
            .WithTags("CoreIdent")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status500InternalServerError)
            .WithSummary("Gets the current user's profile.");

            // PUT /me - Update current user's profile (basic example)
            targetBuilder.MapPut(path, async (
                [FromBody] UpdateUserProfileRequest request,
                HttpContext httpContext,
                IUserStore userStore,
                ILoggerFactory loggerFactory,
                CancellationToken cancellationToken) =>
            {
                var logger = loggerFactory.CreateLogger("CoreIdent.UserProfile");
                var userId = httpContext.User?.FindFirstValue(ClaimTypes.NameIdentifier);
                if (string.IsNullOrWhiteSpace(userId))
                {
                    logger.LogWarning("/me endpoint: User not authenticated");
                    return Results.Unauthorized();
                }
                CoreIdentUser? user;
                try
                {
                    user = await userStore.FindUserByIdAsync(userId, cancellationToken);
                }
                catch (System.Exception ex)
                {
                    logger.LogError(ex, "/me endpoint: Error retrieving user {UserId}", userId);
                    return Results.Problem("An error occurred while retrieving the user profile.", statusCode: StatusCodes.Status500InternalServerError);
                }
                if (user == null)
                {
                    logger.LogWarning("/me endpoint: User {UserId} not found", userId);
                    return Results.NotFound();
                }
                // Update fields (this is a basic example, add validation as needed)
                // user.Email = request.Email ?? user.Email; // CoreIdentUser does not have Email
                user.UserName = request.UserName ?? user.UserName;
                // Save to store (now implemented)
                var result = await userStore.UpdateUserAsync(user, cancellationToken);
                if (result != StoreResult.Success)
                {
                    logger.LogWarning("/me endpoint: Failed to update user {UserId}", userId);
                    return Results.Problem("Failed to update user profile.", statusCode: StatusCodes.Status500InternalServerError);
                }
                logger.LogInformation("/me endpoint: Updated profile for user {UserId}", userId);
                return Results.Ok();
            })
            .WithName("UpdateUserProfile")
            .WithTags("CoreIdent")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status500InternalServerError)
            .WithSummary("Updates the current user's profile.");
        }
    }

    public class UpdateUserProfileRequest
    {
        public string? Email { get; set; }
        public string? UserName { get; set; }
    }
}
