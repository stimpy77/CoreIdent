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

        // Map main token endpoint (/token) and refresh endpoint (/token/refresh)
        routeGroup.MapTokenEndpoints(routeOptions);

        // Map well-known endpoints relative to the root
        endpoints.MapDiscoveryEndpoints(routeOptions);

        // Note: Refresh token endpoint is now handled within the main /token endpoint
        // via grant_type=refresh_token. The old RefreshTokenPath is kept for potential
        // legacy use or different configuration but is not mapped by default here.

        return routeGroup;
    }
}