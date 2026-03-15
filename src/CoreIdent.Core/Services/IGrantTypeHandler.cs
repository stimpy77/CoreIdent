using CoreIdent.Core.Models;
using Microsoft.AspNetCore.Http;

namespace CoreIdent.Core.Services;

/// <summary>
/// Extensible grant type handler for the token endpoint.
/// Implement this interface to register custom OAuth grant types via DI.
/// Built-in grants (client_credentials, refresh_token, authorization_code) are handled
/// directly by the token endpoint; registered handlers are consulted for all other grant types.
/// </summary>
/// <remarks>
/// <para>
/// Handlers should be registered as <c>Singleton</c> or <c>Transient</c>.
/// Since handlers may be resolved from the root container (e.g., for discovery metadata),
/// they must NOT inject scoped services via the constructor. Instead, resolve scoped
/// dependencies from <see cref="Microsoft.AspNetCore.Http.HttpContext.RequestServices"/>
/// within <see cref="HandleAsync"/>.
/// </para>
/// </remarks>
public interface IGrantTypeHandler
{
    /// <summary>
    /// The grant type this handler supports (e.g., "password", "urn:ietf:params:oauth:grant-type:device_code").
    /// </summary>
    string GrantType { get; }

    /// <summary>
    /// Handles the token request for this grant type.
    /// Called after client authentication and grant type authorization have been verified.
    /// </summary>
    /// <param name="client">The authenticated client.</param>
    /// <param name="request">The parsed token request.</param>
    /// <param name="httpContext">The HTTP context for accessing additional services.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>An <see cref="IResult"/> representing the token response or error.</returns>
    Task<IResult> HandleAsync(CoreIdentClient client, TokenRequest request, HttpContext httpContext, CancellationToken ct);
}
