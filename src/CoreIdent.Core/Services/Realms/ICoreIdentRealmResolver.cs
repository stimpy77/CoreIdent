using Microsoft.AspNetCore.Http;

namespace CoreIdent.Core.Services.Realms;

/// <summary>
/// Resolves realm identifier from HTTP context for realm-aware operations.
/// </summary>
public interface ICoreIdentRealmResolver
{
    /// <summary>
    /// Resolves the realm identifier from the provided HTTP context.
    /// </summary>
    /// <param name="httpContext">The HTTP context to resolve realm from.</param>
    /// <returns>The realm identifier if found, otherwise null.</returns>
    string? ResolveRealmId(HttpContext httpContext);
}
