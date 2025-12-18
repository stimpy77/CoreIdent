using Microsoft.AspNetCore.Http;

namespace CoreIdent.Core.Services.Realms;

/// <summary>
/// Default implementation that resolves realm ID from HTTP route values.
/// </summary>
public sealed class DefaultCoreIdentRealmResolver : ICoreIdentRealmResolver
{
    /// <inheritdoc />
    public string? ResolveRealmId(HttpContext httpContext)
    {
        if (httpContext is null)
        {
            return null;
        }

        if (httpContext.Request.RouteValues.TryGetValue("realm", out var realmValue) && realmValue is not null)
        {
            var realm = realmValue.ToString();
            if (!string.IsNullOrWhiteSpace(realm))
            {
                return realm;
            }
        }

        return null;
    }
}
