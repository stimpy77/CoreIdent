using Microsoft.AspNetCore.Http;

namespace CoreIdent.Core.Services.Realms;

public interface ICoreIdentRealmResolver
{
    string? ResolveRealmId(HttpContext httpContext);
}
