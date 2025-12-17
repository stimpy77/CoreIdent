using Microsoft.AspNetCore.Http;

namespace CoreIdent.Core.Services.Realms;

public sealed class HttpContextCoreIdentRealmContext : ICoreIdentRealmContext
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ICoreIdentRealmResolver _resolver;

    private string? _cached;

    public HttpContextCoreIdentRealmContext(IHttpContextAccessor httpContextAccessor, ICoreIdentRealmResolver resolver)
    {
        _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
    }

    public string RealmId
    {
        get
        {
            if (_cached is not null)
            {
                return _cached;
            }

            var ctx = _httpContextAccessor.HttpContext;
            var resolved = ctx is null ? null : _resolver.ResolveRealmId(ctx);
            _cached = string.IsNullOrWhiteSpace(resolved) ? "default" : resolved;
            return _cached;
        }
    }
}
