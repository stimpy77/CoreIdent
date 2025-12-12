using CoreIdent.Core.Middleware;
using Microsoft.AspNetCore.Builder;

namespace CoreIdent.Core.Extensions;

public static class ApplicationBuilderExtensions
{
    public static IApplicationBuilder UseCoreIdentTokenRevocation(this IApplicationBuilder app)
    {
        if (app is null)
        {
            throw new ArgumentNullException(nameof(app));
        }

        return app.UseMiddleware<TokenRevocationMiddleware>();
    }
}
