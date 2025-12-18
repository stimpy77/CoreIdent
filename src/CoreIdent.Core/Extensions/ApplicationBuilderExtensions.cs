using CoreIdent.Core.Middleware;
using Microsoft.AspNetCore.Builder;

namespace CoreIdent.Core.Extensions;

/// <summary>
/// Application pipeline helpers for CoreIdent.
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Adds the token revocation middleware to the request pipeline.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <returns>The application builder.</returns>
    public static IApplicationBuilder UseCoreIdentTokenRevocation(this IApplicationBuilder app)
    {
        if (app is null)
        {
            throw new ArgumentNullException(nameof(app));
        }

        return app.UseMiddleware<TokenRevocationMiddleware>();
    }
}
