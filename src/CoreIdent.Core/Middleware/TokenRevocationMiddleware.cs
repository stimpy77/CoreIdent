using CoreIdent.Core.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;

namespace CoreIdent.Core.Middleware;

/// <summary>
/// Middleware that rejects authenticated requests whose JWT has been revoked.
/// </summary>
public sealed class TokenRevocationMiddleware
{
    private readonly RequestDelegate _next;

    /// <summary>
    /// Creates a new instance.
    /// </summary>
    /// <param name="next">Next middleware delegate.</param>
    public TokenRevocationMiddleware(RequestDelegate next)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
    }

    /// <summary>
    /// Invokes the middleware.
    /// </summary>
    /// <param name="context">HTTP context.</param>
    /// <param name="tokenRevocationStore">Token revocation store.</param>
    public async Task InvokeAsync(HttpContext context, ITokenRevocationStore tokenRevocationStore)
    {
        if (context is null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        if (tokenRevocationStore is null)
        {
            throw new ArgumentNullException(nameof(tokenRevocationStore));
        }

        if (context.User?.Identity?.IsAuthenticated == true)
        {
            var jti = context.User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
            if (!string.IsNullOrWhiteSpace(jti))
            {
                var revoked = await tokenRevocationStore.IsRevokedAsync(jti, context.RequestAborted);
                if (revoked)
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return;
                }
            }
        }

        await _next(context);
    }
}
