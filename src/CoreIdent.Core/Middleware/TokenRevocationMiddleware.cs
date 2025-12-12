using CoreIdent.Core.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;

namespace CoreIdent.Core.Middleware;

public sealed class TokenRevocationMiddleware
{
    private readonly RequestDelegate _next;

    public TokenRevocationMiddleware(RequestDelegate next)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
    }

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
