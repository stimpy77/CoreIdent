using System;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Http;

namespace CoreIdent.TestHost
{
    public class TestAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public const string AuthenticationScheme = "TestScheme";

        public TestAuthHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var userId = Request.Headers["X-Test-User-Id"].FirstOrDefault();
            var email = Request.Headers["X-Test-User-Email"].FirstOrDefault();
            
            // Log detailed request info for debugging authentication issues
            Logger.LogInformation(
                "TestAuthHandler: Scheme={Scheme}, Path={Path}, IsAuthenticated={IsAuthenticated}, Headers: UserId={UserId}, Email={Email}, " +
                "Cookies: {CookieCount}, AuthType={AuthType}",
                Scheme.Name,
                Request.Path,
                Context.User?.Identity?.IsAuthenticated,
                userId,
                email,
                Request.Cookies.Count,
                Context.User?.Identity?.AuthenticationType);
            
            // First check for existing authentication cookie
            if (Context.User?.Identity?.IsAuthenticated == true)
            {
                Logger.LogInformation("TestAuthHandler: User is already authenticated via {AuthType}, forwarding auth to scheme {Scheme}", 
                    Context.User.Identity.AuthenticationType, Scheme.Name);
                return Task.FromResult(AuthenticateResult.Success(
                    new AuthenticationTicket(Context.User, Scheme.Name)));
            }
            
            // Then check for test headers
            if (!string.IsNullOrEmpty(userId) && !string.IsNullOrEmpty(email))
            {
                Logger.LogInformation("TestAuthHandler: Authenticating with X-Test-* headers for {UserId} with scheme {Scheme}", 
                    userId, Scheme.Name);
                
                var claims = new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, userId),
                    new Claim(ClaimTypes.Name, email),
                    new Claim(ClaimTypes.Email, email)
                };
                var identity = new ClaimsIdentity(claims, Scheme.Name);
                var principal = new ClaimsPrincipal(identity);
                var ticket = new AuthenticationTicket(principal, Scheme.Name);
                
                // Also set a cookie to maintain authentication across redirects
                if (Scheme.Name == "TestAuth")
                {
                    try
                    {
                        Logger.LogInformation("TestAuthHandler: Setting cookie for {UserId}", userId);
                        Context.SignInAsync("Cookies", principal).GetAwaiter().GetResult();
                    }
                    catch (Exception ex)
                    {
                        Logger.LogError(ex, "TestAuthHandler: Failed to set cookie for {UserId}", userId);
                    }
                }
                
                return Task.FromResult(AuthenticateResult.Success(ticket));
            }
            
            // No authentication found
            Logger.LogInformation("TestAuthHandler: No authentication found for scheme {Scheme}", Scheme.Name);
            return Task.FromResult(AuthenticateResult.NoResult());
        }
    }
}
