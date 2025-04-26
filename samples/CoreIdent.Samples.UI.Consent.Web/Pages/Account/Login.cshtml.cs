using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System; // Add this for RandomNumberGenerator, Convert
using System.Collections.Generic;
using System.Security.Cryptography; // Add this for RandomNumberGenerator, SHA256
using System.Text; // Add this for Encoding
using Microsoft.AspNetCore.WebUtilities; // Add this for QueryHelpers

namespace CoreIdent.Samples.UI.Web.Pages.Account
{
    // NOTE: Login page itself should allow anonymous access
    // The RequireAuthorization() in Program.cs might need adjustment or
    // this page needs [AllowAnonymous]
    [Microsoft.AspNetCore.Authorization.AllowAnonymous] 
    public class LoginModel : PageModel
    {
        // Inject configuration if needed, e.g., to get CoreIdent URL and ClientId
        // For simplicity, hardcoding values here - SHOULD BE CONFIGURATION
        private const string CoreIdentServerUrl = "https://localhost:7100"; 
        private const string ClientId = "sample-ui-client"; // Needs to be registered in CoreIdent
        private const string ClientRedirectUri = "/signin-oidc"; // Path for the callback handler
        private const string Scope = "openid profile email offline_access"; // Example scopes

        public IActionResult OnGet()
        {
            // --- Start OIDC Authorization Code Flow with PKCE ---

            // 1. Generate PKCE Code Verifier and Challenge
            var codeVerifier = GenerateCodeVerifier();
            var codeChallenge = GenerateCodeChallenge(codeVerifier);
            var state = Guid.NewGuid().ToString("N"); // Protect against CSRF

            // 2. Store code_verifier and state securely (e.g., in a short-lived cookie or session)
            // For simplicity, using a cookie here. In production, consider server-side storage.
            Response.Cookies.Append("pkce_code_verifier", codeVerifier, new CookieOptions 
            { 
                HttpOnly = true, 
                Secure = Request.IsHttps, // Set based on request scheme
                SameSite = SameSiteMode.Lax, // Lax allows redirect back
                Expires = DateTimeOffset.UtcNow.AddMinutes(10) // Short expiry
            });
            Response.Cookies.Append("oauth_state", state, new CookieOptions 
            { 
                HttpOnly = true, 
                Secure = Request.IsHttps, 
                SameSite = SameSiteMode.Lax, 
                Expires = DateTimeOffset.UtcNow.AddMinutes(10) 
            });

            // 3. Construct the Authorize URL
            var authorizeUrl = QueryHelpers.AddQueryString($"{CoreIdentServerUrl}/auth/authorize", new Dictionary<string, string?>
            {
                ["client_id"] = ClientId,
                ["redirect_uri"] = Url.Page(ClientRedirectUri, null, null, Request.Scheme), // Absolute URL for callback
                ["response_type"] = "code",
                ["scope"] = Scope,
                ["state"] = state,
                ["code_challenge"] = codeChallenge,
                ["code_challenge_method"] = "S256",
                ["nonce"] = Guid.NewGuid().ToString("N") // Optional OIDC parameter
            });

            // 4. Redirect the user's browser
            return Redirect(authorizeUrl);
        }

        private static string GenerateCodeVerifier()
        {
            // Generate a random byte array (32 bytes = 256 bits)
            var randomBytes = RandomNumberGenerator.GetBytes(32);
            // Convert to URL-safe base64 string
            return Convert.ToBase64String(randomBytes)
                .Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('=');
        }

        private static string GenerateCodeChallenge(string codeVerifier)
        {
            using var sha256 = SHA256.Create();
            var challengeBytes = sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
            // Convert hash to URL-safe base64 string
            return Convert.ToBase64String(challengeBytes)
                .Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('=');
        }
    }
} 