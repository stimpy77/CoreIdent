using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Text;

namespace CoreIdent.Samples.UI.Web.Pages.Shared
{
    [Microsoft.AspNetCore.Authorization.AllowAnonymous]
    public class SigninOidcModel : PageModel
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<SigninOidcModel> _logger;

        private const string CoreIdentServerUrl = "https://localhost:7100";
        private const string ClientId = "sample-ui-client"; 
        private const string ClientSecret = "sample-ui-secret";
        private const string CookieScheme = CookieAuthenticationDefaults.AuthenticationScheme;

        public SigninOidcModel(IHttpClientFactory httpClientFactory, ILogger<SigninOidcModel> logger)
        {
            _httpClientFactory = httpClientFactory;
            _logger = logger;
        }

        public async Task<IActionResult> OnGetAsync(string? code = null, string? error = null, string? state = null)
        {
            _logger.LogInformation("Callback received. Code: {Code}, Error: {Error}, State: {State}", 
                code ?? "<null>", error ?? "<null>", state ?? "<null>");

            if (!string.IsNullOrEmpty(error))
            {
                _logger.LogError("Error received from authorization server: {Error}", error);
                return RedirectToPage("/Error");
            }

            var expectedState = Request.Cookies["oauth_state"];
            if (string.IsNullOrEmpty(state) || string.IsNullOrEmpty(expectedState) || state != expectedState)
            {
                _logger.LogError("Invalid OAuth state. Expected: {ExpectedState}, Received: {ReceivedState}", expectedState, state);
                Response.Cookies.Delete("oauth_state");
                return RedirectToPage("/Error", new { message = "Invalid state parameter." }); 
            }
            _logger.LogInformation("OAuth state validated successfully.");
            Response.Cookies.Delete("oauth_state");

            var codeVerifier = Request.Cookies["pkce_code_verifier"];
            if (string.IsNullOrEmpty(codeVerifier))
            {
                _logger.LogError("Missing PKCE code verifier cookie.");
                return RedirectToPage("/Error", new { message = "Missing code verifier." });
            }
            Response.Cookies.Delete("pkce_code_verifier");

            var httpClient = _httpClientFactory.CreateClient("CoreIdentApiClient");
            var tokenEndpoint = $"/auth/token";

            var tokenRequestParameters = new Dictionary<string, string?>
            {
                { "grant_type", "authorization_code" },
                { "code", code },
                { "redirect_uri", Url.Page("/Shared/SigninOidc", null, null, Request.Scheme) },
                { "client_id", ClientId },
                { "client_secret", ClientSecret },
                { "code_verifier", codeVerifier }
            };

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
            {
                Content = new FormUrlEncodedContent(tokenRequestParameters!)
            };

            _logger.LogInformation("Exchanging code for tokens at {TokenEndpoint}", tokenEndpoint);
            HttpResponseMessage tokenResponse;
            try
            {
                tokenResponse = await httpClient.SendAsync(requestMessage);
            }
            catch(HttpRequestException ex)
            {
                 _logger.LogError(ex, "HTTP request failed during token exchange.");
                 return RedirectToPage("/Error", new { message = "Failed to connect to authentication server." });
            }
            
            if (!tokenResponse.IsSuccessStatusCode)
            {
                var errorContent = await tokenResponse.Content.ReadAsStringAsync();
                _logger.LogError("Token endpoint request failed: {StatusCode} - {ErrorContent}", tokenResponse.StatusCode, errorContent);
                return RedirectToPage("/Error", new { message = "Token exchange failed." });
            }

            _logger.LogInformation("Token exchange successful.");
            var tokenContent = await tokenResponse.Content.ReadAsStringAsync();
            using var jsonDoc = JsonDocument.Parse(tokenContent);

            var accessToken = jsonDoc.RootElement.TryGetProperty("access_token", out var accessElem) ? accessElem.GetString() : null;
            var idToken = jsonDoc.RootElement.TryGetProperty("id_token", out var idElem) ? idElem.GetString() : null;
            var refreshToken = jsonDoc.RootElement.TryGetProperty("refresh_token", out var refreshElem) ? refreshElem.GetString() : null;

            if (string.IsNullOrEmpty(idToken))
            {
                 _logger.LogError("ID Token missing from token response.");
                 return RedirectToPage("/Error", new { message = "ID Token is missing." });
            }

            _logger.LogInformation("Received ID Token (first 50 chars): {IdTokenStart}...", idToken.Substring(0, Math.Min(50, idToken.Length)));
            
            var claims = ParseIdTokenClaims(idToken); 
            if (claims == null)
            {
                 _logger.LogError("Failed to parse claims from ID Token.");
                 return RedirectToPage("/Error", new { message = "Failed to parse ID token." });
            }
            
            var claimsIdentity = new ClaimsIdentity(claims, CookieScheme, ClaimTypes.Name, ClaimTypes.Role);
            var authProperties = new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1),
            };

            _logger.LogInformation("Signing user in locally. Subject: {Subject}", 
                claimsIdentity.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "<unknown>");

            await HttpContext.SignInAsync(CookieScheme, new ClaimsPrincipal(claimsIdentity), authProperties);

            _logger.LogInformation("Redirecting to home page after successful login.");
            return RedirectToPage("/Index"); 
        }
        
        private IEnumerable<Claim>? ParseIdTokenClaims(string idToken)
        {
            try
            {
                var parts = idToken.Split('.');
                if (parts.Length < 2) return null;
                var payloadBase64 = parts[1];
                payloadBase64 = payloadBase64.Replace('-', '+').Replace('_', '/');
                switch (payloadBase64.Length % 4)
                {
                    case 2: payloadBase64 += "=="; break;
                    case 3: payloadBase64 += "="; break;
                }
                var payloadJson = Encoding.UTF8.GetString(Convert.FromBase64String(payloadBase64));
                using var jsonDoc = JsonDocument.Parse(payloadJson);

                var claims = new List<Claim>();
                foreach (var prop in jsonDoc.RootElement.EnumerateObject())
                {
                    if (prop.Value.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var item in prop.Value.EnumerateArray())
                        {
                            claims.Add(new Claim(prop.Name, item.ToString()));
                        }
                    }
                    else
                    {
                        claims.Add(new Claim(prop.Name, prop.Value.ToString()));
                    }
                }
                var sub = claims.FirstOrDefault(c => c.Type == "sub")?.Value;
                if(sub != null) claims.Add(new Claim(ClaimTypes.NameIdentifier, sub));
                var name = claims.FirstOrDefault(c => c.Type == "name")?.Value;
                if(name != null) claims.Add(new Claim(ClaimTypes.Name, name));
                
                return claims;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to parse ID token payload.");
                return null;
            }
        }
    }
} 