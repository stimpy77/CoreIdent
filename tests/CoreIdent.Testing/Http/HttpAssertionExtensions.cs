using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using CoreIdent.Core.Endpoints;
using Shouldly;

namespace CoreIdent.Testing.Http;

/// <summary>
/// HTTP assertion helpers for CoreIdent integration tests.
/// </summary>
public static class HttpAssertionExtensions
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
    };

    /// <summary>
    /// Asserts that the response is successful (2xx status code).
    /// </summary>
    public static async Task<HttpResponseMessage> ShouldBeSuccessfulAsync(this HttpResponseMessage response)
    {
        response.IsSuccessStatusCode.ShouldBeTrue(
            $"Expected success but got {response.StatusCode}: {await response.Content.ReadAsStringAsync()}");
        return response;
    }

    /// <summary>
    /// Asserts that the response is a 401 Unauthorized.
    /// </summary>
    public static async Task<HttpResponseMessage> ShouldBeUnauthorizedAsync(this HttpResponseMessage response)
    {
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        return response;
    }

    /// <summary>
    /// Asserts that the response is a 400 Bad Request.
    /// </summary>
    public static async Task<HttpResponseMessage> ShouldBeBadRequestAsync(
        this HttpResponseMessage response,
        string? containsError = null)
    {
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);

        if (containsError != null)
        {
            var content = await response.Content.ReadAsStringAsync();
            content.ShouldContain(containsError);
        }

        return response;
    }

    /// <summary>
    /// Asserts that the response is a 302 Redirect.
    /// </summary>
    public static HttpResponseMessage ShouldBeRedirect(this HttpResponseMessage response)
    {
        response.StatusCode.ShouldBe(HttpStatusCode.Found);
        return response;
    }

    /// <summary>
    /// Asserts that the response redirects to the specified URI.
    /// </summary>
    public static async Task<HttpResponseMessage> ShouldRedirectToAsync(
        this HttpResponseMessage response,
        string expectedUri)
    {
        response.ShouldBeRedirect();

        var locationHeader = response.Headers.Location?.ToString();
        locationHeader.ShouldNotBeNull();
        locationHeader.ShouldContain(expectedUri);

        return response;
    }

    /// <summary>
    /// Deserializes the response content as JSON to the specified type.
    /// </summary>
    public static async Task<T?> ContentAs<T>(this HttpResponseMessage response)
    {
        return await response.Content.ReadFromJsonAsync<T>(JsonOptions);
    }

    /// <summary>
    /// Asserts the response is OIDC Discovery document and returns it.
    /// </summary>
    public static async Task<DiscoveryDocument> ShouldBeDiscoveryDocumentAsync(this HttpResponseMessage response)
    {
        await response.ShouldBeSuccessfulAsync();
        var discovery = await response.ContentAs<DiscoveryDocument>();
        discovery.ShouldNotBeNull("Response should be valid OIDC discovery document");
        return discovery;
    }

    /// <summary>
    /// Asserts the response is a valid OAuth error response.
    /// </summary>
    public static async Task<OAuthErrorResponse> ShouldBeOAuthErrorAsync(this HttpResponseMessage response)
    {
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        var error = await response.ContentAs<OAuthErrorResponse>();
        error.ShouldNotBeNull("Response should be valid OAuth error");
        return error;
    }
}

/// <summary>
/// OIDC Discovery document response.
/// </summary>
public class DiscoveryDocument
{
    public string Issuer { get; set; } = string.Empty;
    public string AuthorizationEndpoint { get; set; } = string.Empty;
    public string TokenEndpoint { get; set; } = string.Empty;
    public string? UserInfoEndpoint { get; set; }
    public string JwksUri { get; set; } = string.Empty;
    public string? RegistrationEndpoint { get; set; }
    public List<string> ScopesSupported { get; set; } = [];
    public List<string> ResponseTypesSupported { get; set; } = [];
    public List<string> GrantTypesSupported { get; set; } = [];
    public List<string> TokenEndpointAuthMethodsSupported { get; set; } = [];
    public List<string> ClaimsSupported { get; set; } = [];
    public List<string> SubjectTypesSupported { get; set; } = [];
    public List<string> IdTokenSigningAlgValuesSupported { get; set; } = [];
}

/// <summary>
/// Standard OAuth error response.
/// </summary>
public class OAuthErrorResponse
{
    public string Error { get; set; } = string.Empty;
    public string? ErrorDescription { get; set; }
    public string? ErrorUri { get; set; }
    public string? State { get; set; }
}
