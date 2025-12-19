using System.Net;
using CoreIdent.Client;

namespace CoreIdent.Client.Samples.BrowserLaunchers;

/// <summary>
/// A test-only browser launcher that simulates an interactive login by calling the authorize URL
/// with a test-header authenticated request and returning the redirect Location.
/// </summary>
public sealed class TestHeaderBrowserLauncher : IBrowserLauncher, IDisposable
{
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly string _userId;
    private readonly string? _email;

    public TestHeaderBrowserLauncher(HttpClient http, string userId, string? email)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        _ownsHttp = false;
        _http = http;
        _userId = userId;
        _email = string.IsNullOrWhiteSpace(email) ? null : email;
    }

    public TestHeaderBrowserLauncher(HttpMessageHandler handler, Uri baseAddress, string userId, string? email)
    {
        ArgumentNullException.ThrowIfNull(handler);
        ArgumentNullException.ThrowIfNull(baseAddress);
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        _ownsHttp = true;
        _http = new HttpClient(handler) { BaseAddress = baseAddress };
        _userId = userId;
        _email = string.IsNullOrWhiteSpace(email) ? null : email;
    }

    public async Task<BrowserResult> LaunchAsync(string url, string redirectUri, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(url);
        ArgumentException.ThrowIfNullOrWhiteSpace(redirectUri);

        using var req = new HttpRequestMessage(HttpMethod.Get, url);

        // CoreIdent sample host uses this auth scheme for /auth/authorize.
        req.Headers.TryAddWithoutValidation("X-Test-User-Id", _userId);
        if (_email is not null)
        {
            req.Headers.TryAddWithoutValidation("X-Test-User-Email", _email);
        }

        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);

        if (resp.StatusCode is HttpStatusCode.Found or HttpStatusCode.SeeOther)
        {
            var location = resp.Headers.Location?.ToString();
            if (string.IsNullOrWhiteSpace(location))
            {
                return BrowserResult.Fail("invalid_response", "Authorize response did not include a Location header.");
            }

            // Return the URL (which should be the redirect_uri with code + state).
            return BrowserResult.Success(location);
        }

        var body = string.Empty;
        try
        {
            body = await resp.Content.ReadAsStringAsync(ct);
        }
        catch
        {
            // ignore
        }

        return BrowserResult.Fail(
            "authorize_failed",
            $"Authorize request failed. Status={(int)resp.StatusCode} {resp.ReasonPhrase}. Body={body}");
    }

    public void Dispose()
    {
        if (_ownsHttp)
        {
            _http.Dispose();
        }
    }
}
