using CoreIdent.Client;

namespace CoreIdent.Client.Maui;

/// <summary>
/// Browser launcher using .NET MAUI WebAuthenticator.
/// </summary>
public sealed class MauiBrowserLauncher : IBrowserLauncher
{
    private readonly IMauiWebAuthenticatorAdapter _authenticator;

    /// <summary>
    /// Creates a new instance with default WebAuthenticator.
    /// </summary>
    public MauiBrowserLauncher()
        : this(null)
    {
    }

    /// <summary>
    /// Creates a new instance (internal for testing).
    /// </summary>
    /// <param name="authenticator">Optional authenticator adapter.</param>
    internal MauiBrowserLauncher(IMauiWebAuthenticatorAdapter? authenticator)
    {
        _authenticator = authenticator ?? MauiWebAuthenticatorAdapter.Default;
    }

    /// <inheritdoc />
    public async Task<BrowserResult> LaunchAsync(string url, string redirectUri, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(url);
        ArgumentException.ThrowIfNullOrWhiteSpace(redirectUri);

        if (!Uri.TryCreate(url, UriKind.Absolute, out var authorizationUri))
        {
            throw new InvalidOperationException("url must be an absolute URI.");
        }

        if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out var callbackUri))
        {
            throw new InvalidOperationException("redirectUri must be an absolute URI.");
        }

        try
        {
            var response = await _authenticator.AuthenticateAsync(authorizationUri, callbackUri, ct);
            var parameters = new Dictionary<string, string>(response.Properties, StringComparer.Ordinal);

            if (!string.IsNullOrWhiteSpace(response.AccessToken) && !parameters.ContainsKey("access_token"))
            {
                parameters["access_token"] = response.AccessToken!;
            }

            var responseUrl = BuildRedirectUrl(redirectUri, parameters);
            return BrowserResult.Success(responseUrl);
        }
        catch (OperationCanceledException)
        {
            return BrowserResult.Fail("cancelled", "Browser flow was cancelled.");
        }
        catch (Exception ex)
        {
            return BrowserResult.Fail("authentication_failed", ex.Message);
        }
    }

    private static string BuildRedirectUrl(string redirectUri, IReadOnlyDictionary<string, string> parameters)
    {
        if (parameters.Count == 0)
        {
            return redirectUri;
        }

        var builder = new UriBuilder(redirectUri);
        var queryValues = ParseQuery(builder.Query);

        foreach (var (key, value) in parameters)
        {
            queryValues[key] = value;
        }

        builder.Query = string.Join("&", queryValues.Select(kvp => $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value)}"));
        return builder.Uri.ToString();
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(query))
        {
            return result;
        }

        var trimmed = query.TrimStart('?');
        foreach (var pair in trimmed.Split('&', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var kvp = pair.Split('=', 2);
            if (kvp.Length == 0)
            {
                continue;
            }

            var key = Uri.UnescapeDataString(kvp[0]);
            var value = kvp.Length == 2 ? Uri.UnescapeDataString(kvp[1]) : string.Empty;
            result[key] = value;
        }

        return result;
    }
}
