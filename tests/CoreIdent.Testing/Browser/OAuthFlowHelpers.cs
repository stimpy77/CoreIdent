using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace CoreIdent.Testing.Browser;

/// <summary>
/// Helpers for OAuth/OIDC authorization code flow with PKCE.
/// </summary>
public static class OAuthFlowHelpers
{
    private const string Characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

    /// <summary>
    /// Generates a cryptographically secure random string for PKCE code verifier.
    /// </summary>
    public static string GenerateCodeVerifier(int length = 43)
    {
        var bytes = new byte[length];
        Rng.GetBytes(bytes);

        var result = new StringBuilder(length);
        foreach (var b in bytes)
        {
            result.Append(Characters[b % Characters.Length]);
        }

        return result.ToString();
    }

    /// <summary>
    /// Generates the PKCE code challenge from a code verifier using S256.
    /// </summary>
    public static string GenerateCodeChallenge(string codeVerifier)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier));
        var base64 = Convert.ToBase64String(digest)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

        return base64;
    }

    /// <summary>
    /// Generates state parameter for CSRF protection.
    /// </summary>
    public static string GenerateState(int length = 32)
    {
        return GenerateCodeVerifier(length);
    }

    /// <summary>
    /// Builds the authorization URL with PKCE.
    /// </summary>
    public static string BuildAuthorizationUrl(
        string authorizationEndpoint,
        string clientId,
        string redirectUri,
        string[] scopes,
        string state,
        string codeChallenge,
        string? nonce = null,
        string? codeChallengeMethod = "S256")
    {
        var parameters = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = clientId,
            ["redirect_uri"] = redirectUri,
            ["scope"] = string.Join(" ", scopes),
            ["state"] = state,
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = codeChallengeMethod ?? "S256"
        };

        if (!string.IsNullOrEmpty(nonce))
        {
            parameters["nonce"] = nonce;
        }

        var queryString = string.Join("&",
            parameters.Select(kv => $"{HttpUtility.UrlEncode(kv.Key)}={HttpUtility.UrlEncode(kv.Value)}"));

        return $"{authorizationEndpoint}?{queryString}";
    }

    /// <summary>
    /// Parses the authorization response to extract code and state.
    /// </summary>
    public static (string code, string state) ParseAuthorizationResponse(string url)
    {
        var uri = new Uri(url);
        var query = HttpUtility.ParseQueryString(uri.Query);

        var code = query["code"] ?? throw new InvalidOperationException("Missing 'code' in authorization response");
        var state = query["state"] ?? throw new InvalidOperationException("Missing 'state' in authorization response");

        return (code, state);
    }

    /// <summary>
    /// Validates the state parameter matches expected value.
    /// </summary>
    public static void ValidateState(string actualState, string expectedState)
    {
        if (actualState != expectedState)
        {
            throw new InvalidOperationException($"State mismatch: expected '{expectedState}', got '{actualState}'");
        }
    }
}

/// <summary>
/// Callback listener for handling redirect URIs during OAuth flow.
/// </summary>
public class CallbackListener : IDisposable
{
    private readonly HttpListener _listener;
    private readonly string _path;
    private readonly TaskCompletionSource<(string url, Dictionary<string, string> parameters)> _tcs;
    private bool _disposed;

    public CallbackListener(int port = 0, string path = "/callback")
    {
        _listener = new HttpListener();
        _path = path;
        _tcs = new TaskCompletionSource<(string, Dictionary<string, string>)>(TaskCreationOptions.RunContinuationsAsynchronously);

        Port = port == 0 ? GetEphemeralPort() : port;
        // Use loopback only to avoid URL reservation / admin requirements.
        _listener.Prefixes.Add($"http://localhost:{Port}/");
        RedirectUri = $"http://localhost:{Port}{_path}";
    }

    /// <summary>
    /// Gets the port the listener is bound to.
    /// </summary>
    public int Port { get; }

    /// <summary>
    /// Gets the redirect URI to use in the OAuth flow.
    /// </summary>
    public string RedirectUri { get; }

    /// <summary>
    /// Starts listening for the callback.
    /// </summary>
    public void Start()
    {
        _listener.Start();
        Task.Run(ListenAsync);
    }

    private static int GetEphemeralPort()
    {
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private async Task ListenAsync()
    {
        try
        {
            while (!_disposed)
            {
                var context = await _listener.GetContextAsync();
                _ = Task.Run(async () => await HandleRequestAsync(context));
            }
        }
        catch (ObjectDisposedException)
        {
            // Expected when listener is stopped
        }
        catch (HttpListenerException)
        {
            // Expected when listener is stopped
        }
    }

    private async Task HandleRequestAsync(HttpListenerContext context)
    {
        var request = context.Request;
        var response = context.Response;

        if (request.Url?.AbsolutePath != _path)
        {
            response.StatusCode = 404;
            response.Close();
            return;
        }

        var query = HttpUtility.ParseQueryString(request.Url.Query);
        var parameters = new Dictionary<string, string>();
        foreach (string? key in query.AllKeys)
        {
            if (key != null)
                parameters[key] = query[key] ?? string.Empty;
        }

        _tcs.SetResult((request.Url.ToString(), parameters));

        // Send a simple response to close the browser window
        var html = @"<!DOCTYPE html>
<html><head><title>Authentication Complete</title></head>
<body><h1>Authentication Complete</h1>
<p>You have been successfully authenticated. You may close this window.</p>
<script>setTimeout(() => window.close(), 2000);</script>
</body></html>";

        var buffer = Encoding.UTF8.GetBytes(html);
        response.ContentType = "text/html; charset=utf-8";
        response.StatusCode = 200;
        await response.OutputStream.WriteAsync(buffer);
        response.OutputStream.Close();
    }

    /// <summary>
    /// Waits for the callback to be received.
    /// </summary>
    public async Task<(string url, Dictionary<string, string> parameters)> WaitForCallbackAsync(
        TimeSpan? timeout = null)
    {
        timeout ??= TimeSpan.FromMinutes(5);

        using var cts = new CancellationTokenSource(timeout.Value);
        cts.Token.Register(() => _tcs.TrySetCanceled());

        return await _tcs.Task;
    }

    /// <summary>
    /// Stops the listener.
    /// </summary>
    public void Stop()
    {
        _disposed = true;
        _listener.Stop();
        _listener.Close();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _listener.Close();
    }
}

/// <summary>
/// Result of an OAuth/OIDC flow execution.
/// </summary>
public class OAuthFlowResult
{
    public string? AuthorizationCode { get; set; }
    public string? AccessToken { get; set; }
    public string? IdToken { get; set; }
    public string? RefreshToken { get; set; }
    public string? Error { get; set; }
    public string? ErrorDescription { get; set; }
    public bool Success => AccessToken != null && string.IsNullOrEmpty(Error);
}
