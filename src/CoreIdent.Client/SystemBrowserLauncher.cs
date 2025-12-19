using System.Diagnostics;
using System.Net;

namespace CoreIdent.Client;

/// <summary>
/// Browser launcher using the system default browser and an HttpListener loopback callback.
/// </summary>
public sealed class SystemBrowserLauncher : IBrowserLauncher
{
    private const string DefaultResponseHtml = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Login complete</title></head><body>You can close this window.</body></html>";

    /// <inheritdoc />
    public async Task<BrowserResult> LaunchAsync(string url, string redirectUri, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(url);
        ArgumentException.ThrowIfNullOrWhiteSpace(redirectUri);

        if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out var redirect))
        {
            throw new InvalidOperationException("redirectUri must be an absolute URI.");
        }

        if (!string.Equals(redirect.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(redirect.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("SystemBrowserLauncher requires an http/https redirectUri.");
        }

        var isLoopbackHost = string.Equals(redirect.Host, "localhost", StringComparison.OrdinalIgnoreCase)
            || (IPAddress.TryParse(redirect.Host, out var ip) && IPAddress.IsLoopback(ip));

        if (!isLoopbackHost)
        {
            // This keeps behavior safe; loopback flows should use localhost/127.0.0.1.
            throw new InvalidOperationException("SystemBrowserLauncher requires a loopback redirectUri host (localhost/127.0.0.1).");
        }

        var prefix = redirect.GetLeftPart(UriPartial.Path);
        if (!prefix.EndsWith("/", StringComparison.Ordinal))
        {
            prefix += "/";
        }

        using var listener = new HttpListener();
        listener.Prefixes.Add(prefix);
        listener.Start();

        try
        {
            OpenBrowser(url);

            using var reg = ct.Register(() =>
            {
                try
                {
                    listener.Stop();
                }
                catch
                {
                }
            });

            HttpListenerContext context;
            try
            {
                context = await listener.GetContextAsync();
            }
            catch (HttpListenerException)
            {
                return BrowserResult.Fail("cancelled", "Browser flow was cancelled.");
            }
            catch (ObjectDisposedException)
            {
                return BrowserResult.Fail("cancelled", "Browser flow was cancelled.");
            }

            try
            {
                context.Response.StatusCode = 200;
                context.Response.ContentType = "text/html; charset=utf-8";
                using var writer = new StreamWriter(context.Response.OutputStream);
                await writer.WriteAsync(DefaultResponseHtml);
            }
            catch
            {
            }
            finally
            {
                try
                {
                    context.Response.Close();
                }
                catch
                {
                }
            }

            return BrowserResult.Success(context.Request.Url?.ToString() ?? string.Empty);
        }
        finally
        {
            try
            {
                listener.Stop();
            }
            catch
            {
            }
        }
    }

    private static void OpenBrowser(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Failed to launch system browser.", ex);
        }
    }
}
