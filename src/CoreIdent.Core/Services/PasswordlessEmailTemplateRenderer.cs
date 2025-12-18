using CoreIdent.Core.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace CoreIdent.Core.Services;

/// <summary>
/// Renders passwordless email templates (default or from a configured template path).
/// </summary>
public sealed class PasswordlessEmailTemplateRenderer
{
    private readonly IOptions<PasswordlessEmailOptions> _options;
    private readonly IHostEnvironment _environment;

    /// <summary>
    /// Creates a new instance.
    /// </summary>
    /// <param name="options">Passwordless email options.</param>
    /// <param name="environment">Host environment.</param>
    public PasswordlessEmailTemplateRenderer(IOptions<PasswordlessEmailOptions> options, IHostEnvironment environment)
    {
        _options = options;
        _environment = environment;
    }

    /// <summary>
    /// Renders the HTML email body.
    /// </summary>
    /// <param name="email">The recipient email address.</param>
    /// <param name="verifyUrl">The verification URL.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The rendered HTML body.</returns>
    public async Task<string> RenderAsync(string email, string verifyUrl, CancellationToken ct = default)
    {
        var options = _options.Value;

        string template;
        if (!string.IsNullOrWhiteSpace(options.EmailTemplatePath))
        {
            var path = options.EmailTemplatePath;
            if (!Path.IsPathRooted(path))
            {
                path = Path.Combine(_environment.ContentRootPath, path);
            }

            template = await File.ReadAllTextAsync(path, ct);
        }
        else
        {
            template = DefaultTemplate;
        }

        return template
            .Replace("{AppName}", _environment.ApplicationName, StringComparison.Ordinal)
            .Replace("{Email}", email, StringComparison.Ordinal)
            .Replace("{VerifyUrl}", verifyUrl, StringComparison.Ordinal);
    }

    private const string DefaultTemplate = "<!doctype html><html><body style=\"font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;\"><h2>Sign in to {AppName}</h2><p>Click the link below to sign in:</p><p><a href=\"{VerifyUrl}\">Sign in</a></p><p>If you did not request this, you can ignore this email.</p></body></html>";
}
