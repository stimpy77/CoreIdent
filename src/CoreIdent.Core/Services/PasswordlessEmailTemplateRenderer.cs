using CoreIdent.Core.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace CoreIdent.Core.Services;

public sealed class PasswordlessEmailTemplateRenderer
{
    private readonly IOptions<PasswordlessEmailOptions> _options;
    private readonly IHostEnvironment _environment;

    public PasswordlessEmailTemplateRenderer(IOptions<PasswordlessEmailOptions> options, IHostEnvironment environment)
    {
        _options = options;
        _environment = environment;
    }

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
