using System.Net;
using System.Net.Mail;
using CoreIdent.Core.Configuration;
using Microsoft.Extensions.Options;

namespace CoreIdent.Core.Services;

/// <summary>
/// Sends email using SMTP.
/// </summary>
public sealed class SmtpEmailSender : IEmailSender
{
    private readonly IOptions<SmtpOptions> _options;

    /// <summary>
    /// Creates a new instance.
    /// </summary>
    /// <param name="options">SMTP options.</param>
    public SmtpEmailSender(IOptions<SmtpOptions> options)
    {
        _options = options;
    }

    /// <inheritdoc />
    public async Task SendAsync(EmailMessage message, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(message);

        var options = _options.Value;
        if (string.IsNullOrWhiteSpace(options.Host))
        {
            throw new InvalidOperationException("SMTP host is not configured.");
        }

        if (string.IsNullOrWhiteSpace(options.FromAddress))
        {
            throw new InvalidOperationException("SMTP from address is not configured.");
        }

        using var smtp = new SmtpClient(options.Host, options.Port)
        {
            EnableSsl = options.EnableTls
        };

        if (!string.IsNullOrWhiteSpace(options.UserName))
        {
            smtp.Credentials = new NetworkCredential(options.UserName, options.Password);
        }

        var from = string.IsNullOrWhiteSpace(options.FromDisplayName)
            ? new MailAddress(options.FromAddress)
            : new MailAddress(options.FromAddress, options.FromDisplayName);

        using var mail = new MailMessage
        {
            From = from,
            Subject = message.Subject,
            Body = message.HtmlBody,
            IsBodyHtml = true
        };

        mail.To.Add(message.To);

        if (!string.IsNullOrWhiteSpace(message.TextBody))
        {
            mail.AlternateViews.Add(AlternateView.CreateAlternateViewFromString(message.TextBody, null, "text/plain"));
        }

        await smtp.SendMailAsync(mail, ct);
    }
}
