namespace CoreIdent.Core.Services;

/// <summary>
/// Sends email messages.
/// </summary>
public interface IEmailSender
{
    /// <summary>
    /// Sends an email message.
    /// </summary>
    /// <param name="message">The email message.</param>
    /// <param name="ct">The cancellation token.</param>
    Task SendAsync(EmailMessage message, CancellationToken ct = default);
}

/// <summary>
/// Represents an email message.
/// </summary>
public record EmailMessage
{
    /// <summary>
    /// Creates a new <see cref="EmailMessage"/>.
    /// </summary>
    /// <param name="to">Recipient email address.</param>
    /// <param name="subject">Email subject.</param>
    /// <param name="htmlBody">HTML body.</param>
    /// <param name="textBody">Optional plain-text body.</param>
    public EmailMessage(string to, string subject, string htmlBody, string? textBody = null)
    {
        To = to;
        Subject = subject;
        HtmlBody = htmlBody;
        TextBody = textBody;
    }

    /// <summary>
    /// The recipient email address.
    /// </summary>
    public string To { get; init; }

    /// <summary>
    /// The email subject.
    /// </summary>
    public string Subject { get; init; }

    /// <summary>
    /// The HTML body.
    /// </summary>
    public string HtmlBody { get; init; }

    /// <summary>
    /// The optional plain-text body.
    /// </summary>
    public string? TextBody { get; init; }
}
