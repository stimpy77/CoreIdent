namespace CoreIdent.Core.Services;

public interface IEmailSender
{
    Task SendAsync(EmailMessage message, CancellationToken ct = default);
}

public record EmailMessage(string To, string Subject, string HtmlBody, string? TextBody = null);
